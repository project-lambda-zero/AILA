"""TaskQueue — platform-owned task submission API.

Modules receive a TaskQueue instance on context.task_queue and call submit()
to enqueue background work. They never touch ARQ, Redis, or TaskRecord
directly — the platform owns the infrastructure boundary.

Per D-27/HANG-03: submit() is async. Await it from any async context
(FastAPI routes, @platform_task handlers).

Decision references:
- D-02: track → 1:1 to ARQ queue name (arq:queue:{track})
- D-04: fn_path validated against module boundary at submit time
- D-13: depends_on=[task_id] holds task in WAITING status
- D-14: TopologicalSorter rejects circular depends_on
- D-19 (revised Phase 178): Redis is REQUIRED. There is no sync fallback.
  If Redis is unreachable at submit time we raise WorkerUnreachableError
  (HTTP 503 via the envelope pipeline) rather than silently executing the
  task in-process. The previous in-process fallback path was removed
  because it (a) blocked the event loop, (b) defeated retries/checkpoints,
  and (c) created orphan DB records whenever callers interpreted the
  silent fallback as a successful enqueue.
- D-23: Redis URL from ConfigRegistry namespace="platform", key="redis_url" (INFRA-02)
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
from collections.abc import Callable
from datetime import UTC
from graphlib import CycleError, TopologicalSorter

from sqlmodel import select

from aila.api.constants import MODULE_ID_PLATFORM
from aila.platform.exceptions import WorkerUnreachableError
from aila.platform.tasks.constants import (
    ARQ_QUEUE_KEY_TEMPLATE,
    CONFIG_KEY_REDIS_URL,
    CONFIG_NS_PLATFORM,
)
from aila.platform.tasks.models import TaskHandle, TaskRecord, TaskStatus
from aila.storage.database import async_session_scope

__all__ = ["TaskQueue"]

_log = logging.getLogger(__name__)


class TaskQueue:
    """Platform-owned task submission API. Modules call submit() to enqueue async work.

    Modules never reference ARQ, Redis, or TaskRecord directly. The platform
    creates one TaskQueue per module context, binding it to the calling module's
    module_id for boundary enforcement.

    Per D-27/HANG-03: submit() is async. Await it from any async context
    (FastAPI routes, @platform_task handlers).
    """

    def __init__(
        self,
        config_registry: object,  # ConfigRegistry — avoid circular import at module level
        module_id: str,
    ) -> None:
        """Bind TaskQueue to a module_id for module boundary enforcement.

        Args:
            config_registry: ConfigRegistry instance for Redis URL lookup (INFRA-02 / D-23).
            module_id: The ID of the owning module (e.g., "vulnerability").
                       submit() rejects functions from any other module (D-04 / MOD-10).
        """
        self._config_registry = config_registry
        self._module_id = module_id
        self._draining: bool = False

    async def submit(
        self,
        track: str,
        fn: Callable[..., object],
        kwargs: dict[str, object],
        depends_on: list[str] | None = None,
        user_id: str = "system",
        group_id: str = "system",
        team_id: str | None = None,
    ) -> TaskHandle:
        """Submit a background task. Returns a TaskHandle for status polling.

        Validates module boundary (MOD-10 / D-04), persists a TaskRecord
        (MOD-06), checks dependency DAG for cycles (MOD-11 / D-14), and
        enqueues to ARQ. Redis is REQUIRED — if the broker cannot be
        reached, ``WorkerUnreachableError`` is raised BEFORE any DB record
        is persisted so the caller sees a clean 503 and no orphan task
        records accumulate.

        Args:
            track: Task track name — maps 1:1 to ARQ queue key (D-02 / MOD-07).
            fn: Callable belonging to THIS module. Cross-module callables are
                rejected at submit time (D-04 / MOD-10).
            kwargs: Keyword arguments passed to fn. Must be JSON-serializable.
            depends_on: Optional list of task_ids that must reach DONE before
                this task transitions from WAITING to QUEUED (D-13 / MOD-11).
            user_id: Caller user_id for task ownership (MOD-13). Defaults to "system".
            group_id: Caller group_id (role) for scoped queries. Defaults to "system".
            team_id: Team isolation ID (TEAM-01). Stamped on TaskRecord so
                background workers can reconstruct TeamContext for query
                scoping. None for admin/system tasks (TEAM-06).

        Returns:
            TaskHandle with task_id for polling GET /tasks/{task_id}.

        Raises:
            ValueError: On module boundary violation (MOD-10) or circular
                dependency (MOD-11).
            WorkerUnreachableError: When Redis/ARQ broker is unreachable.
                The envelope pipeline (176a) returns HTTP 503 with a hint.
        """
        if self._draining:
            raise RuntimeError("Queue is draining; new submissions rejected")

        fn_path = self._get_fn_path(fn)
        fn_module = self._extract_module_id(fn_path)
        self._enforce_module_boundary(fn_path, fn_module)

        # SEC-07: SHA-256 task dedup — return existing handle for identical active tasks
        input_hash = hashlib.sha256(
            json.dumps({"fn": fn_path, "kwargs": kwargs}, sort_keys=True, default=str).encode()
        ).hexdigest()

        async with async_session_scope() as dedup_session:
            existing = (await dedup_session.exec(
                select(TaskRecord)
                .where(TaskRecord.input_hash == input_hash)
                .where(TaskRecord.status.in_(["queued", "running", "waiting"]))  # type: ignore[union-attr]
            )).first()
            if existing is not None:
                _log.info("Task dedup: returning existing task %s for hash %s", existing.id, input_hash[:12])
                return TaskHandle(task_id=str(existing.id))

        # Fail-fast Redis reachability check (no DB record written yet). This
        # is the single source of truth for "broker is usable" — if the check
        # passes but the actual enqueue later fails, that exception is also
        # surfaced as WorkerUnreachableError so no orphan DB record remains.
        redis_url = None
        if not depends_on:
            redis_url = self._get_redis_url()
            if not redis_url:
                raise WorkerUnreachableError(
                    "Task queue Redis URL is not configured — submission rejected."
                )

        initial_status = TaskStatus.WAITING if depends_on else TaskStatus.QUEUED

        record = TaskRecord(
            track=track,
            fn_path=fn_path,
            fn_module=fn_module,
            status=initial_status,
            user_id=user_id,
            group_id=group_id,
            team_id=team_id,
            kwargs_json=json.dumps(kwargs),
            depends_on_json=json.dumps(depends_on) if depends_on else None,
            input_hash=input_hash,
        )

        async with async_session_scope() as session:
            session.add(record)
            await session.commit()
            await session.refresh(record)
            task_id = record.id

        if depends_on:
            try:
                await self._validate_dag(task_id, depends_on)
            except ValueError:
                # Clean up the orphaned WAITING record before re-raising
                async with async_session_scope() as session:
                    orphan = (await session.exec(
                        select(TaskRecord).where(TaskRecord.id == task_id)
                    )).first()
                    if orphan is not None:
                        await session.delete(orphan)
                        await session.commit()
                raise

        if not depends_on:
            if redis_url is None:
                raise ValueError("Redis URL is not configured — check AILA_PLATFORM_REDIS_URL")
            # Per-investigation backpressure: when this submission is for
            # an investigation that already has N >= cap tasks in flight,
            # defer the new task so other investigations (or other modules)
            # get worker slots. Without this, one investigation spawning
            # branches and re-enqueuing rapidly can monopolise max_jobs
            # and starve every other investigation in the queue.
            defer_seconds = await self._compute_investigation_defer(kwargs)
            enqueued = await self._arq_enqueue_async(
                track=track,
                task_id=task_id,
                fn_path=fn_path,
                fn_module=fn_module,
                kwargs=kwargs,
                user_id=user_id,
                redis_url=redis_url,
                defer_seconds=defer_seconds,
            )
            if not enqueued:
                # Roll back the DB record so a failed enqueue does not leave
                # a ghost "queued" task sitting in the DB forever.
                async with async_session_scope() as session:
                    ghost = (await session.exec(
                        select(TaskRecord).where(TaskRecord.id == task_id)
                    )).first()
                    if ghost is not None:
                        await session.delete(ghost)
                        await session.commit()
                raise WorkerUnreachableError(
                    f"Task queue Redis is unreachable (url={redis_url}) — submission rejected."
                )

        return TaskHandle(task_id=task_id)

    # Per-investigation in-flight cap. Tasks beyond this count for the
    # same investigation_id get deferred so other investigations don't
    # starve. Value is intentionally small: each branch turn is a
    # separate task and a 3-branch investigation routinely has 3 in
    # flight; allowing 6 covers normal fan-out without monopolising.
    INVESTIGATION_INFLIGHT_CAP: int = 6
    INVESTIGATION_DEFER_STEP_S: float = 30.0

    async def _compute_investigation_defer(
        self, kwargs: dict[str, object],
    ) -> float:
        """Return seconds to defer this submission based on in-flight
        task count for the same investigation. Returns 0 when the
        submission is not investigation-scoped or under the cap.
        """
        from sqlmodel import func  # noqa: PLC0415

        inv_id = kwargs.get("investigation_id") if isinstance(kwargs, dict) else None
        if not isinstance(inv_id, str) or not inv_id:
            return 0.0
        try:
            async with async_session_scope() as session:
                count = (await session.exec(
                    select(func.count(TaskRecord.id)).where(
                        TaskRecord.status.in_(["queued", "running", "waiting"]),  # type: ignore[union-attr]
                        TaskRecord.kwargs_json.like(f'%"{inv_id}"%'),
                    )
                )).one()
        except Exception as exc:  # noqa: BLE001 — best-effort fairness
            _log.debug("investigation defer count failed: %s", exc)
            return 0.0
        excess = max(0, int(count) - self.INVESTIGATION_INFLIGHT_CAP)
        return excess * self.INVESTIGATION_DEFER_STEP_S

    # ---- admin management methods ----------------------------------------

    async def depth(self) -> dict[str, int]:
        """Return task counts grouped by status."""
        from sqlmodel import func

        async with async_session_scope() as session:
            rows = (await session.exec(
                select(TaskRecord.status, func.count(TaskRecord.id))
                .group_by(TaskRecord.status)
            )).all()
            return {status: count for status, count in rows}

    async def drain(self) -> int:
        """Pause new submissions and return pending task count."""
        from sqlmodel import func

        self._draining = True
        async with async_session_scope() as session:
            count = (await session.exec(
                select(func.count(TaskRecord.id))
                .where(TaskRecord.status == "queued")
            )).one()
            return count

    async def requeue_failed(self, max_age_hours: int = 24) -> int:
        """Requeue recently failed tasks.

        Transitions tasks with status 'failed' and updated_at within
        max_age_hours back to 'queued' status. Clears the error field.

        Args:
            max_age_hours: Only requeue tasks that failed within this many hours.

        Returns:
            Number of tasks requeued.
        """
        from datetime import datetime, timedelta

        cutoff = datetime.now(UTC) - timedelta(hours=max_age_hours)
        async with async_session_scope() as session:
            failed = (await session.exec(
                select(TaskRecord)
                .where(TaskRecord.status == "failed")
                .where(TaskRecord.updated_at >= cutoff)
            )).all()
            count = 0
            for task in failed:
                task.status = "queued"
                task.error = None
                session.add(task)
                count += 1
            await session.commit()
            return count

    # ---- private helpers ------------------------------------------------

    def _get_fn_path(self, fn: Callable[..., object]) -> str:
        """Return the fully-qualified dotted path of fn.

        Example: "aila.modules.vulnerability.tasks.scan"

        Raises:
            ValueError: If inspect.getmodule(fn) returns None.
        """
        module = inspect.getmodule(fn)
        if module is None:
            raise ValueError(
                f"Cannot determine module for callable {fn!r}. "
                "Ensure fn is defined at module scope, not as a local lambda."
            )
        return f"{module.__name__}.{fn.__qualname__}"

    def _extract_module_id(self, fn_path: str) -> str:
        """Extract module_id: 'aila.modules.X.*' -> 'X', 'aila.*' -> '__platform__'."""
        parts = fn_path.split(".")
        if len(parts) >= 3 and parts[0] == "aila" and parts[1] == "modules":
            return parts[2]
        if len(parts) >= 2 and parts[0] == "aila":
            return MODULE_ID_PLATFORM
        return parts[0]

    def _enforce_module_boundary(self, fn_path: str, fn_module: str) -> None:
        """Raise ValueError if fn belongs to a different module. '__platform__' always passes."""
        if self._module_id == MODULE_ID_PLATFORM:
            return  # Platform-level submissions bypass boundary check
        if fn_module != self._module_id and fn_module != MODULE_ID_PLATFORM:
            raise ValueError(
                f"Module boundary violation: fn_path '{fn_path}' belongs to module "
                f"'{fn_module}' but submit() was called from module '{self._module_id}'. "
                "Modules may only submit their own functions."
            )

    async def _validate_dag(self, new_task_id: str, depends_on: list[str]) -> None:
        """Raise ValueError if adding this dependency edge creates a cycle in the task DAG."""
        graph: dict[str, set[str]] = {}
        async with async_session_scope() as session:
            records = (await session.exec(select(TaskRecord))).all()
            for r in records:
                deps: list[str] = json.loads(r.depends_on_json) if r.depends_on_json else []
                graph[r.id] = set(deps)
        graph[new_task_id] = set(depends_on)
        try:
            sorter = TopologicalSorter(graph)
            sorter.prepare()
        except CycleError as exc:
            raise ValueError(f"Circular dependency detected: {exc}") from exc

    def _get_redis_url(self) -> str | None:
        import os
        # Check env var first (sync-safe, no async registry call needed)
        env_url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
        if env_url:
            return env_url
        try:
            url = self._config_registry.get(CONFIG_NS_PLATFORM, CONFIG_KEY_REDIS_URL)  # type: ignore[attr-defined]  # ConfigRegistry duck-typed
            # ConfigRegistry.get is async — if we got a coroutine, skip it
            if hasattr(url, "__await__"):
                _log.debug("ConfigRegistry.get returned coroutine in sync context, using env fallback")
                return None
            return str(url) if url else None
        except Exception:
            _log.debug("ConfigRegistry redis_url lookup failed, treating as unconfigured", exc_info=True)
            return None

    def _arq_enqueue(
        self,
        track: str,
        task_id: str,
        fn_path: str,
        fn_module: str,
        kwargs: dict[str, object],
        user_id: str,
        redis_url: str,
    ) -> bool:
        """Enqueue to ARQ from a sync (threadpool) context. Returns True on success, False if unreachable.

        INVARIANT: This method is intended for sync callers running inside a thread
        that has no active asyncio event loop (e.g. code dispatched via
        ``asyncio.to_thread``). In that case ``asyncio.run()`` is safe because no
        loop is present in the current thread.

        ``submit()`` (``async def``) uses ``_arq_enqueue_async`` instead — the async
        variant avoids spawning a thread pool and awaits ARQ directly.

        DO NOT call ``_arq_enqueue`` from ``async def`` code — use ``_arq_enqueue_async``.
        If this method is called from an async context (running loop detected), it logs
        a warning and raises ``RuntimeError`` so the violation is surfaced immediately
        rather than silently deadlocking.
        """
        import asyncio as _asyncio

        # Guard: detect accidental call from an async context.
        # asyncio.get_running_loop() raises RuntimeError when no loop is running
        # (the safe/expected case). If it succeeds, a loop IS running in this thread
        # and the caller violated the invariant.
        try:
            _asyncio.get_running_loop()
            # A running loop was found — this is the violation case.
            _log.error(
                "task_queue._arq_enqueue called from async context — use _arq_enqueue_async instead"
            )
            raise RuntimeError(
                "_arq_enqueue called from an async context; use _arq_enqueue_async instead"
            )
        except RuntimeError as _loop_err:
            if "_arq_enqueue called from an async context" in str(_loop_err):
                raise
            # RuntimeError from get_running_loop() means no loop present — safe to proceed.

        async def _enqueue() -> bool:
            from arq.connections import RedisSettings, create_pool

            settings = RedisSettings.from_dsn(redis_url)
            pool = await create_pool(settings)
            try:
                queue_key = ARQ_QUEUE_KEY_TEMPLATE.format(track=track)
                # Phase 179: ARQ looks up functions by __qualname__. The
                # @platform_task wrapper preserves the decorated function's
                # own __qualname__, so ``fn_path``'s last segment is the
                # ARQ function name. Payload kwargs are passed as-is; the
                # wrapper constructs TaskContext from the ARQ ctx dict and
                # the TaskRecord row.
                arq_fn_name = fn_path.rsplit(".", 1)[-1]
                await pool.enqueue_job(
                    arq_fn_name,
                    _queue_name=queue_key,
                    _job_id=task_id,
                    **kwargs,
                )
                # fn_module and user_id are captured on the TaskRecord and
                # looked up by the hooks; they are no longer passed as ARQ
                # job args because the @platform_task wrapper owns the
                # signature shape (ctx: TaskContext, **kwargs).
                _ = fn_module, user_id  # retained in signature for callers
                return True
            finally:
                await pool.aclose()

        try:
            # No running loop in this thread (validated above) — asyncio.run() is safe.
            return _asyncio.run(_enqueue())
        except Exception as exc:
            # Redis/broker is unreachable. Callers surface this as
            # WorkerUnreachableError. There is NO sync fallback.
            _log.error(
                "Redis unavailable (url=%s): %s — submission will be rejected.",
                redis_url,
                exc,
            )
            return False

    async def _arq_enqueue_async(
        self,
        track: str,
        task_id: str,
        fn_path: str,
        fn_module: str,
        kwargs: dict[str, object],
        user_id: str,
        redis_url: str,
        defer_seconds: float = 0.0,
    ) -> bool:
        """Async variant of _arq_enqueue for callers in an async context.

        Use this when calling from ``async def`` code. The sync ``_arq_enqueue``
        raises if called from an async context — use this method instead.
        Returns True on success, False if Redis is unreachable.

        ``defer_seconds`` > 0 schedules the job to be picked up that many
        seconds in the future. Used by the per-investigation backpressure
        gate to avoid one investigation monopolising the worker pool.
        """
        from arq.connections import RedisSettings, create_pool
        from datetime import timedelta  # noqa: PLC0415

        pool = None
        try:
            settings = RedisSettings.from_dsn(redis_url)
            pool = await create_pool(settings)
            queue_key = ARQ_QUEUE_KEY_TEMPLATE.format(track=track)
            arq_fn_name = fn_path.rsplit(".", 1)[-1]
            enqueue_kwargs: dict = {
                "_queue_name": queue_key,
                "_job_id": task_id,
                **kwargs,
            }
            if defer_seconds > 0:
                enqueue_kwargs["_defer_by"] = timedelta(seconds=defer_seconds)
            await pool.enqueue_job(
                arq_fn_name,
                **enqueue_kwargs,
            )
            _ = fn_module, user_id  # retained in signature for callers
            return True
        except Exception as exc:
            _log.error(
                "Redis unavailable (url=%s): %s — async submission rejected.",
                redis_url,
                exc,
            )
            return False
        finally:
            if pool is not None:
                await pool.aclose()
