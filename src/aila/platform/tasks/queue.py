"""TaskQueue -- platform-owned task submission API.

Modules receive a TaskQueue instance on context.task_queue and call submit()
to enqueue background work. They never touch ARQ, Redis, or TaskRecord
directly -- the platform owns the infrastructure boundary.

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

import contextvars
import hashlib
import inspect
import json
import logging
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from graphlib import CycleError, TopologicalSorter

from arq.connections import RedisSettings, create_pool
from redis import asyncio as aioredis
from sqlalchemy import cast
from sqlalchemy import delete as _delete
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlmodel import func, select

from aila.api.constants import MODULE_ID_PLATFORM
from aila.platform.exceptions import WorkerUnreachableError
from aila.platform.tasks.constants import (
    ARQ_IN_PROGRESS_PREFIX,
    ARQ_JOB_PREFIX,
    ARQ_QUEUE_KEY_TEMPLATE,
    ARQ_RESULT_PREFIX,
    ARQ_RETRY_PREFIX,
    CONFIG_KEY_REDIS_URL,
    CONFIG_NS_PLATFORM,
)
from aila.platform.tasks.models import TaskHandle, TaskRecord, TaskStatus
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowStateCursor

__all__ = [
    "TaskQueue",
    "requeue_same_job_id",
]

_log = logging.getLogger(__name__)

# #53: team_id of the currently-running task. The @platform_task wrapper sets
# this from the running TaskRecord before invoking the body; submit() reads it
# so a follow-up task spawned inside a worker inherits its parent's team_id
# without every worker/agent submit site threading it explicitly. It is None
# outside any task execution (request handlers, cron), so root submits still
# pass team_id explicitly.
_current_task_team_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "aila_current_task_team_id", default=None,
)

# #53: user_id of the currently-running task. Set alongside
# ``_current_task_team_id`` from the running TaskRecord in the
# ``@platform_task`` wrapper. Read by tools that need the authenticated
# identity of the caller (AuditLogTool, follow-up submits) so an agent
# cannot spoof ``user_id`` through tool input. Unset outside a task
# execution (request handlers, cron); tool sites fall back to ``"system"``.
_current_task_user_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "aila_current_task_user_id", default=None,
)


def _env_redis_url() -> str | None:
    """Return ``AILA_PLATFORM_REDIS_URL`` from the environment (None when unset).

    Non-``TaskQueue`` call sites (e.g. :class:`aila.platform.tasks.storage.TaskRepository`
    status-transition helpers) reach the same Redis broker as ``TaskQueue.submit``
    but do not carry a ``ConfigRegistry`` reference. Mirrors the env-only
    lookup used by ``worker._reconcile_orphan_arq_locks`` /
    ``worker._sweep_orphan_running_tasks`` so all three code paths agree on
    which Redis they talk to when only the env is present.
    """
    import os

    url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
    return url or None


def qualified_task_name(fn: Callable[..., object]) -> str:
    """Return the ARQ registry key for ``fn`` without double-qualifying.

    ``@platform_task`` decorates a callable by replacing ``__qualname__``
    with the full dotted ``registry_name`` (template.py), so joining
    ``module.__name__`` onto it again yields a doubled path
    (``aila.modules.vr.workflow.task.aila.modules.vr.workflow.task.run_vr_investigate``)
    that ARQ cannot resolve -- the function map is keyed on the
    single-qualified name. Plain module-level callables still carry a bare
    ``__qualname__`` and need the module prefix joined.

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
    qualname = fn.__qualname__
    if qualname.startswith(f"{module.__name__}."):
        return qualname
    return f"{module.__name__}.{qualname}"


async def _enqueue_arq_job(
    track: str,
    task_id: str,
    fn_name: str,
    kwargs: dict[str, object],
    redis_url: str,
    defer_seconds: float = 0.0,
) -> bool:
    """Enqueue an ARQ job using the same conventions as ``TaskQueue.submit``.

    ``fn_name`` is the fully-qualified registry name
    ``{fn.__module__}.{fn.__qualname__}`` -- the same value stored in
    ``TaskRecord.fn_path`` and used as the ARQ ``Function.name`` key by
    :meth:`aila.platform.tasks.template._Registry.all_functions` (#40-5).
    Passing the bare ``__qualname__`` here would inherit the cross-module
    collision documented in CLAUDE.md #19: two modules registering the same
    bare name would silently overwrite one another in ARQ's function map,
    so the queue would dispatch the right job id but run the wrong body.
    ``kwargs`` are forwarded verbatim; ``defer_seconds`` mirrors the
    ``_defer_by`` scheduling argument. Returns True on success, False when
    Redis is unreachable or the enqueue raises.

    Shared by:
    - :meth:`TaskQueue._arq_enqueue_async` (initial submit path).
    - :meth:`TaskQueue.requeue_failed` (post-failure re-enqueue).
    - :meth:`aila.platform.tasks.storage.TaskRepository.set_queued_from_paused`
      (resume-from-pause re-enqueue).
    All three must go through one code path so future changes to the
    enqueue convention (queue key template, defer semantics, job-id shape)
    only need one edit.
    """
    pool = None
    try:
        settings = RedisSettings.from_dsn(redis_url)
        pool = await create_pool(settings)
        queue_key = ARQ_QUEUE_KEY_TEMPLATE.format(track=track)
        enqueue_kwargs: dict = {
            "_queue_name": queue_key,
            "_job_id": task_id,
            **kwargs,
        }
        if defer_seconds > 0:
            enqueue_kwargs["_defer_by"] = timedelta(seconds=defer_seconds)
        job = await pool.enqueue_job(fn_name, **enqueue_kwargs)
        # RFC-07 reconcile wave: ARQ returns ``None`` when a job or its
        # retained result for ``_job_id`` still lives in Redis (dedup with
        # keep_result=3600s). A None return means the enqueue was REFUSED,
        # not performed -- callers treat a False return as leave-status /
        # retry, so reporting refused-as-success here would let a stale
        # ``arq:job:<id>`` / ``arq:result:<id>`` fake a live queue. This
        # is the single enqueue-verification chokepoint every resubmission
        # path (submit, requeue_failed, set_queued_from_paused, the
        # same-job-id resume helper) funnels through.
        return job is not None
    except Exception as exc:
        # Redis / arq errors surface heterogeneously (RedisError, OSError,
        # ValueError from DSN parsing, TimeoutError). Callers translate a
        # False return into WorkerUnreachableError / a leave-status action.
        _log.error(
            "Redis unavailable (url=%s): %s -- async enqueue rejected.",
            redis_url, exc,
        )
        return False
    finally:
        if pool is not None:
            await pool.aclose()


async def _drop_arq_in_progress_key(task_id: str, redis_url: str) -> bool:
    """Best-effort delete of ``arq:in-progress:<task_id>`` from Redis.

    Mirrors ``worker._sweep_orphan_running_tasks`` which deletes the same
    key when a task is force-cancelled. A failed delete does NOT reverse
    the caller's DB-side transition -- the cron reaper reconciles orphan
    keys on the next sweep. Returns True on a clean delete, False on
    failure.
    """
    client = aioredis.Redis.from_url(redis_url, socket_connect_timeout=2.0)
    try:
        await client.delete(f"{ARQ_IN_PROGRESS_PREFIX}{task_id}")
        return True
    except (OSError, TimeoutError, RuntimeError) as exc:
        _log.warning(
            "queue._drop_arq_in_progress_key(%s) failed: %s -- reaper "
            "will reconcile on the next sweep", task_id, exc,
        )
        return False
    finally:
        try:
            await client.aclose()
        except (OSError, RuntimeError) as close_exc:
            _log.debug(
                "queue._drop_arq_in_progress_key(%s) client.aclose() failed: %s",
                task_id, close_exc,
            )


async def requeue_same_job_id(task_id: str, *, track: str | None = None) -> bool:
    """Re-run an existing tracked run under its OWN job id (never a fresh uuid).

    The single "make this checkpointed run run again" primitive (RFC-07
    reconcile wave, L1.2). ARQ dedup refuses a re-enqueue while a job or
    its retained result for ``_job_id`` still lives in Redis
    (``keep_result=3600s``), so a same-id resume must first clear that
    stale debris; and the ``TaskRecord`` must be reset to QUEUED so the
    row finalizes normally when the resumed worker finishes. The
    ``workflow_state_cursor`` row keyed by ``run_id == task_id`` is
    intentionally NOT touched: the engine picks the checkpoint back up
    on the next execute, which is the entire point of reusing the id.

    Ordering preserves the enqueue-first invariant (every
    ``status='queued'`` row is backed by a live ARQ job) that
    ``requeue_failed`` also maintains: the row is only reset after the
    enqueue returned a live job. A missing TaskRecord, a missing Redis
    URL, an empty ``fn_path`` / ``track``, malformed ``kwargs_json``, or
    a refused enqueue all return ``False`` with the row untouched.

    Args:
        task_id: TaskRecord.id == ARQ job_id == workflow_state_cursor.run_id.
        track: ARQ queue track. Defaults to the row's own ``track``.

    Returns:
        True when a live ARQ job was enqueued under ``task_id`` AND the
        row was reset to QUEUED in the same call; False otherwise (caller
        leaves the row alone / retries later).
    """
    async with async_session_scope() as session:
        record = await session.get(TaskRecord, task_id)
        if record is None:
            _log.info(
                "queue.requeue_same_job_id(%s): no TaskRecord -- nothing "
                "to resume under this id", task_id,
            )
            return False
        effective_track = track or record.track
        if not effective_track or not record.fn_path:
            _log.warning(
                "queue.requeue_same_job_id(%s): missing track / fn_path -- "
                "cannot resume", task_id,
            )
            return False
        try:
            task_kwargs = json.loads(record.kwargs_json) if record.kwargs_json else {}
        except (TypeError, ValueError) as exc:
            _log.warning(
                "queue.requeue_same_job_id(%s): kwargs_json malformed (%s) "
                "-- cannot resume", task_id, exc,
            )
            return False
        redis_url = _env_redis_url()
        if not redis_url:
            _log.warning(
                "queue.requeue_same_job_id(%s): AILA_PLATFORM_REDIS_URL "
                "unset -- cannot resume", task_id,
            )
            return False

    # 1. Clear stale ARQ debris for the id so dedup accepts it: the job
    #    blob, the retained result, the retry counter, and any dangling
    #    in-progress worker slot. Best-effort: a failed clear just makes
    #    the enqueue below come back refused (False), which is the same
    #    leave-alone outcome.
    client = aioredis.Redis.from_url(redis_url, socket_connect_timeout=2.0)
    try:
        await client.delete(
            f"{ARQ_JOB_PREFIX}{task_id}",
            f"{ARQ_RESULT_PREFIX}{task_id}",
            f"{ARQ_RETRY_PREFIX}{task_id}",
            f"{ARQ_IN_PROGRESS_PREFIX}{task_id}",
        )
    except (OSError, TimeoutError, RuntimeError) as exc:
        _log.warning(
            "queue.requeue_same_job_id(%s): ARQ debris clear failed: %s",
            task_id, exc,
        )
    finally:
        try:
            await client.aclose()
        except (OSError, RuntimeError) as close_exc:
            _log.debug(
                "queue.requeue_same_job_id(%s) client.aclose() failed: %s",
                task_id, close_exc,
            )

    # 2+3. Enqueue first (live job under the same id), then reset the row.
    enqueued = await _enqueue_arq_job(
        track=effective_track,
        task_id=task_id,
        fn_name=record.fn_path,
        kwargs=task_kwargs,
        redis_url=redis_url,
    )
    if not enqueued:
        _log.warning(
            "queue.requeue_same_job_id(%s): enqueue refused -- row left "
            "unchanged", task_id,
        )
        return False

    async with async_session_scope() as session:
        current = await session.get(TaskRecord, task_id)
        if current is None:
            # Row vanished between the enqueue and this reset (a parallel
            # canceled/delete raced us); the ARQ job will pick up nothing
            # and finish quietly. Nothing left to reset.
            _log.info(
                "queue.requeue_same_job_id(%s): row vanished after "
                "enqueue; job will no-op", task_id,
            )
            return False
        current.status = TaskStatus.QUEUED.value
        current.started_at = None
        current.heartbeat_at = None
        current.completed_at = None
        current.error = (
            (current.error or "")
            + f"[requeue_same_job_id: resumed under original job id {task_id}]\n"
        )
        current.updated_at = datetime.now(UTC)
        session.add(current)
        try:
            await session.commit()
        except IntegrityError:
            # §72 partial UNIQUE index on input_hash (status IN queued/
            # running/waiting) rejected the reset: another active row with
            # the same fn+kwargs is already queued/running. Resetting this
            # row to QUEUED would create a second active duplicate. Roll
            # back and treat the requeue as a no-op -- the live twin owns
            # the work. The ARQ job enqueued above will find a non-runnable
            # row and quietly no-op.
            await session.rollback()
            _log.info(
                "queue.requeue_same_job_id(%s): reset skipped -- active "
                "duplicate input_hash already present; leaving row as-is",
                task_id,
            )
            return False
    _log.info(
        "queue.requeue_same_job_id(%s): re-enqueued under same id track=%s",
        task_id, effective_track,
    )
    return True


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
        config_registry: object,  # ConfigRegistry -- avoid circular import at module level
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
        bypass_dedup: bool = False,
    ) -> TaskHandle:
        """Submit a background task. Returns a TaskHandle for status polling.

        Validates module boundary (MOD-10 / D-04), persists a TaskRecord
        (MOD-06), checks dependency DAG for cycles (MOD-11 / D-14), and
        enqueues to ARQ. Redis is REQUIRED -- if the broker cannot be
        reached, ``WorkerUnreachableError`` is raised BEFORE any DB record
        is persisted so the caller sees a clean 503 and no orphan task
        records accumulate.

        Args:
            track: Task track name -- maps 1:1 to ARQ queue key (D-02 / MOD-07).
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

        # #53: inherit the running task's team_id for a follow-up that does not
        # pass one explicitly. Root submits (request handlers) pass
        # team_id=auth.team_id; system/cron submits run outside any task, so
        # the ContextVar default (None) leaves them unscoped.
        if team_id is None:
            team_id = _current_task_team_id.get()

        fn_path = self._get_fn_path(fn)
        fn_module = self._extract_module_id(fn_path)
        self._enforce_module_boundary(fn_path, fn_module)

        # SEC-07: SHA-256 task dedup. fix §73 -- drop ``default=str`` so two
        # semantically different kwarg sets (Decimal("1.0") vs "1.0", UUID
        # vs UUID-string, datetime vs ISO string) no longer stringify-collide
        # into the same dedup hash. Callers must pass JSON-clean kwargs.
        #
        # bypass_dedup = True path (2026-06-12, maddie stall fix): when the
        # caller is mid-task and wants to enqueue a continuation, the dedup
        # query would match the caller's own still-running TaskRecord and
        # hand back its id WITHOUT enqueueing a new task. The caller thinks
        # success; the worker exits; nothing's in the queue. The branch
        # idles forever.
        # Diagnosed on inv <inv-uuid-a> maddie branch <inv-uuid-b>: AUTO_CONTINUE
        # from investigation_emit hit dedup against its own running task.
        # Mix a UUID into the hash input when bypass_dedup is set so the
        # dedup query never matches the caller (different hash) AND the
        # §72 partial UNIQUE index on input_hash WHERE status IN
        # (queued, running, waiting) doesn't reject the insert.
        # The persisted kwargs_json stays clean (no UUID leakage into
        # worker's view of arguments).
        try:
            _hash_payload: dict[str, object] = {"fn": fn_path, "kwargs": kwargs}
            if bypass_dedup:
                _hash_payload["_continue_seq"] = uuid.uuid4().hex
            input_hash = hashlib.sha256(
                json.dumps(_hash_payload, sort_keys=True).encode(),
            ).hexdigest()
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "TaskQueue.submit kwargs must be JSON-serializable "
                f"(strict mode -- §73): {exc}",
            ) from exc

        if not bypass_dedup:
            async with async_session_scope() as dedup_session:
                existing = (await dedup_session.exec(
                    select(TaskRecord)
                    .where(TaskRecord.input_hash == input_hash)
                    .where(TaskRecord.status.in_(["queued", "running", "waiting"]))  # type: ignore[union-attr]
                )).first()
                if existing is not None:
                    _log.info(
                        "Task dedup: returning existing task %s for hash %s",
                        existing.id, input_hash[:12],
                    )
                    return TaskHandle(task_id=str(existing.id))

        # RFC-13 DEDUP MISMATCH FIX (2026-07-26): branch-scoped soft dedup.
        # The hash-based dedup above cannot see an in-flight auto_continue
        # because that same branch's auto_continue mixes a UUID into the
        # hash (``bypass_dedup=True`` in emit_base) so the caller does not
        # match its own running TaskRecord. Consequence: when spawn_fn
        # (normal dedup) races an already-in-flight auto_continue, both
        # succeed and two tasks land on the same branch. Duplicate turns
        # bill twice, race the case_state cursor, and produce the
        # per-branch duplication reported on RFC-13.
        #
        # This branch-scoped check runs for every submit that carries both
        # ``investigation_id`` and ``branch_id`` (regardless of
        # ``bypass_dedup``) and searches ONLY ``queued`` / ``waiting``
        # tasks -- never ``running`` -- so it can never match the caller's
        # own record on the auto_continue path. It narrows by fn_path and
        # by a LIKE match on branch_id in kwargs_json before parsing the
        # candidate rows, so the Python-side filter stays bounded even on
        # a busy queue. Documented choice: extend spawn_fn's dedup surface
        # to SEE auto_continue tasks (rather than stripping bypass_dedup
        # out of auto_continue, which would re-open the caller-matches-self
        # bug diagnosed 2026-06-12 on maddie branch).
        inv_id_val = kwargs.get("investigation_id") if isinstance(kwargs, dict) else None
        branch_id_val = kwargs.get("branch_id") if isinstance(kwargs, dict) else None
        if (
            isinstance(inv_id_val, str) and inv_id_val
            and isinstance(branch_id_val, str) and branch_id_val
        ):
            async with async_session_scope() as branch_dedup_session:
                candidates = (await branch_dedup_session.exec(
                    select(TaskRecord)
                    .where(TaskRecord.fn_path == fn_path)
                    .where(TaskRecord.status.in_(["queued", "waiting"]))  # type: ignore[union-attr]
                    .where(TaskRecord.kwargs_json.like(f'%"{branch_id_val}"%'))
                )).all()
            for c in candidates:
                try:
                    c_kwargs = json.loads(c.kwargs_json or "{}")
                except (ValueError, TypeError):
                    continue
                if (
                    str(c_kwargs.get("investigation_id") or "") == inv_id_val
                    and str(c_kwargs.get("branch_id") or "") == branch_id_val
                ):
                    _log.info(
                        "Task branch-dedup: returning existing %s for "
                        "inv=%s branch=%s fn=%s (avoids duplicate "
                        "spawn/auto_continue for the same branch)",
                        c.id, inv_id_val, branch_id_val, fn_path,
                    )
                    return TaskHandle(task_id=str(c.id))


        # Fail-fast Redis reachability check (no DB record written yet). This
        # is the single source of truth for "broker is usable" -- if the check
        # passes but the actual enqueue later fails, that exception is also
        # surfaced as WorkerUnreachableError so no orphan DB record remains.
        redis_url = None
        defer_seconds = 0.0
        if not depends_on:
            redis_url = self._get_redis_url()
            if not redis_url:
                raise WorkerUnreachableError(
                    "Task queue Redis URL is not configured -- submission rejected."
                )
            # Whole Window pre-computation (RFC-07 reconcile wave, L2.3):
            # resolve the per-investigation backpressure defer BEFORE the
            # TaskRecord commits so the commit->enqueue window holds no DB
            # round-trip. A crash in that window used to leave a QUEUED row
            # with no ARQ job (the defer SELECT ran after the commit and a
            # process death between them orphaned the row).
            defer_seconds = await self._compute_investigation_defer(kwargs)

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
            try:
                await session.commit()
            except IntegrityError:
                # fix §72 -- the partial UNIQUE index on input_hash WHERE
                # status IN (queued, running, waiting) caught the race
                # between two concurrent submit() calls with identical
                # fn+kwargs. The loser falls back to a dedup return of
                # the winner's task_id, so the operator never sees two
                # ARQ jobs for the same hash.
                await session.rollback()
                async with async_session_scope() as dedup_session:
                    winner = (await dedup_session.exec(
                        select(TaskRecord)
                        .where(TaskRecord.input_hash == input_hash)
                        .where(
                            TaskRecord.status.in_(  # type: ignore[union-attr]
                                ["queued", "running", "waiting"],
                            ),
                        )
                    )).first()
                if winner is not None:
                    _log.info(
                        "Task dedup via §72 unique index: hash=%s winner=%s",
                        input_hash[:12], winner.id,
                    )
                    return TaskHandle(task_id=str(winner.id))
                # No active winner row -- the race resolved to a terminal
                # state between the integrity error and our re-read. Bail.
                raise
            await session.refresh(record)
            task_id = record.id

        if depends_on:
            try:
                await self._validate_dag(task_id, depends_on)
            except ValueError:
                # fix §74 -- rollback path now also deletes the workflow_state_cursor
                # row keyed by run_id == task_id so a parallel worker that loaded
                # the cursor between INSERT and rollback can't leave it orphaned.
                async with async_session_scope() as session:
                    orphan = (await session.exec(
                        select(TaskRecord).where(TaskRecord.id == task_id)
                    )).first()
                    if orphan is not None:
                        await session.delete(orphan)
                        await session.commit()
                await self._delete_orphan_cursor(task_id)
                raise

        if not depends_on:
            if redis_url is None:
                raise ValueError("Redis URL is not configured -- check AILA_PLATFORM_REDIS_URL")
            # Per-investigation backpressure was resolved BEFORE the record
            # commit (L2.3); ``defer_seconds`` is already computed above.
            try:
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
            except (OSError, TimeoutError, RuntimeError) as exc:
                # L2.3 exception arm: the enqueue path normally swallows
                # broker errors into a False return, but a transport
                # exception that escapes it (a close() failure on the
                # pool, task teardown) must NOT leave the just-committed
                # QUEUED row alive without a job. Mirror the enqueue==False
                # cleanup below so every failure mode converges on the
                # same rollback.
                async with async_session_scope() as session:
                    ghost = (await session.exec(
                        select(TaskRecord).where(TaskRecord.id == task_id)
                    )).first()
                    if ghost is not None:
                        await session.delete(ghost)
                        await session.commit()
                await self._delete_orphan_cursor(task_id)
                raise WorkerUnreachableError(
                    f"Task queue Redis is unreachable (url={redis_url}) -- submission rejected."
                ) from exc
            if not enqueued:
                # Roll back the DB record so a failed enqueue does not leave
                # a ghost "queued" task sitting in the DB forever. fix §74 --
                # also clean up any workflow_state_cursor that was created
                # by a parallel worker between the INSERT commit and this
                # rollback.
                async with async_session_scope() as session:
                    ghost = (await session.exec(
                        select(TaskRecord).where(TaskRecord.id == task_id)
                    )).first()
                    if ghost is not None:
                        await session.delete(ghost)
                        await session.commit()
                await self._delete_orphan_cursor(task_id)
                raise WorkerUnreachableError(
                    f"Task queue Redis is unreachable (url={redis_url}) -- submission rejected."
                )

        return TaskHandle(task_id=task_id)

    # Per-investigation in-flight cap. Tasks beyond this count for the
    # same investigation_id get deferred so other investigations don't
    # starve. Value is intentionally small: each branch turn is a
    # separate task and a 3-branch investigation routinely has 3 in
    # flight; allowing 6 covers normal fan-out without monopolising.
    INVESTIGATION_INFLIGHT_CAP: int = 6
    INVESTIGATION_DEFER_STEP_S: float = 30.0
    # RFC-07 reconcile wave (L2.3 / Finding 5): upper bound on the
    # per-investigation defer. Schema field
    # ``platform.investigation_defer_ceiling_s`` carries the operator
    # override; this constant is the code fallback for a TaskQueue built
    # without a ConfigRegistry (tests) and must match the schema default.
    INVESTIGATION_DEFER_CEILING_DEFAULT_S: float = 180.0

    def _resolve_defer_ceiling_s(self) -> float:
        """Return the bounded defer ceiling for one investigation submit.

        Reads ``platform.investigation_defer_ceiling_s`` (schema default
        ``180``) via ``ConfigRegistry.get_sync`` -- the same sync read
        :meth:`_get_redis_url` uses -- so an operator can widen or narrow
        the ceiling with ``PUT /config/platform`` / the
        ``AILA_PLATFORM_INVESTIGATION_DEFER_CEILING_S`` env var without a
        restart. A registry-less TaskQueue (test construction) or a
        failed lookup falls back to the class constant, which matches the
        schema default.
        """
        try:
            if self._config_registry is not None:
                value = self._config_registry.get_sync(
                    CONFIG_NS_PLATFORM, "investigation_defer_ceiling_s",
                )
                if value is not None:
                    return float(value)
        except (OSError, RuntimeError, ValueError, TypeError):
            _log.debug(
                "queue._resolve_defer_ceiling_s: lookup failed; using "
                "default", exc_info=True,
            )
        return self.INVESTIGATION_DEFER_CEILING_DEFAULT_S

    async def _compute_investigation_defer(
        self, kwargs: dict[str, object],
    ) -> float:
        """Return seconds to defer this submission based on in-flight
        task count for the same investigation. Returns 0 when the
        submission is not investigation-scoped or under the cap. The
        computed excess is capped at the operator ceiling
        (``platform.investigation_defer_ceiling_s``, default 180s) so a
        wide / repeatedly-resumed investigation can never be deferred
        without bound (RFC-07 reconcile wave, L2.3 / Finding 5).
        """
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
        except (SQLAlchemyError, OSError, TimeoutError, RuntimeError) as exc:
            # Fail closed (#31, RFC-07 acceptance bullet 2): a DB error makes
            # in-flight load unmeasurable, so assume the queue is under
            # pressure and back off by one bounded step rather than returning
            # 0.0 -- returning 0.0 floods the queue under DB pressure and
            # deepens the spiral. The defer is bounded and clears on the next
            # healthy read. Routing through ResilienceLayer.conservative_default
            # centralises the fail-signal bump so this site stops carrying its
            # own metric-and-log pattern. The resilience module is imported
            # inside this handler (not at file scope) because services/__init__
            # re-exports audit which back-imports this module, so a top-level
            # binding here breaks module load.
            from aila.platform.services.resilience import (
                get_default_resilience_layer,
            )

            return get_default_resilience_layer().conservative_default(
                self.INVESTIGATION_DEFER_STEP_S,
                op="queue_investigation_defer",
                source="db_error",
                exc=exc,
            )
        excess = max(0, int(count) - self.INVESTIGATION_INFLIGHT_CAP)
        computed = excess * self.INVESTIGATION_DEFER_STEP_S
        return min(computed, self._resolve_defer_ceiling_s())

    # ---- admin management methods ----------------------------------------

    async def depth(self) -> dict[str, int]:
        """Return task counts grouped by status."""
        async with async_session_scope() as session:
            rows = (await session.exec(
                select(TaskRecord.status, func.count(TaskRecord.id))
                .group_by(TaskRecord.status)
            )).all()
            return {status: count for status, count in rows}

    async def drain(self) -> int:
        """Pause new submissions and return pending task count."""
        self._draining = True
        async with async_session_scope() as session:
            count = (await session.exec(
                select(func.count(TaskRecord.id))
                .where(TaskRecord.status == "queued")
            )).one()
            return count

    async def enqueued_investigation_ids(
        self, investigation_ids: Sequence[str],
    ) -> set[str]:
        """Return the subset of ``investigation_ids`` that already have
        at least one ``TaskRecord`` row on file.

        Read-only. Matches on the typed JSONB extract
        ``(kwargs_json::jsonb)->>'investigation_id'`` so the check is on
        a JSON path, not a substring, and cannot false-positive on
        tasks that embed the same UUID in a different kwarg
        (``parent_investigation_id`` etc.). Returned set is a subset of
        the input; ids with no matching row are simply absent. Empty
        input returns an empty set without touching the database.

        RFC-05 crit 10: modules never query the platform-owned
        ``taskrecord`` table directly. Cross-module reconcilers that
        need to distinguish "child investigation already handed off to
        the queue" from "child investigation still virgin" call this
        method instead of importing :class:`TaskRecord` and running a
        local JSONB-extract subquery. The platform owns the task
        table; this is the public read side of that boundary.
        """
        if not investigation_ids:
            return set()
        # Preserve caller's ordering, drop duplicates -- IN (...) is
        # unordered anyway and we return a set, so dedup keeps the
        # bound-parameter list minimal without changing semantics.
        ids = list(dict.fromkeys(investigation_ids))
        extracted = cast(TaskRecord.kwargs_json, JSONB)[
            "investigation_id"
        ].astext
        async with async_session_scope() as session:
            rows = (await session.exec(
                select(extracted)
                .where(extracted.in_(ids))
                .distinct()
            )).all()
        found: set[str] = set()
        for row in rows:
            # SQLModel session.exec returns Row tuples for a
            # single-column select; unwrap to the plain string.
            if hasattr(row, "__getitem__") and not isinstance(row, str):
                value = row[0]
            else:
                value = row
            if value is not None:
                found.add(str(value))
        return found

    async def requeue_failed(self, max_age_hours: int = 24) -> int:
        """Requeue recently failed tasks.

        For each row whose ``status='failed'`` and ``updated_at >= cutoff``,
        enqueue a fresh ARQ job with the row's ``fn_path`` / ``kwargs_json`` /
        ``track`` (mirroring :meth:`submit`'s enqueue path via
        :func:`_enqueue_arq_job`), THEN flip the status back to 'queued'
        and clear the error field. Enqueue-first ordering preserves the
        invariant that every ``status='queued'`` row is backed by a live
        ARQ job -- the previous code committed the DB flip without ever
        enqueueing (issue #40-1), leaving the task queued forever.

        If enqueue fails for a given row (Redis unreachable, malformed
        ``kwargs_json``, empty ``fn_path``), that row is skipped and
        stays 'failed' so a later call can retry it.

        Args:
            max_age_hours: Only requeue tasks that failed within this many hours.

        Returns:
            Number of tasks that were successfully re-enqueued AND flipped to 'queued'.

        Raises:
            WorkerUnreachableError: When the Redis URL is not configured -- no
                DB flips are performed, matching :meth:`submit`'s fail-fast policy.
        """
        redis_url = self._get_redis_url()
        if not redis_url:
            raise WorkerUnreachableError(
                "Task queue Redis URL is not configured -- requeue rejected."
            )
        cutoff = datetime.now(UTC) - timedelta(hours=max_age_hours)
        async with async_session_scope() as session:
            failed = (await session.exec(
                select(TaskRecord)
                .where(TaskRecord.status == "failed")
                .where(TaskRecord.updated_at >= cutoff)
            )).all()
            count = 0
            for task in failed:
                try:
                    task_kwargs = json.loads(task.kwargs_json) if task.kwargs_json else {}
                except (TypeError, ValueError) as exc:
                    _log.warning(
                        "requeue_failed: task %s kwargs_json malformed (%s) -- "
                        "leaving status=failed", task.id, exc,
                    )
                    continue
                # #40-5: enqueue with the fully-qualified ``fn_path``. ARQ's
                # function map is now keyed on the qualified registry name
                # (``_Registry.all_functions``), so the historical bare
                # ``__qualname__`` would miss whenever two modules shared a
                # callable name -- see CLAUDE.md #19.
                if not task.fn_path or not task.track:
                    _log.warning(
                        "requeue_failed: task %s missing fn_path / track -- "
                        "leaving status=failed", task.id,
                    )
                    continue
                enqueued = await _enqueue_arq_job(
                    track=task.track,
                    task_id=task.id,
                    fn_name=task.fn_path,
                    kwargs=task_kwargs,
                    redis_url=redis_url,
                )
                if not enqueued:
                    _log.warning(
                        "requeue_failed: enqueue failed for %s -- leaving status=failed",
                        task.id,
                    )
                    continue
                task.status = "queued"
                task.error = None
                session.add(task)
                count += 1
            await session.commit()
            return count

    # ---- private helpers ------------------------------------------------

    def _get_fn_path(self, fn: Callable[..., object]) -> str:
        """Return the fully-qualified dotted path of fn.

        Delegates to :func:`qualified_task_name`, which guards against
        double-qualifying ``@platform_task`` wrappers (they already carry
        the full dotted ``registry_name`` in ``__qualname__`` -- joining
        ``module.__name__`` again doubles the path and ARQ fails the job
        with ``function ... not found``).

        Example: "aila.modules.vulnerability.tasks.scan"
        """
        return qualified_task_name(fn)

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

    # #40-6: hard ceiling on the DAG-cycle scan. A cycle would have to lie
    # inside the live task graph, so scoping to non-terminal statuses
    # (WAITING/QUEUED/RUNNING/PAUSED) is both correct and small enough to
    # keep the scan bounded. The extra LIMIT is defence-in-depth against a
    # pathological blast radius (e.g. thousands of paused rows waiting on
    # operator resume). If the incoming edge or one of its deps is not in
    # the loaded slice, the topological sort still catches any cycle that
    # touches ``new_task_id``'s reachable set from the loaded rows; a
    # cycle wholly outside that set cannot include the new edge.
    _VALIDATE_DAG_SCAN_LIMIT: int = 10_000

    async def _validate_dag(self, new_task_id: str, depends_on: list[str]) -> None:
        """Raise ValueError if adding this dependency edge creates a cycle in the task DAG.

        The historical implementation loaded EVERY ``TaskRecord`` in the
        database (#40-6); on a long-lived deployment with hundreds of
        thousands of terminal rows that was an O(N) scan per new task with
        deps. The scan is now scoped to non-terminal statuses (the only
        rows that can participate in a live dependency cycle) and capped
        by ``_VALIDATE_DAG_SCAN_LIMIT``.
        """
        graph: dict[str, set[str]] = {}
        async with async_session_scope() as session:
            records = (await session.exec(
                select(TaskRecord)
                .where(
                    TaskRecord.status.in_(  # type: ignore[union-attr]
                        [
                            TaskStatus.WAITING,
                            TaskStatus.QUEUED,
                            TaskStatus.RUNNING,
                            TaskStatus.PAUSED,
                        ],
                    ),
                )
                .limit(self._VALIDATE_DAG_SCAN_LIMIT)
            )).all()
            for r in records:
                deps: list[str] = json.loads(r.depends_on_json) if r.depends_on_json else []
                graph[r.id] = set(deps)
        graph[new_task_id] = set(depends_on)
        try:
            sorter = TopologicalSorter(graph)
            sorter.prepare()
        except CycleError as exc:
            raise ValueError(f"Circular dependency detected: {exc}") from exc

    async def _delete_orphan_cursor(self, task_id: str) -> None:
        """Drop ``workflow_state_cursor`` rows keyed by ``task_id`` on the
        rollback paths in :meth:`submit` (fix §74).

        A parallel worker that loaded ``_load_or_init_cursor`` between
        the INSERT commit and the rollback could leave a cursor without
        a TaskRecord backing it. ``cursor_reaper`` only sweeps
        ``__crashed__`` cursors; this one would be at ``start_state``
        and linger forever, blocking re-submission per the
        stale-cursor-blocks-resubmission rule in CLAUDE.md.

        Best-effort: never raises. A failed cleanup just leaves the
        cursor for the cursor reaper to pick up on a later sweep.
        """
        try:
            async with async_session_scope() as session:
                await session.execute(
                    _delete(WorkflowStateCursor).where(
                        WorkflowStateCursor.run_id == task_id,
                    )
                )
                await session.commit()
        except Exception as exc:
            _log.warning(
                "queue._delete_orphan_cursor(%s) failed: %s; cursor reaper "
                "will retry on the next tick", task_id, exc,
            )

    def _get_redis_url(self) -> str | None:
        import os
        # Check env var first (sync-safe, no async registry call needed)
        env_url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
        if env_url:
            return env_url
        if self._config_registry is None:
            return None
        try:
            # get_sync is the sync read path (C3); the async .get() returned a
            # coroutine that this sync method could never await, so the URL was
            # always dropped and enqueue silently fell back to env-only.
            url = self._config_registry.get_sync(CONFIG_NS_PLATFORM, CONFIG_KEY_REDIS_URL)
            return str(url) if url else None
        except (OSError, RuntimeError, ValueError):
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

        ``submit()`` (``async def``) uses ``_arq_enqueue_async`` instead -- the async
        variant avoids spawning a thread pool and awaits ARQ directly.

        DO NOT call ``_arq_enqueue`` from ``async def`` code -- use ``_arq_enqueue_async``.
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
            # A running loop was found -- this is the violation case.
            _log.error(
                "task_queue._arq_enqueue called from async context -- use _arq_enqueue_async instead"
            )
            raise RuntimeError(
                "_arq_enqueue called from an async context; use _arq_enqueue_async instead"
            )
        except RuntimeError as _loop_err:
            if "_arq_enqueue called from an async context" in str(_loop_err):
                raise
            # RuntimeError from get_running_loop() means no loop present -- safe to proceed.

        async def _enqueue() -> bool:
            settings = RedisSettings.from_dsn(redis_url)
            pool = await create_pool(settings)
            try:
                queue_key = ARQ_QUEUE_KEY_TEMPLATE.format(track=track)
                # #40-5: ARQ registers each ``@platform_task`` under its
                # fully-qualified ``{fn.__module__}.{fn.__qualname__}``
                # registry name (see ``_Registry.all_functions``). Enqueue
                # under that same key so two modules that share a bare
                # callable name (CLAUDE.md #19) cannot cross-dispatch --
                # the right task id would otherwise resolve to whichever
                # module was imported last.
                job = await pool.enqueue_job(
                    fn_path,
                    _queue_name=queue_key,
                    _job_id=task_id,
                    **kwargs,
                )
                # fn_module and user_id are captured on the TaskRecord and
                # looked up by the hooks; they are no longer passed as ARQ
                # job args because the @platform_task wrapper owns the
                # signature shape (ctx: TaskContext, **kwargs).
                _ = fn_module, user_id  # retained in signature for callers
                # RFC-07 reconcile wave: mirror ``_enqueue_arq_job`` --
                # a ``None`` job (ARQ dedup refusing the ``_job_id``) is a
                # refused enqueue, never a success.
                return job is not None
            finally:
                await pool.aclose()

        try:
            # No running loop in this thread (validated above) -- asyncio.run() is safe.
            return _asyncio.run(_enqueue())
        except Exception as exc:
            # Redis/broker is unreachable. Callers surface this as
            # WorkerUnreachableError. There is NO sync fallback.
            _log.error(
                "Redis unavailable (url=%s): %s -- submission will be rejected.",
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
        raises if called from an async context -- use this method instead.
        Returns True on success, False if Redis is unreachable.

        ``defer_seconds`` > 0 schedules the job to be picked up that many
        seconds in the future. Used by the per-investigation backpressure
        gate to avoid one investigation monopolising the worker pool.
        """
        _ = fn_module, user_id  # retained in signature for callers
        # #40-5: pass the fully-qualified ``fn_path`` -- ARQ's Function map
        # is keyed on the same qualified name via ``_Registry.all_functions``,
        # so the bare ``__qualname__`` would miss on any dual-module bare-name
        # collision (CLAUDE.md #19).
        return await _enqueue_arq_job(
            track=track,
            task_id=task_id,
            fn_name=fn_path,
            kwargs=kwargs,
            redis_url=redis_url,
            defer_seconds=defer_seconds,
        )
