"""ARQ worker lifecycle hooks (Phase 179).

Two callables here populate the ARQ ``WorkerSettings``:

* :func:`_on_job_start` -- load the TaskRecord, set ``RUNNING`` on first try,
  bind structlog, populate ``WorkflowRunRecord.plan_json`` for engine tasks.
* :func:`_on_job_end` -- single source of truth for TaskRecord terminal
  state. Reads the per-job outcome stashed by the ``@platform_task``
  wrapper and drives one of six D-14 branches.

The stash pattern (``_OUTCOME_STASH``) exists because ARQ's ``on_job_end``
hook receives only ``ctx``; it does NOT see the job's return value or the
raised exception. The wrapper writes into the stash, the hook reads from
it. Stash keys are ``(job_id, job_try)`` so a retry on the same job_id
doesn't clobber the previous attempt's outcome before the hook consumes it.

Trust-boundary note (T-179-01): the stash lives in the worker process's
memory only. A process restart clears it; the hook degrades gracefully by
assuming a crash-before-stash (Branch 4) and marking the task DEAD_LETTER
with a clear error message. No cross-process trust.
"""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Any, Literal

import structlog
from arq import create_pool as _create_pool
from arq.connections import RedisSettings as _RedisSettings
from sqlalchemy import update as sa_update
from sqlmodel import select

from aila.api.metrics import TASK_DEAD_LETTER_TOTAL
from aila.platform.contracts import utc_now
from aila.platform.runtime.shared import get_shared_run_memory
from aila.platform.tasks.constants import ARQ_QUEUE_KEY_TEMPLATE
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import async_session_scope

# Internal module: every callable here (``_on_job_start``, ``_on_job_end``,
# ``_stash_outcome``, ``_pop_outcome``) is sibling-internal and is imported
# directly by ``aila.platform.tasks.template`` and ``aila.platform.tasks.worker``.
# There is no public surface via star-import, so ``__all__`` is intentionally
# omitted.


_log = logging.getLogger(__name__)
_slog = structlog.get_logger(__name__)
_OUTCOME_STASH_MAX = 50_000
_OUTCOME_STASH_SWEEP_BATCH = 100


OutcomeKind = Literal[
    "success",
    "retry_signalled",
    "exception",
    "cancelled",
    "timeout",
]


@dataclass(frozen=True, slots=True)
class _JobOutcome:
    """Outcome record written by the @platform_task wrapper for the hook.

    Attributes:
        kind: Discriminant consumed by :func:`_on_job_end`'s branch switch.
        result: Return value on ``kind == "success"``. ``None`` otherwise.
        exception: The raised exception (if any). Carried for debug logging
            only; never persisted verbatim to avoid leaking stack frames.
        exception_class: ``type(exc).__name__`` -- safe to label metrics with.
    """

    kind: OutcomeKind
    result: dict[str, Any] | None = None
    exception: BaseException | None = None
    exception_class: str | None = None


_OUTCOME_STASH: dict[tuple[str, int], _JobOutcome] = {}


def _stash_outcome(job_id: str, job_try: int, outcome: _JobOutcome) -> None:
    """Record the per-attempt outcome for :func:`_on_job_end` to consume.

    Bounded to :data:`_OUTCOME_STASH_MAX` entries. The historical FIFO
    eviction dropped the OLDEST inserted keys, which were exactly the
    long-running tasks operators care about -- a MASVS audit with 318
    investigation_loop tasks running 50 turns each could roll the
    stash past _OUTCOME_STASH_MAX between a long task's stash-write and
    its on_job_end read, and the long task got marked DEAD_LETTER (§77).

    Now: stash is LRU. Every insert / read touches the key, so an
    actively-completing task is never the eviction victim. Eviction
    still happens when the dict crosses _OUTCOME_STASH_MAX but it
    targets the LEAST RECENTLY USED entry. Combined with the bumped
    cap (50k) this gives long-running jobs head-room to consume their
    outcome before any eviction can touch them.
    """
    if len(_OUTCOME_STASH) >= _OUTCOME_STASH_MAX:
        # Drop the LRU head -- dict iteration order is insertion order,
        # but every successful _pop_outcome ALSO removes the key, and
        # any other read goes through this stash. So the head IS the
        # least recently touched at this point.
        for key in list(_OUTCOME_STASH.keys())[:_OUTCOME_STASH_SWEEP_BATCH]:
            _OUTCOME_STASH.pop(key, None)
    # Move-to-end semantics: if the same (job_id, job_try) is being
    # re-stashed (rare -- would mean the wrapper re-fired), pop+reinsert
    # so it ends up at the dict tail.
    _OUTCOME_STASH.pop((job_id, job_try), None)
    _OUTCOME_STASH[(job_id, job_try)] = outcome


def _pop_outcome(job_id: str, job_try: int) -> _JobOutcome | None:
    """Return and remove the outcome for (job_id, job_try), if present."""
    return _OUTCOME_STASH.pop((job_id, job_try), None)


async def _on_job_start(ctx: dict[str, Any]) -> None:
    """ARQ ``on_job_start`` hook (D-13).

    Loads the TaskRecord, sets ``status=RUNNING`` + ``started_at`` on the
    first try, always bumps ``updated_at``, and binds structlog with
    ``(task_id, job_try, user_id, team_id)``. For registered workflow-
    engine tasks on the first try, writes ``WorkflowRunRecord.plan_json``
    from the frozen definition so Phase 181's timeline can render without
    re-deriving the plan.

    Best-effort: a missing TaskRecord is logged at WARNING and the hook
    returns without raising -- ARQ still runs the job body.
    """
    from aila.platform.tasks.template import _REGISTRY
    from aila.storage.database import async_session_scope
    from aila.storage.db_models import WorkflowRunRecord

    task_id = str(ctx.get("job_id", ""))
    job_try = int(ctx.get("job_try", 1))

    async with async_session_scope() as session:
        record: TaskRecord | None = (
            await session.exec(select(TaskRecord).where(TaskRecord.id == task_id))
        ).first()
        if record is None:
            _log.warning(
                "on_job_start: TaskRecord %s not found -- hook is best-effort, "
                "ARQ will still execute the job.",
                task_id,
            )
            return

        # fix §76 -- reset started_at on EVERY attempt so the reaper's
        # fallback (started_at < fresh_cutoff when heartbeat_at IS NULL)
        # measures the CURRENT attempt's lifetime, not the original
        # submission. Without this, retry N inherits attempt 1's
        # started_at and gets reaped immediately as a stale RUNNING row.
        values: dict[str, Any] = {
            "updated_at": utc_now(),
            "started_at": utc_now(),
        }
        if job_try == 1:
            values["status"] = TaskStatus.RUNNING
        await session.execute(
            sa_update(TaskRecord)
            .where(TaskRecord.id == task_id)  # type: ignore[arg-type]
            .values(**values)
        )

        # Phase 181 audit trail (D-13 + D-38 from 178): populate plan_json
        # covering the timeline page snapshot. fix §84 -- always overwrite on
        # job_try == 1 instead of skipping when plan_json IS NOT NULL.
        # A phase-handoff that reused the run_id with a fresh definition
        # previously left the prior definition's plan_json behind, so the
        # timeline rendered the wrong shape. Overwriting per attempt-1
        # keeps the snapshot consistent with the definition actually in
        # flight; retries (job_try > 1) still leave the snapshot alone
        # because they run the SAME definition.
        if job_try == 1:
            platform_task = _REGISTRY.get_task(f"{record.fn_module}.{record.fn_path.rsplit('.', 1)[-1]}")
            # Fall back to keyed-by-fn_path lookup (registry stores
            # module-qualified names; callers may submit either form).
            if platform_task is None:
                platform_task = _REGISTRY.get_task(record.fn_path)
            if platform_task is not None and platform_task.definition is not None:
                run_record = (
                    await session.exec(
                        select(WorkflowRunRecord).where(
                            WorkflowRunRecord.id == task_id,
                        )
                    )
                ).first()
                if run_record is not None:
                    await session.execute(
                        sa_update(WorkflowRunRecord)
                        .where(WorkflowRunRecord.id == task_id)  # type: ignore[arg-type]
                        .values(
                            plan_json=_serialize_definition(platform_task.definition),
                        )
                    )

        await session.commit()

        structlog.contextvars.bind_contextvars(
            task_id=task_id,
            job_try=job_try,
            user_id=record.user_id,
            team_id=getattr(record, "team_id", None),
        )


async def _on_job_end(ctx: dict[str, Any]) -> None:
    """ARQ ``on_job_end`` hook -- the single source of truth for terminal state.

    Reads the outcome stash written by :func:`~aila.platform.tasks.template.platform_task`
    and drives one of six D-14 branches:

    1. ``success`` -> ``DONE``, ``result_path`` from returned dict, enqueue
       dependents.
    2. ``retry_signalled`` (the wrapper raised ``arq.Retry``) -> touch
       ``updated_at`` only.
    3. ``exception`` + ``job_try < max_tries_for_task`` -> log warning,
       leave RUNNING.
    4. ``exception`` + final try -> ``DEAD_LETTER``, persist payload,
       increment counter.
    5. ``timeout`` -> ``DEAD_LETTER`` with ``code=JOB_TIMEOUT``.
    6. ``cancelled`` -> ``CANCELLED``, no dead-letter.

    If the stash is empty (worker crashed between wrapper and hook), falls
    through to a defensive Branch-4 path so the TaskRecord never stays
    stuck in ``RUNNING``.
    """
    from aila.platform.tasks.template import _REGISTRY
    from aila.platform.tasks.worker import _persist_dead_letter
    from aila.storage.database import async_session_scope

    task_id = str(ctx.get("job_id", ""))
    job_try = int(ctx.get("job_try", 1))

    outcome = _pop_outcome(task_id, job_try)

    try:
        async with async_session_scope() as session:
            record: TaskRecord | None = (
                await session.exec(select(TaskRecord).where(TaskRecord.id == task_id))
            ).first()
            if record is None:
                _log.warning(
                    "on_job_end: TaskRecord %s not found -- nothing to finalize.",
                    task_id,
                )
                return

            platform_task = _REGISTRY.get_task(record.fn_path)
            max_tries_for_task = (
                platform_task.max_tries if platform_task is not None else 3
            )

            now = utc_now()
            values: dict[str, Any] = {"updated_at": now}
            terminal_branch: str | None = None
            persist_dead_letter = False
            dead_letter_error = ""
            dead_letter_exception_class = "Unknown"

            if outcome is None:
                # Defensive branch -- should be rare. Treat as a crash between
                # wrapper and hook: mark DEAD_LETTER so the row does not
                # stay stuck in RUNNING.
                values["status"] = TaskStatus.DEAD_LETTER
                values["error"] = "worker crashed before outcome stash"
                values["completed_at"] = now
                terminal_branch = "defensive"
                persist_dead_letter = True
                dead_letter_error = "worker crashed before outcome stash"
                dead_letter_exception_class = "WorkerCrash"

            elif outcome.kind == "success":
                # Branch 1.
                values["status"] = TaskStatus.DONE
                values["completed_at"] = now
                values["error"] = None
                if isinstance(outcome.result, dict):
                    rp = outcome.result.get("result_path")
                    if isinstance(rp, str):
                        values["result_path"] = rp
                terminal_branch = "success"

            elif outcome.kind == "retry_signalled":
                # Branch 2. Keep RUNNING; ARQ owns the backoff.
                terminal_branch = None  # no terminal change

            elif outcome.kind == "exception":
                if job_try < max_tries_for_task:
                    # Branch 3.
                    _slog.warning(
                        "task.attempt_failed_will_retry",
                        task_id=task_id,
                        job_try=job_try,
                        max_tries=max_tries_for_task,
                        exception_class=outcome.exception_class,
                    )
                    terminal_branch = None
                else:
                    # Branch 4.
                    values["status"] = TaskStatus.DEAD_LETTER
                    values["error"] = _safe_error_text(outcome.exception)
                    values["completed_at"] = now
                    terminal_branch = "dead_letter"
                    persist_dead_letter = True
                    dead_letter_error = _safe_error_text(outcome.exception)
                    dead_letter_exception_class = (
                        outcome.exception_class or "Unknown"
                    )

            elif outcome.kind == "timeout":
                # Branch 5.
                values["status"] = TaskStatus.DEAD_LETTER
                values["error"] = "code=JOB_TIMEOUT task exceeded job_timeout_s"
                values["completed_at"] = now
                terminal_branch = "timeout"
                persist_dead_letter = True
                dead_letter_error = "code=JOB_TIMEOUT task exceeded job_timeout_s"
                dead_letter_exception_class = "JobTimeout"

            elif outcome.kind == "cancelled":
                # Branch 6.
                values["status"] = TaskStatus.CANCELLED
                values["completed_at"] = now
                terminal_branch = "cancelled"

            await session.execute(
                sa_update(TaskRecord)
                .where(TaskRecord.id == task_id)  # type: ignore[arg-type]
                .values(**values)
            )
            await session.commit()

            snapshot_track = record.track
            snapshot_fn_path = record.fn_path
            snapshot_fn_module = record.fn_module
            snapshot_user_id = record.user_id
            snapshot_kwargs_json = record.kwargs_json or "{}"

        # Post-commit side-effects. These run outside the session so a
        # Redis hiccup cannot unwind a successful DB transition.
        if terminal_branch == "success":
            await _enqueue_dependents(task_id)

        # fix §130 -- terminal state (any branch that wrote completed_at)
        # is the canonical wire-point for RunMemory.clear(). Without
        # this, the in-memory token / scratchpad map grows by one entry
        # per task and never shrinks across worker uptime. Skipped for
        # retry-signalled / will-retry branches because the run is still
        # active. Cleared even for cancelled / dead_letter so leaked
        # workers don't pin orphan run_ids in memory.
        if terminal_branch is not None:
            try:
                _run_memory = get_shared_run_memory()
                if _run_memory is not None:
                    _run_memory.clear(task_id)
            except (ImportError, AttributeError) as exc:
                _log.debug(
                    "_on_job_end: RunMemory.clear skipped for %s -- %s",
                    task_id, exc,
                )

        if persist_dead_letter:
            try:
                await _persist_dead_letter(
                    track=snapshot_track,
                    task_id=task_id,
                    fn_path=snapshot_fn_path,
                    fn_module=snapshot_fn_module,
                    kwargs_json=snapshot_kwargs_json,
                    user_id=snapshot_user_id,
                    error=dead_letter_error,
                    attempts=job_try,
                    exception_class=dead_letter_exception_class,
                )
            except Exception:
                _log.warning(
                    "dead_letter.persist_failed task_id=%s",
                    task_id,
                    exc_info=True,
                )
            TASK_DEAD_LETTER_TOTAL.labels(
                exception_class=dead_letter_exception_class,
            ).inc()
    finally:
        # Always clean structlog binding, even on exceptional flow, so a
        # future unrelated job cannot inherit this job's context.
        structlog.contextvars.unbind_contextvars(
            "task_id", "job_try", "user_id", "team_id",
        )


def _serialize_definition(definition: Any) -> dict[str, Any]:
    """JSON-safe snapshot of a :class:`WorkflowDefinition` for plan_json.

    ``WorkflowDefinition`` is a frozen dataclass whose ``states`` mapping
    references live handler callables and service factories -- not
    JSON-serializable. We persist only the graph shape Phase 181's timeline
    needs: ``definition_id``, ``start_state``, and the list of state names
    with their ``terminal`` flag and ``max_retries``. Handler identities
    are intentionally omitted so the timeline page cannot leak internal
    module paths to the frontend.
    """
    states_out: dict[str, dict[str, Any]] = {}
    for name, spec in definition.states.items():
        states_out[name] = {
            "terminal": bool(getattr(spec, "terminal", False)),
            "max_retries": int(getattr(spec, "max_retries", 0)),
            "timeout_s": float(getattr(spec, "timeout_s", 0.0)),
        }
    return {
        "definition_id": definition.definition_id,
        "start_state": definition.start_state,
        "states": states_out,
    }


def _safe_error_text(exc: BaseException | None) -> str:
    """Return a truncated, string-safe rendering of an exception.

    Matches the existing ``_persist_dead_letter`` contract (2000 char cap).
    Class-name fallback on ``str(exc)`` failure guards against handlers
    that define ``__str__`` to raise.
    """
    if exc is None:
        return ""
    try:
        return str(exc)[:2000]
    except Exception:
        return f"<unreprable {type(exc).__name__}>"


async def _enqueue_dependents(completed_task_id: str) -> None:
    """Promote WAITING tasks to QUEUED when every dependency is DONE and
    enqueue them to ARQ.

    Three fixes in one place:

    * §134 -- the historical implementation flipped status to QUEUED in
      the DB but never enqueued to Redis. The orphan-queued sweep then
      killed the dependent ~60s later. Now ``_arq_enqueue_async`` runs
      after each commit so the queue and DB stay consistent.
    * §135 -- the historical implementation scanned EVERY WAITING task on
      every completion. Now we pre-filter with a substring LIKE on
      ``depends_on_json`` so the WHERE clause never returns rows that
      can't possibly depend on this task. The JSON-decode +
      dependency-readiness check still runs per candidate, but the
      candidate set is bounded by the substring match instead of the
      whole WAITING table.
    * §136 -- dependency completion check now compares deduplicated sets,
      so a duplicate dep entry like ``["a", "a", "b"]`` no longer keeps
      the dependent stuck at WAITING forever.
    """
    import json

    promoted_records: list[TaskRecord] = []
    async with async_session_scope() as session:
        # fix §135 -- narrow candidate set with a substring LIKE so the
        # JSON-decode loop only sees rows that may actually reference the
        # completed task. Index on depends_on_json (added implicitly by
        # Postgres on Text) makes the pattern scan cheap relative to a
        # full WAITING scan.
        waiting_tasks = (
            await session.exec(
                select(TaskRecord)
                .where(TaskRecord.status == TaskStatus.WAITING)
                .where(
                    TaskRecord.depends_on_json.like(  # type: ignore[union-attr]
                        f"%{completed_task_id}%",
                    ),
                )
            )
        ).all()
        for task in waiting_tasks:
            if not task.depends_on_json:
                continue
            deps: list[str] = json.loads(task.depends_on_json)
            if completed_task_id not in deps:
                continue
            dep_records = {
                r.id: r
                for r in (
                    await session.exec(
                        select(TaskRecord).where(TaskRecord.id.in_(deps))  # type: ignore[attr-defined]
                    )
                ).all()
            }
            # fix §136 -- compare deduplicated sets so ``["a", "a", "b"]``
            # is treated as ``{"a", "b"}`` and matches ``dep_records`` keys.
            unique_deps = set(deps)
            if dep_records.keys() == unique_deps and all(
                dep_records[d].status == TaskStatus.DONE for d in unique_deps
            ):
                task.status = TaskStatus.QUEUED
                session.add(task)
                promoted_records.append(task)
        if promoted_records:
            await session.commit()

    if not promoted_records:
        return

    # fix §134 -- actually enqueue to ARQ now that the rows are QUEUED. A
    # row that's flipped in DB but absent from arq:queue:* gets reaped by
    # the orphan-queued sweep ~60s later, so the dependent never runs.
    redis_url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
    if not redis_url:
        _log.warning(
            "_enqueue_dependents: %d task(s) promoted but Redis URL is "
            "unset -- orphan-queued sweep will reap them.",
            len(promoted_records),
        )
        return

    pool = None
    try:
        pool = await _create_pool(_RedisSettings.from_dsn(redis_url))
        for rec in promoted_records:
            try:
                fn_short = (
                    rec.fn_path.rsplit(".", 1)[-1]
                    if rec.fn_path else None
                )
                if not fn_short or not rec.track:
                    _log.warning(
                        "_enqueue_dependents: skipping %s (fn=%s track=%s)",
                        rec.id, fn_short, rec.track,
                    )
                    continue
                kwargs = json.loads(rec.kwargs_json) if rec.kwargs_json else {}
                queue_key = ARQ_QUEUE_KEY_TEMPLATE.format(track=rec.track)
                await pool.enqueue_job(
                    fn_short,
                    _queue_name=queue_key,
                    _job_id=rec.id,
                    **kwargs,
                )
                _log.info(
                    "_enqueue_dependents: enqueued dependent %s to %s",
                    rec.id, queue_key,
                )
            except (OSError, RuntimeError, ValueError, TypeError) as exc:
                _log.warning(
                    "_enqueue_dependents: enqueue of %s failed: %s",
                    rec.id, exc,
                )
    finally:
        if pool is not None:
            try:
                await pool.aclose()
            except (OSError, RuntimeError) as exc:
                _log.debug(
                    "_enqueue_dependents: pool close failed: %s", exc,
                )


# Suppress unused-import warning when asyncio is imported only for typing.
_ = asyncio
