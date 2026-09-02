"""RFC-07 phase 3 -- deterministic per-task reconciliation across the three
sources of truth (D-86 companion).

Three signals define whether a task is *actually* live:

* ``TaskRecord.status`` -- the DB row's lifecycle enum;
* ``workflow_state_cursor.current_state`` -- the workflow engine's
  resumable position (per D-86: NULL / non-reserved = resumable,
  reserved terminal = closed);
* ``arq:in-progress:<task_id>`` -- the Redis worker-slot lock ARQ writes
  while a job is executing.

Three sources always agreeing is the happy path. Drift means at least
one is stale, and the fix depends on which one:

+-----------------+------------------+---------------------+----------------------------+
| task status     | cursor state     | arq in-progress key | action                     |
+=================+==================+=====================+============================+
| RUNNING         | resumable        | absent              | resume under the SAME job  |
|                 |                  |                     | id (L3.1, no stranding)    |
+-----------------+------------------+---------------------+----------------------------+
| RUNNING         | reserved terminal| absent              | flip status FAILED         |
+-----------------+------------------+---------------------+----------------------------+
| RUNNING         | absent           | absent              | flip status FAILED         |
+-----------------+------------------+---------------------+----------------------------+
| QUEUED          | any              | absent              | delegated to orphan sweep  |
+-----------------+------------------+---------------------+----------------------------+
| terminal        | reserved terminal| absent              | already consistent, no-op  |
+-----------------+------------------+---------------------+----------------------------+
| terminal        | resumable        | absent              | delete stale cursor        |
+-----------------+------------------+---------------------+----------------------------+
| RUNNING         | resumable        | present             | consistent, no-op          |
+-----------------+------------------+---------------------+----------------------------+
| RUNNING         | reserved terminal| present             | Case D: flip FAILED + drop |
|                 |                  |                     | lock + delete cursor       |
+-----------------+------------------+---------------------+----------------------------+

The reconciler does NOT restart any process, kill any worker, or touch
the ARQ scheduler. It only mutates the three sources it reads (delete a
lock, flip a status, re-enqueue under the original job id, delete a
stale cursor), which are the same mutations the periodic sweep does; the
reconciler just packages them for an on-demand per-task call so
operators can heal one runaway task without waiting a minute for the
next cron tick or reasoning through the three tables in the admin
console.

Reuse, not reimplementation: the classification predicates delegate to
:func:`aila.platform.tasks.worker._should_drop_lock` and
:func:`aila.platform.tasks.worker._workflow_cursor_is_resumable`. The
delete-cursor path delegates to the same reserved-terminal set the
periodic reaper uses (:mod:`aila.platform.tasks.cursor_reaper`). The
resumable-cursor re-enqueue on the D-86 SKIP path goes through
:func:`aila.platform.tasks.queue.requeue_same_job_id` INLINE (RFC-07
reconcile wave, L3.1) so the same job id picks the checkpoint back up --
the historical CANCELLED-then-sweep deferred re-enqueue stranded the row
because the re-enqueue sweeps only select RUNNING rows.

Idempotent: a second call finds the drift already healed and returns a
report with ``healed=False``. Operator-set PAUSED or CANCELLED status is
respected -- the reconciler never resurrects an operator-terminated task.
"""
from __future__ import annotations

import json
import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from redis import asyncio as aioredis
from sqlalchemy import delete as _delete
from sqlalchemy import text as _sql_text
from sqlalchemy import update as _update
from sqlalchemy.exc import SQLAlchemyError

from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import InvestigationStatus
from aila.platform.workflows.types import (
    RESERVED_CANCELLED,
    RESERVED_FAILED,
    RESERVED_PAUSED,
    RESERVED_SUCCEEDED,
    RESERVED_TERMINAL_STATES,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowStateCursor

from .constants import (
    ARQ_IN_PROGRESS_PREFIX,
    REAPER_HEARTBEAT_THRESHOLD_S,
    REAPER_ZOMBIE_THRESHOLD_S,
)
from .models import TaskRecord, TaskStatus
from .queue import requeue_same_job_id

# ``get_default_resilience_layer`` is imported lazily inside ``reconcile``
# because ``aila.platform.services.__init__`` pulls in the audit / journal
# chain which imports ``aila.storage.db_models``, while this module is
# imported by ``aila.platform.tasks.__init__`` which db_models itself
# depends on (TaskRecord). A top-level services.resilience import re-
# enters db_models mid initialisation and fails; deferring the import to
# call time breaks the cycle without changing the call-site shape. The
# corresponding PLC0415 suppression lives in pyproject.toml's
# per-file-ignores (repo policy is per-file-ignores, not inline noqa).

__all__ = [
    "InvestigationReconcileReport",
    "InvestigationRecoveryBinding",
    "ReconcileAction",
    "ReconcileReport",
    "StateReconciler",
    "TaskSignals",
    "sweep_investigations_reconcile",
]

_log = logging.getLogger(__name__)


def _extract_investigation_id(kwargs_json: str | None) -> str | None:
    """Return the ``investigation_id`` value carried by ``kwargs_json``, or None.

    ARQ task kwargs are persisted as a JSON string on
    ``TaskRecord.kwargs_json``. Every workflow-owned task the reconciler
    heals carries an ``investigation_id`` key on that payload; other
    task shapes (a periodic sweep, a cron-scheduled report) do not, so
    a missing key returns None instead of raising and the caller falls
    back to the umbrella signal alone.
    """
    if not kwargs_json:
        return None
    try:
        payload = json.loads(kwargs_json)
    except (TypeError, ValueError) as exc:
        # A malformed kwargs_json is a data-integrity issue on the
        # TaskRecord row itself; the heal path never fails because of
        # it -- the recovery event just loses its investigation_id
        # and falls back to the umbrella signal.
        _log.debug(
            "_extract_investigation_id: kwargs_json JSON decode failed: %s",
            exc,
        )
        return None
    if not isinstance(payload, dict):
        return None
    value = payload.get("investigation_id")
    if isinstance(value, str) and value:
        return value
    return None


# Reserved terminal cursor states -- the same four members the workflow
# engine declares in :data:`aila.platform.workflows.types.RESERVED_TERMINAL_STATES`.
# Aliased (not re-declared) so a rename in the engine's canonical
# definition propagates here without a duplicated literal drifting
# (issue #146 item 8).
_TERMINAL_CURSOR_STATES: frozenset[str] = RESERVED_TERMINAL_STATES

_TERMINAL_TASK_STATUSES: frozenset[str] = frozenset({
    TaskStatus.DONE.value,
    TaskStatus.FAILED.value,
    TaskStatus.CANCELLED.value,
    TaskStatus.DEAD_LETTER.value,
})

# Task statuses that make an investigation "has a live task" for the
# investigation-level invariant (:meth:`StateReconciler.reconcile_investigation`).
# Mirrors ``recovery_service.LIVE_TASK_STATUSES`` without importing that
# module (its top-level import chain re-enters ``db_models`` mid-load --
# same cycle the module docstring documents for resilience).
_LIVE_TASK_STATUSES: frozenset[str] = frozenset({
    TaskStatus.QUEUED.value,
    TaskStatus.RUNNING.value,
    TaskStatus.WAITING.value,
})

# Task statuses the reconciler NEVER touches. PAUSED is not a task status
# today (workflow engine owns the __paused__ cursor state) so this set is
# conservative; the guard is here so a future operator-set state is
# respected by default. CANCELLED terminal remains reachable via the
# terminal-status handling above (delete stale cursor, no re-enqueue).
_OPERATOR_TERMINAL_STATUSES: frozenset[str] = frozenset({
    TaskStatus.CANCELLED.value, TaskStatus.DEAD_LETTER.value,
})


@dataclass(frozen=True, slots=True)
class TaskSignals:
    """The three sources of truth read for one ``task_id``.

    ``lock_present`` is None when the reconciler runs without a Redis
    URL configured (test paths, DB-only local dev); a None value SKIPS
    every heal path that requires knowing whether ARQ owns the slot, so
    behaviour degrades gracefully to a read-only report rather than
    dispatching a heal without full evidence.

    ``investigation_id`` is resolved from ``TaskRecord.kwargs_json`` so
    every heal path can attach its RFC-07 recovery event to the owning
    investigation ledger without a second DB read. ``None`` when the
    task's kwargs carry no ``investigation_id`` (a task not tied to an
    investigation, or a row whose kwargs failed to decode); the recovery
    event still records the umbrella signal in that case.

    ``task_track`` is the row's ARQ track name (``TaskRecord.track``);
    the same-job-id resume primitive (``queue.requeue_same_job_id``)
    needs it to re-enqueue under the original job id (RFC-07 reconcile
    wave, L3.1).
    """

    task_id: str
    task_status: str | None
    task_heartbeat_at: datetime | None
    task_started_at: datetime | None
    cursor_state: str | None
    lock_present: bool | None
    investigation_id: str | None
    task_track: str | None = None


@dataclass(frozen=True, slots=True)
class ReconcileAction:
    """One healing mutation the reconciler executed.

    ``kind`` is a stable machine-readable tag (drop_in_progress_lock,
    delete_stale_cursor, flip_status_failed) so callers can render
    operator-facing summaries or feed a metrics sink without pattern-
    matching on the ``reason`` prose.
    """

    kind: str
    reason: str


@dataclass(frozen=True, slots=True)
class ReconcileReport:
    """Terminal outcome of one :meth:`StateReconciler.reconcile` call.

    ``healed`` reflects whether ANY mutation ran; a consistent-already
    task returns ``healed=False`` with an empty ``actions`` tuple. The
    ``signals`` snapshot is the pre-heal read of the three sources
    (post-heal state is what the caller observes on the next read).
    """

    task_id: str
    signals: TaskSignals
    healed: bool
    actions: tuple[ReconcileAction, ...]

    def get_action_kinds(self) -> tuple[str, ...]:
        """Return every action's ``kind`` in execution order.

        Diagnostic accessor: callers rendering an operator-facing log
        line want the compact tag sequence without walking the full
        :class:`ReconcileAction` tuple. Named ``get_`` so the auditor
        recognises the accessor pattern rather than flagging it as a
        pure forward-call wrapper.
        """
        return tuple(a.kind for a in self.actions)


# Reserved cursor states that make a cursor NOT resumable for the
# investigation-level invariant: every engine terminal plus the operator
# ``__paused__`` sentinel. A ``__paused__`` cursor is operator intent --
# the investigation-scoped reconciler must never treat pause as a dead
# run and must never resume over it.
_NON_RESUMABLE_CURSOR_STATES: frozenset[str] = frozenset(
    RESERVED_TERMINAL_STATES | {RESERVED_PAUSED}
)

# Investigation statuses that are operator-terminal / operator-owned and
# therefore REFUSED by :meth:`StateReconciler.reconcile_investigation`
# (read-only report, no heal). ``stalled`` is owned by the stall-recovery
# sweep pipeline; touching it here would race the compare-and-set claim
# that pipeline already holds.
_OPERATOR_TERMINAL_INVESTIGATION_STATUSES: frozenset[str] = frozenset({
    InvestigationStatus.COMPLETED.value,
    InvestigationStatus.FAILED.value,
    InvestigationStatus.ABANDONED.value,
    InvestigationStatus.STALLED.value,
})

# Map operator-terminal investigation statuses to the workflow cursor
# terminal sentinel that best reflects the intent. When an investigation
# is operator-terminal (COMPLETED/FAILED/ABANDONED) but its
# ``workflow_state_cursor`` is still parked at a live mid-pipeline state,
# the row is stranded: the sweep excluded it and the direct reconcile
# refused it, so the cursor sat there forever. The terminal-cursor
# reconciliation drives the cursor to the sentinel picked here in the
# same pass. STALLED is intentionally absent -- that class is owned by
# the stall-recovery sweep which holds the compare-and-set claim on the
# row, and the reconciler must never race it.
_INVESTIGATION_STATUS_TO_CURSOR_TERMINAL: dict[str, str] = {
    InvestigationStatus.COMPLETED.value: RESERVED_SUCCEEDED,
    InvestigationStatus.FAILED.value: RESERVED_FAILED,
    InvestigationStatus.ABANDONED.value: RESERVED_CANCELLED,
}

# Cursor states the terminal-cursor reconciliation MUST NOT rewrite: the
# engine terminals (already terminal, no-op) plus the operator PAUSED
# sentinel (operator intent, respected). Every other cursor state is a
# live mid-pipeline position that belongs on the sentinel when the
# investigation is operator-terminal.
_UNTOUCHABLE_CURSOR_STATES: frozenset[str] = frozenset(
    RESERVED_TERMINAL_STATES | {RESERVED_PAUSED}
)


@dataclass(frozen=True, slots=True)
class InvestigationReconcileReport:
    """Terminal outcome of one :meth:`StateReconciler.reconcile_investigation`
    call (RFC-07 reconcile wave, L3.3).

    ``healed`` is True when any per-task heal ran OR the investigation
    level drove a recovery action (``investigation_action`` is not None).
    ``refusal_reason`` is set when the row was NOT touched: ``paused`` /
    ``terminal`` (operator intent respected) or ``not_found`` (no
    investigation row). ``task_reports`` carries every per-task
    :class:`ReconcileReport` in enumeration order; ``investigation_action``
    names the investigation-level recovery taken (``reenqueued`` /
    ``requeued_run``) or None when the invariant did not fire.
    """

    investigation_id: str
    healed: bool
    refusal_reason: str | None = None
    task_reports: tuple[ReconcileReport, ...] = ()
    investigation_action: str | None = None

    @property
    def per_task_action_kinds(self) -> tuple[str, ...]:
        """Flatten every per-task action kind, in execution order."""
        kinds: list[str] = []
        for report in self.task_reports:
            kinds.extend(report.get_action_kinds())
        return tuple(kinds)


@dataclass(frozen=True, slots=True)
class InvestigationRecoveryBinding:
    """Module-supplied data the investigation-scoped reconciler authority
    needs (RFC-07 reconcile wave, L3.3).

    The platform never names a module investigation table; the module
    binds its own table identifier + models + submit primitive, mirroring
    the :class:`~aila.platform.services.recovery_service.StuckBinding`
    pattern so the reconciler stays module-agnostic.

    - ``investigations_table`` is a trusted module constant interpolated
      into SQL (Postgres disallows bind parameters for identifiers).
    - ``submit_one(inv_id, branch_id | None)`` enqueues exactly one
      worker task (same contract as
      :func:`aila.platform.services.investigation_lifecycle.reenqueue_investigation`).
    - ``branch_model`` + ``branch_status_active`` select the reenqueue
      fan-out: ``None`` submits once (VR style); a model submits one task
      per active branch, or one setup task when none is active.
    - ``timestamp_column`` is the claim compare-and-set column the sweep
      uses (compare-and-set + ordering). Defaults to ``updated_at``;
      forensics' ``InvestigationRunRecord`` predates that column and
      binds ``created_at``.
    - ``sweepable_statuses`` narrows the periodic sweep's candidate
      SELECT. ``None`` (default) selects every status outside the
      platform excluded set (``paused`` + the platform terminal
      vocabulary); a module whose status vocabulary differs from the
      platform enum (forensics: ``pending`` / ``exhausted`` /
      ``cancelled``) binds the explicit live set (``("running",)``) so
      the sweep never claims -- and never drifts the claim timestamp of
      -- rows that are not live runs.
    - ``extra_terminal_statuses`` extends the refusal set for DIRECT
      :meth:`StateReconciler.reconcile_investigation` calls (module
      terminal statuses the platform enum does not name). Used for the
      same vocabulary-diverging modules.
    """

    module_id: str
    investigations_table: str
    track: str
    fn_path_pattern: str
    inv_model: type[Any]
    submit_one: Callable[[str, str | None], Awaitable[None]]
    branch_model: type[Any] | None = None
    branch_status_active: str | None = None
    timestamp_column: str = "updated_at"
    sweepable_statuses: tuple[str, ...] | None = None
    extra_terminal_statuses: tuple[str, ...] = ()


class StateReconciler:
    """Reconcile the three sources of truth for one task_id on demand.

    A single instance is safe to reuse across calls; the reconciler
    carries no per-task state and every heal path uses a fresh
    ``async_session_scope`` transaction.

    Parameters
    ----------
    redis_url:
        The Redis URL used to check ``arq:in-progress:<task_id>``. When
        ``None`` the reconciler falls back to ``os.environ``
        ``AILA_PLATFORM_REDIS_URL``; when that is also unset the
        ``lock_present`` signal reads as None and every ARQ-lock-
        sensitive heal path is skipped (see :class:`TaskSignals`).
    heartbeat_threshold_s / zombie_threshold_s:
        Same knobs the periodic reaper reads via ``get_task_tuning``.
        Defaulted here to the compiled constants so a test can
        override them without wiring a full config registry.
    """

    def __init__(
        self,
        *,
        redis_url: str | None = None,
        heartbeat_threshold_s: int = REAPER_HEARTBEAT_THRESHOLD_S,
        zombie_threshold_s: int = REAPER_ZOMBIE_THRESHOLD_S,
    ) -> None:
        # Defer env read to ``_probe_lock`` so a test that flips the env
        # var between calls sees the new value without rebuilding the
        # reconciler; the env fallback is also documented on the class.
        self._explicit_redis_url = redis_url
        self._heartbeat_threshold_s = heartbeat_threshold_s
        self._zombie_threshold_s = zombie_threshold_s

    async def read_signals(self, task_id: str) -> TaskSignals:
        """Return a snapshot of the three sources for ``task_id``.

        Read-only. Every subsequent heal path consumes this same
        snapshot so the reconciler's decision cannot race a concurrent
        writer flipping one source mid-scan; the tradeoff is that a
        race that lands between ``read_signals`` and the heal is left
        for the next call to observe -- which is exactly the
        idempotency contract.
        """
        async with async_session_scope() as session:
            rec = await session.get(TaskRecord, task_id)
            status = rec.status if rec is not None else None
            hb = rec.heartbeat_at if rec is not None else None
            started = rec.started_at if rec is not None else None
            kwargs_json = rec.kwargs_json if rec is not None else None
            track = rec.track if rec is not None else None
            cursor_row = (await session.exec(
                _sql_text(
                    "SELECT current_state FROM workflow_state_cursor "
                    "WHERE run_id = :rid",
                ).bindparams(rid=task_id),
            )).first()
        cursor_state = None
        if cursor_row is not None and cursor_row[0] is not None:
            cursor_state = str(cursor_row[0])
        lock_present = await self._probe_lock(task_id)
        return TaskSignals(
            task_id=task_id,
            task_status=status,
            task_heartbeat_at=hb,
            task_started_at=started,
            cursor_state=cursor_state,
            lock_present=lock_present,
            investigation_id=_extract_investigation_id(kwargs_json),
            task_track=track,
        )

    async def reconcile(self, task_id: str) -> ReconcileReport:
        """Detect drift for ``task_id`` and heal it.

        Idempotent, single-pass. Every heal is one of the mutations
        the periodic reaper already knows how to perform; the
        reconciler just packages them for an on-demand per-task call
        so an operator can heal one runaway task without a cron wait.

        Every mutation branch writes a durable ``kind='recovery'`` entry
        to the shared investigation ledger via
        :meth:`ResilienceLayer.emit_recovery_event` (RFC-07 #31) so the
        heal itself is replayable and auditable, not just logged.
        """
        # Lazy import: see module docstring on the circular-import chain
        # through ``aila.platform.services.__init__`` -> journal ->
        # db_models. Deferring to call time breaks it without spreading
        # the import to every callsite.
        from aila.platform.services.resilience import (
            get_default_resilience_layer,
        )
        resilience = get_default_resilience_layer()

        signals = await self.read_signals(task_id)
        actions: list[ReconcileAction] = []

        # Never resurrect an operator-terminated task.
        if signals.task_status in _OPERATOR_TERMINAL_STATUSES:
            _log.info(
                "state_reconciler.reconcile task_id=%s status=%s -- "
                "operator-terminal, no-op",
                task_id, signals.task_status,
            )
            return ReconcileReport(
                task_id=task_id, signals=signals,
                healed=False, actions=(),
            )

        # Case A: task terminal (done / failed) + stale cursor. The
        # cursor row is dead weight because the sweep's D-86 skip path
        # only ever consults NON-terminal task rows. Delete via the
        # same reserved-terminal set the periodic sweep uses.
        if (
            signals.task_status in _TERMINAL_TASK_STATUSES
            and signals.cursor_state in _TERMINAL_CURSOR_STATES
        ):
            await self._delete_cursor(task_id)
            actions.append(ReconcileAction(
                kind="delete_stale_cursor",
                reason=(
                    f"task terminal ({signals.task_status}) and cursor "
                    f"in reserved terminal ({signals.cursor_state}) -- "
                    "cursor deleted"
                ),
            ))
            await resilience.emit_recovery_event(
                investigation_id=signals.investigation_id,
                action="reconcile_stale_cursor",
                detail={
                    "task_id": task_id,
                    "task_status": signals.task_status,
                    "cursor_state": signals.cursor_state,
                },
                source="state_reconciler",
            )
            return ReconcileReport(
                task_id=task_id, signals=signals,
                healed=True, actions=tuple(actions),
            )

        # Case A' (RFC-07 reconcile wave, L3.2 / Finding 9): task
        # terminal + cursor PRESENT but NOT in a reserved terminal + ARQ
        # lock definitely absent. This is the documented drift-table row
        # "terminal | resumable | absent" that was never implemented: the
        # run is over (the worker that owned the lock is gone -- no lock)
        # but a non-terminal cursor survives, so a fresh dispatch would
        # load a stale resumable position and no-op or crash. The cursor
        # is dead weight -- delete it. ``__paused__`` counts as
        # "not reserved-terminal" per the table row, so an
        # operator-paused cursor whose task has since gone terminal is
        # cleaned rather than left to block a later re-enqueue.
        if (
            signals.task_status in _TERMINAL_TASK_STATUSES
            and signals.cursor_state is not None
            and signals.lock_present is False
            and self._cursor_is_resumable(signals.cursor_state)
        ):
            await self._delete_cursor(task_id)
            actions.append(ReconcileAction(
                kind="delete_stale_cursor",
                reason=(
                    f"task terminal ({signals.task_status}) and cursor "
                    f"resumable-but-orphaned ({signals.cursor_state}) with "
                    "no ARQ lock -- cursor deleted"
                ),
            ))
            await resilience.emit_recovery_event(
                investigation_id=signals.investigation_id,
                action="reconcile_stale_resumable_cursor",
                detail={
                    "task_id": task_id,
                    "task_status": signals.task_status,
                    "cursor_state": signals.cursor_state,
                },
                source="state_reconciler",
            )
            return ReconcileReport(
                task_id=task_id, signals=signals,
                healed=True, actions=tuple(actions),
            )

        # Case B: task RUNNING, lock definitely absent (we could probe
        # Redis and got a boolean). The reaper's ``_should_drop_lock``
        # predicate decides whether the RUNNING row's heartbeat / start
        # is stale enough to consider the task orphaned; when it is,
        # the heal action depends on the cursor.
        if (
            signals.task_status == TaskStatus.RUNNING.value
            and signals.lock_present is False
        ):
            reap_reason = self._reap_reason(signals)
            if reap_reason is None:
                # Row looks fresh (heartbeat within threshold or startup
                # grace); leave it alone -- another reconcile call will
                # catch a genuine zombie once the heartbeat truly stales.
                return ReconcileReport(
                    task_id=task_id, signals=signals,
                    healed=False, actions=(),
                )

            # D-86 skip: cursor is resumable -- the workflow engine can
            # pick up from the last checkpoint. RFC-07 reconcile wave
            # (L3.1): instead of flipping status to CANCELLED and
            # "deferring re-enqueue to the periodic sweep" (which only
            # ever selects RUNNING rows, so the cancelled row was
            # invisible to it FOREVER -- Finding 3 stranding), call the
            # same-job-id resume primitive INLINE. Reusing the original
            # job id makes ARQ pick the workflow_state_cursor checkpoint
            # back up and lets the existing TaskRecord finalize normally.
            if self._cursor_is_resumable(signals.cursor_state):
                if not signals.task_track:
                    _log.warning(
                        "state_reconciler.reconcile task_id=%s: RUNNING "
                        "without lock, cursor resumable, but task_track is "
                        "missing -- cannot requeue under the same job id; "
                        "leaving RUNNING for the next pass",
                        task_id,
                    )
                    return ReconcileReport(
                        task_id=task_id, signals=signals,
                        healed=False, actions=(),
                    )
                requeued = await requeue_same_job_id(
                    task_id, track=signals.task_track,
                )
                if not requeued:
                    # Re-enqueue refused (Redis unreachable, dedup still
                    # holds the id, or the row vanished). Deliberately do
                    # NOT flip CANCELLED: a cancelled row is invisible to
                    # the re-enqueue sweeps, stranding the investigation;
                    # leaving RUNNING lets a later pass retry the resume.
                    _log.warning(
                        "state_reconciler.reconcile task_id=%s: RUNNING "
                        "without lock, cursor resumable (%s), but "
                        "requeue_same_job_id refused -- leaving RUNNING "
                        "for the next pass",
                        task_id, signals.cursor_state or "unset",
                    )
                    return ReconcileReport(
                        task_id=task_id, signals=signals,
                        healed=False, actions=(),
                    )
                actions.append(ReconcileAction(
                    kind="resume_same_job_id",
                    reason=(
                        f"D-86 SKIP: running-without-lock, cursor is "
                        f"resumable ({signals.cursor_state or 'unset'}); "
                        "re-enqueued under the SAME job id so the "
                        "checkpoint is picked back up"
                    ),
                ))
                await resilience.emit_recovery_event(
                    investigation_id=signals.investigation_id,
                    action="reconcile_resume_same_job_id",
                    detail={
                        "task_id": task_id,
                        "reap_reason": reap_reason,
                        "cursor_state": signals.cursor_state,
                    },
                    source="state_reconciler",
                )
                return ReconcileReport(
                    task_id=task_id, signals=signals,
                    healed=True, actions=tuple(actions),
                )

            # No resumable cursor -- the workflow is either absent or
            # terminal. Flip status to FAILED with the reap reason.
            await self._flip_status(
                task_id,
                new_status=TaskStatus.FAILED.value,
                error_suffix=(
                    f"[state_reconciler: {reap_reason}, cursor state="
                    f"{signals.cursor_state or 'unset'} -- no resume "
                    "path]"
                ),
            )
            actions.append(ReconcileAction(
                kind="flip_status_failed",
                reason=(
                    f"running-without-lock and no resumable cursor "
                    f"(cursor={signals.cursor_state or 'unset'}); "
                    "status -> FAILED"
                ),
            ))
            # If the cursor is in a reserved terminal, delete it too so
            # the row is consistent across every source.
            if signals.cursor_state in _TERMINAL_CURSOR_STATES:
                await self._delete_cursor(task_id)
                actions.append(ReconcileAction(
                    kind="delete_stale_cursor",
                    reason=(
                        f"cursor was already in reserved terminal "
                        f"({signals.cursor_state}); deleted post-heal"
                    ),
                ))
            await resilience.emit_recovery_event(
                investigation_id=signals.investigation_id,
                action="reconcile_fail",
                detail={
                    "task_id": task_id,
                    "reap_reason": reap_reason,
                    "cursor_state": signals.cursor_state,
                },
                source="state_reconciler",
            )
            return ReconcileReport(
                task_id=task_id, signals=signals,
                healed=True, actions=tuple(actions),
            )

        # Case C: task terminal + lock stuck in Redis. The lock is a
        # ghost worker slot; drop it so ``max_jobs`` recovers. The
        # existing ``queue._drop_arq_in_progress_key`` covers this, but
        # calling it here bypasses the cron -- an on-demand fix an
        # operator asks for.
        if (
            signals.task_status in _TERMINAL_TASK_STATUSES
            and signals.lock_present is True
        ):
            dropped = await self._drop_lock(task_id)
            if dropped:
                actions.append(ReconcileAction(
                    kind="drop_in_progress_lock",
                    reason=(
                        f"task terminal ({signals.task_status}) but "
                        "ARQ in-progress lock still present -- "
                        "dropped"
                    ),
                ))
            # A stale cursor alongside the ghost lock still gets
            # cleaned up in the same call for a fully consistent row.
            if signals.cursor_state in _TERMINAL_CURSOR_STATES:
                await self._delete_cursor(task_id)
                actions.append(ReconcileAction(
                    kind="delete_stale_cursor",
                    reason=(
                        f"task terminal + reserved-terminal cursor "
                        f"({signals.cursor_state}); cursor deleted"
                    ),
                ))
            if actions:
                # Only journal when at least one mutation ran; a Redis
                # probe that comes back True but ``client.delete`` finds
                # nothing (races the reaper) is a no-op, not a heal.
                await resilience.emit_recovery_event(
                    investigation_id=signals.investigation_id,
                    action="reconcile_drop_lock",
                    detail={
                        "task_id": task_id,
                        "task_status": signals.task_status,
                        "lock_dropped": bool(dropped),
                        "cursor_state": signals.cursor_state,
                    },
                    source="state_reconciler",
                )
            return ReconcileReport(
                task_id=task_id, signals=signals,
                healed=bool(actions), actions=tuple(actions),
            )

        # Case D (#120): task RUNNING, ARQ in-progress lock present,
        # BUT the workflow cursor already sits in a reserved terminal.
        # This is the "worker completed the workflow, then crashed
        # before updating TaskRecord" window. The lock is a ghost worker
        # slot AND the row is a stuck-RUNNING zombie -- neither the
        # heartbeat reaper (still fresh, worker died mid-teardown) nor
        # Case B (which requires lock absent) nor Case C (which requires
        # terminal task status) covers it. Without Case D on-demand
        # reconcile returns healed=False and falsely reports the row as
        # consistent; only the 24h periodic reaper eventually cleans it.
        #
        # Heal: flip status FAILED with a distinct suffix so the audit
        # trail names the crash-mid-teardown mode, drop the ghost lock,
        # and delete the terminal cursor (same three mutations Case B
        # would run if it saw the same cursor state).
        if (
            signals.task_status == TaskStatus.RUNNING.value
            and signals.lock_present is True
            and signals.cursor_state in _TERMINAL_CURSOR_STATES
        ):
            await self._flip_status(
                task_id,
                new_status=TaskStatus.FAILED.value,
                error_suffix=(
                    f"[state_reconciler: cursor terminal "
                    f"({signals.cursor_state}) but task RUNNING with "
                    "in-progress lock -- worker crashed mid-teardown]"
                ),
            )
            actions.append(ReconcileAction(
                kind="flip_status_failed",
                reason=(
                    f"RUNNING + lock present + cursor terminal "
                    f"({signals.cursor_state}); worker crashed after "
                    "workflow completion but before status flip -- "
                    "status -> FAILED"
                ),
            ))
            dropped = await self._drop_lock(task_id)
            if dropped:
                actions.append(ReconcileAction(
                    kind="drop_in_progress_lock",
                    reason=(
                        "ARQ in-progress lock was a ghost slot "
                        "(worker died mid-teardown); dropped"
                    ),
                ))
            await self._delete_cursor(task_id)
            actions.append(ReconcileAction(
                kind="delete_stale_cursor",
                reason=(
                    f"cursor was in reserved terminal "
                    f"({signals.cursor_state}); deleted post-heal"
                ),
            ))
            await resilience.emit_recovery_event(
                investigation_id=signals.investigation_id,
                action="reconcile_crashed_mid_teardown",
                detail={
                    "task_id": task_id,
                    "task_status": signals.task_status,
                    "cursor_state": signals.cursor_state,
                    "lock_dropped": bool(dropped),
                },
                source="state_reconciler",
            )
            return ReconcileReport(
                task_id=task_id, signals=signals,
                healed=True, actions=tuple(actions),
            )

        # Everything else (task QUEUED / WAITING / RUNNING+lock present
        # with a resumable cursor, or the lock-probe was skipped) is
        # either consistent or falls under a periodic sweep's owned
        # scope; the reconciler declines to heal so we do not fork any
        # of those paths here.
        return ReconcileReport(
            task_id=task_id, signals=signals,
            healed=False, actions=(),
        )

    async def reconcile_investigation(
        self,
        investigation_id: str,
        *,
        binding: InvestigationRecoveryBinding,
    ) -> InvestigationReconcileReport:
        """Reconcile every task + cursor of one investigation, then apply
        the investigation-level convergence invariant (RFC-07 signature,
        L3.3).

        Refuses operator-terminal / PAUSED rows (read-only report, no
        heal): ``refusal_reason`` is ``paused`` / ``terminal`` /
        ``not_found`` in those cases. Otherwise:

        1. Enumerates every ``TaskRecord`` for the investigation via the
           TYPED JSONB extract ``kwargs_json::jsonb->>'investigation_id'``
           (never a substring LIKE -- same shape
           :meth:`TaskQueue.enqueued_investigation_ids` uses) and every
           cursor via the denormalized ``investigation_id`` column
           (RFC-02), then calls the existing per-task
           :meth:`reconcile` for each.
        2. Applies the investigation invariant on RUNNING / CREATED rows
           AFTER per-task healing: when NO live task (queued/running/
           waiting) remains AND no resumable cursor exists, it drives the
           full :func:`~aila.platform.services.investigation_lifecycle
           .reenqueue_investigation` reset (the same primitive the
           stall/stuck sweeps use), so a RUNNING-but-dead investigation
           is detected and re-enqueued (RFC-07 acceptance criterion).
           When a resumable cursor exists but no live task, it uses
           :func:`aila.platform.tasks.queue.requeue_same_job_id` for that
           cursor's run so the checkpoint is picked back up under the
           original job id.
        3. Journals ONE aggregated recovery event for the whole pass.

        ``binding`` supplies the module data the platform authority still
        needs (investigation table identifier, track, fn-path pattern,
        models, submit primitive) -- see :class:`InvestigationRecoveryBinding`.
        """
        from aila.platform.services.resilience import (
            get_default_resilience_layer,
        )
        resilience = get_default_resilience_layer()

        # 1a. Read the investigation row; respect operator intent.
        status_stmt = _sql_text(
            f"SELECT status AS status FROM {binding.investigations_table} "
            "WHERE id = :inv"
        ).bindparams(inv=investigation_id)
        try:
            async with async_session_scope() as session:
                status_row = (
                    await session.execute(status_stmt)
                ).mappings().first()
        except SQLAlchemyError as exc:
            _log.warning(
                "state_reconciler.reconcile_investigation inv=%s: status "
                "read failed: %s", investigation_id, exc,
            )
            return InvestigationReconcileReport(
                investigation_id=investigation_id,
                healed=False,
                refusal_reason="read_failed",
            )
        if status_row is None:
            return InvestigationReconcileReport(
                investigation_id=investigation_id,
                healed=False,
                refusal_reason="not_found",
            )
        inv_status = str(status_row["status"])
        if inv_status == InvestigationStatus.PAUSED.value:
            return InvestigationReconcileReport(
                investigation_id=investigation_id,
                healed=False,
                refusal_reason="paused",
            )
        # Operator-terminal reconciliation. When the investigation is
        # COMPLETED / FAILED / ABANDONED but its cursor is still parked
        # at a live mid-pipeline state, the row is stranded (the sweep
        # excluded it, the direct reconcile refused it). Drive every
        # stranded cursor to the sentinel that matches the investigation
        # status, journal a recovery event, and return healed=True. Any
        # module extra-terminal or the STALLED class continues to refuse
        # -- STALLED is owned by the stall-recovery sweep's CAS claim
        # and we must never race it; module extras are the module's own
        # opaque terminal set and we do not know the cursor semantics.
        cursor_terminal_target = _INVESTIGATION_STATUS_TO_CURSOR_TERMINAL.get(
            inv_status,
        )
        if cursor_terminal_target is not None:
            return await self._reconcile_terminal_investigation_cursors(
                investigation_id=investigation_id,
                inv_status=inv_status,
                target_state=cursor_terminal_target,
                resilience=resilience,
            )
        refusal = _OPERATOR_TERMINAL_INVESTIGATION_STATUSES | set(
            binding.extra_terminal_statuses
        )
        if inv_status in refusal:
            return InvestigationReconcileReport(
                investigation_id=investigation_id,
                healed=False,
                refusal_reason="terminal",
            )

        # 1b. Enumerate tasks (typed jsonb extract) + cursors
        #     (denormalized investigation_id column, RFC-02).
        try:
            async with async_session_scope() as session:
                task_rows = (
                    await session.execute(_sql_text(
                        "SELECT id::text AS id FROM taskrecord "
                        "WHERE kwargs_json::jsonb->>'investigation_id' = :inv"
                    ).bindparams(inv=investigation_id))
                ).mappings().all()
                cursor_rows = (
                    await session.execute(_sql_text(
                        "SELECT run_id::text AS run_id, "
                        "       current_state AS current_state "
                        "FROM workflow_state_cursor "
                        "WHERE investigation_id = :inv"
                    ).bindparams(inv=investigation_id))
                ).mappings().all()
        except SQLAlchemyError as exc:
            _log.warning(
                "state_reconciler.reconcile_investigation inv=%s: "
                "enumeration failed: %s", investigation_id, exc,
            )
            return InvestigationReconcileReport(
                investigation_id=investigation_id,
                healed=False,
                refusal_reason="read_failed",
            )
        task_ids = [str(r["id"]) for r in task_rows]
        cursors = [
            (str(r["run_id"]), str(r["current_state"]))
            for r in cursor_rows
        ]

        # Slow-node in-flight capture (VR-8FD8). Probe the arq
        # ``arq:in-progress:<task_id>`` lock for every enumerated task
        # BEFORE the per-task reconcile loop runs -- that loop's Case C
        # (task terminal + lock present) DROPS a lock it reads as a ghost
        # slot, which erases the one signal that tells us a worker is
        # actively transitioning states for this investigation right now.
        # On the slow 27B node a run's TaskRecord.status can desync to a
        # stale ``cancelled`` while the arq job is still executing; a lock
        # held here means "a worker is driving this run", and requeuing it
        # spawns a duplicate loop instance (the branch_status_flipped:
        # abandoned ~1/sec storm) that then crashes arq on
        # ``del self.job_tasks[job_id]``. Captured now, consumed by the
        # invariant guard below.
        lock_present_at_entry = False
        for task_id in task_ids:
            if await self._probe_lock(task_id):
                lock_present_at_entry = True
                break

        # 2. Per-task healing (each report is journaled individually by
        #    :meth:`reconcile`).
        task_reports: list[ReconcileReport] = []
        for task_id in task_ids:
            task_reports.append(await self.reconcile(task_id))

        # 3. Investigation invariant -- only RUNNING / CREATED rows.
        if inv_status not in (
            InvestigationStatus.RUNNING.value,
            InvestigationStatus.CREATED.value,
        ):
            return InvestigationReconcileReport(
                investigation_id=investigation_id,
                healed=any(r.healed for r in task_reports),
                task_reports=tuple(task_reports),
            )

        try:
            async with async_session_scope() as session:
                live_row = (
                    await session.execute(_sql_text(
                        "SELECT 1 AS one FROM taskrecord "
                        "WHERE kwargs_json::jsonb->>'investigation_id' = :inv "
                        "  AND status = ANY(:live) LIMIT 1"
                    ).bindparams(
                        inv=investigation_id,
                        live=list(_LIVE_TASK_STATUSES),
                    ))
                ).mappings().first()
                resumable_row = (
                    await session.execute(_sql_text(
                        "SELECT 1 AS one FROM workflow_state_cursor "
                        "WHERE investigation_id = :inv "
                        "  AND current_state <> ALL(:non_resumable) LIMIT 1"
                    ).bindparams(
                        inv=investigation_id,
                        non_resumable=list(_NON_RESUMABLE_CURSOR_STATES),
                    ))
                ).mappings().first()
        except SQLAlchemyError as exc:
            _log.warning(
                "state_reconciler.reconcile_investigation inv=%s: "
                "invariant probe failed: %s", investigation_id, exc,
            )
            return InvestigationReconcileReport(
                investigation_id=investigation_id,
                healed=any(r.healed for r in task_reports),
                task_reports=tuple(task_reports),
            )
        has_live_task = live_row is not None
        has_resumable_cursor = resumable_row is not None

        # Slow-node in-flight guard (VR-8FD8). ``has_live_task`` above is
        # read purely from ``TaskRecord.status``. On a slow/flaky model the
        # TaskRecord can desync -- a run whose status is a stale
        # ``cancelled`` while the arq job is STILL executing inside a worker
        # slot. ``lock_present_at_entry`` captured the arq in-progress lock
        # before the per-task loop could drop it, and is the ground truth
        # for "a worker is driving this run right now". When it was held,
        # treat the investigation as having a live task and refuse to
        # requeue: the job is alive, just slow. Requeuing it would spawn a
        # duplicate loop instance (the branch_status_flipped:abandoned storm)
        # and crash arq on ``del self.job_tasks[job_id]``.
        if not has_live_task and lock_present_at_entry:
            has_live_task = True
            _log.info(
                "state_reconciler.reconcile_investigation inv=%s: no live "
                "TaskRecord status but an ARQ in-progress lock was held at "
                "entry -- a worker is driving this run (slow node); skipping "
                "requeue to avoid a duplicate-loop storm",
                investigation_id,
            )

        investigation_action: str | None = None
        if not has_live_task:
            if has_resumable_cursor:
                # The checkpoint itself is worth keeping: re-run that
                # cursor's run under its OWN job id so the engine picks
                # the resumable state back up (never a fresh uuid).
                requeued_runs: list[str] = []
                for run_id, run_state in cursors:
                    if run_state in _NON_RESUMABLE_CURSOR_STATES:
                        continue
                    if await requeue_same_job_id(
                        run_id, track=binding.track,
                    ):
                        requeued_runs.append(run_id)
                if requeued_runs:
                    investigation_action = "requeued_run"
            else:
                # RUNNING/CREATED with NO live task and NO resumable
                # cursor: the investigation is dead. Drive the same full
                # reset the stall/stuck sweeps use (reset to CREATED,
                # cancel stale tasks, wipe prior-run cursors, submit
                # fresh) so the invariant converges immediately rather
                # than waiting on a sibling sweep's eligibility window.
                from aila.platform.services.investigation_lifecycle import (
                    ReenqueueInvestigationError,
                    reenqueue_investigation,
                )
                try:
                    await reenqueue_investigation(
                        investigation_id,
                        inv_model=binding.inv_model,
                        fn_path_pattern=binding.fn_path_pattern,
                        submit_one=binding.submit_one,
                        branch_model=binding.branch_model,
                        branch_status_active=binding.branch_status_active,
                    )
                    investigation_action = "reenqueued"
                except (
                    ReenqueueInvestigationError,
                    SQLAlchemyError,
                    OSError,
                    RuntimeError,
                    ValueError,
                    TypeError,
                ) as exc:
                    _log.warning(
                        "state_reconciler.reconcile_investigation inv=%s: "
                        "REENQUEUE fallback failed: %s",
                        investigation_id, exc,
                    )
                    investigation_action = "reenqueue_failed"

        # 4. ONE aggregated recovery event when the pass did anything.
        task_kinds = tuple(
            kind
            for report in task_reports
            for kind in report.get_action_kinds()
        )
        if task_kinds or investigation_action in ("reenqueued", "requeued_run"):
            await resilience.emit_recovery_event(
                investigation_id=investigation_id,
                action="reconcile_investigation",
                detail={
                    "inv_status": inv_status,
                    "task_action_kinds": list(task_kinds),
                    "investigation_action": investigation_action,
                    "task_count": len(task_ids),
                    "cursor_count": len(cursors),
                },
                source="state_reconciler",
            )

        healed = bool(task_kinds) or investigation_action in (
            "reenqueued", "requeued_run",
        )
        return InvestigationReconcileReport(
            investigation_id=investigation_id,
            healed=healed,
            task_reports=tuple(task_reports),
            investigation_action=investigation_action,
        )

    async def _reconcile_terminal_investigation_cursors(
        self,
        *,
        investigation_id: str,
        inv_status: str,
        target_state: str,
        resilience: Any,
    ) -> InvestigationReconcileReport:
        """Drive every stranded workflow cursor of an operator-terminal
        investigation to ``target_state`` (RFC-07 terminal-cursor
        reconciliation, VR-truth Stream C3).

        Selects the investigation's cursor rows whose ``current_state``
        is a live mid-pipeline position (not in :data:`_UNTOUCHABLE_CURSOR_STATES`,
        so engine terminals and the operator ``__paused__`` sentinel are
        left alone) and UPDATEs them in a single idempotent statement.
        Emits one aggregated recovery event so operators see the pass in
        the ledger. A concurrent DELETE / independent terminal write
        races to a rowcount-0 no-op; the caller path stays idempotent.
        """
        try:
            async with async_session_scope() as session:
                update_result = await session.execute(
                    _update(WorkflowStateCursor)
                    .where(
                        WorkflowStateCursor.investigation_id
                        == investigation_id
                    )
                    .where(
                        WorkflowStateCursor.current_state.not_in(  # type: ignore[union-attr]
                            list(_UNTOUCHABLE_CURSOR_STATES)
                        )
                    )
                    .values(
                        current_state=target_state,
                        updated_at=utc_now(),
                    )
                    .execution_options(synchronize_session=False)
                )
                await session.commit()
        except SQLAlchemyError as exc:
            _log.warning(
                "state_reconciler.reconcile_investigation inv=%s: "
                "terminal-cursor UPDATE failed: %s",
                investigation_id, exc,
            )
            return InvestigationReconcileReport(
                investigation_id=investigation_id,
                healed=False,
                refusal_reason="read_failed",
            )
        terminalized = int(update_result.rowcount or 0)
        if terminalized == 0:
            # No stranded cursor for this operator-terminal investigation
            # -- nothing to heal. Return the historical refusal so the
            # sweep log line does not lie about work performed.
            return InvestigationReconcileReport(
                investigation_id=investigation_id,
                healed=False,
                refusal_reason="terminal",
            )
        await resilience.emit_recovery_event(
            investigation_id=investigation_id,
            action="reconcile_terminal_cursor",
            detail={
                "inv_status": inv_status,
                "target_state": target_state,
                "cursors_terminalized": terminalized,
            },
            source="state_reconciler",
        )
        _log.info(
            "state_reconciler.reconcile_investigation inv=%s: operator-"
            "terminal status=%s drove %d stranded cursor(s) to %s",
            investigation_id, inv_status, terminalized, target_state,
        )
        return InvestigationReconcileReport(
            investigation_id=investigation_id,
            healed=True,
            investigation_action="terminalized_cursor",
        )

    # ------------------------------------------------------------------
    # Signal helpers
    # ------------------------------------------------------------------

    def _resolve_redis_url(self) -> str:
        """Return the Redis URL to hit, or the empty string when unset."""
        if self._explicit_redis_url is not None:
            return self._explicit_redis_url
        return os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()

    async def _probe_lock(self, task_id: str) -> bool | None:
        """Return True iff ``arq:in-progress:<task_id>`` is present in Redis.

        None means the probe was skipped (no Redis URL); False means the
        key is definitely absent; True means the key is present.
        """
        redis_url = self._resolve_redis_url()
        if not redis_url:
            return None
        client = aioredis.Redis.from_url(
            redis_url, socket_connect_timeout=2.0,
        )
        try:
            key = f"{ARQ_IN_PROGRESS_PREFIX}{task_id}"
            exists = await client.exists(key)
        except (OSError, RuntimeError) as exc:
            _log.warning(
                "state_reconciler._probe_lock(%s): redis exists failed: %s "
                "-- treating as unknown", task_id, exc,
            )
            return None
        finally:
            try:
                await client.aclose()
            except (OSError, RuntimeError) as exc:
                _log.debug(
                    "state_reconciler._probe_lock aclose: %s", exc,
                )
        return bool(exists)

    def _cursor_is_resumable(self, cursor_state: str | None) -> bool:
        """Return True when a cursor row is present and non-terminal.

        Mirrors :func:`aila.platform.tasks.worker._workflow_cursor_is_resumable`
        without needing a live session, so ``read_signals`` can decide
        the heal path from the pre-fetched snapshot.
        """
        if cursor_state is None:
            return False
        return cursor_state not in _TERMINAL_CURSOR_STATES

    def _reap_reason(self, signals: TaskSignals) -> str | None:
        """Return the reap reason string when the row is a stale zombie.

        Mirrors :func:`aila.platform.tasks.worker._should_drop_lock` for
        the RUNNING branch: heartbeat older than the heartbeat cutoff,
        or no heartbeat and started_at older than the zombie cutoff.
        Returns None when the row is still within grace.
        """
        if signals.task_status != TaskStatus.RUNNING.value:
            return None
        now = utc_now()
        hb_cutoff = now - timedelta(seconds=self._heartbeat_threshold_s)
        fresh_cutoff = now - timedelta(seconds=self._zombie_threshold_s)
        hb = signals.task_heartbeat_at
        if hb is not None:
            hb_norm = hb if hb.tzinfo is not None else hb.replace(
                tzinfo=now.tzinfo,
            )
            if hb_norm < hb_cutoff:
                return "stale_heartbeat_at"
            return None
        started = signals.task_started_at
        if started is None:
            return "no_started_at"
        started_norm = (
            started if started.tzinfo is not None
            else started.replace(tzinfo=now.tzinfo)
        )
        if started_norm < fresh_cutoff:
            return "stale_started_at"
        return None

    # ------------------------------------------------------------------
    # Heal helpers (delegated to the same mutations the periodic sweep
    # already performs; kept small so a reviewer can see each is a
    # single SQL statement / single Redis command).
    # ------------------------------------------------------------------

    async def _flip_status(
        self, task_id: str, *, new_status: str, error_suffix: str,
    ) -> None:
        """Update ``TaskRecord.status`` to ``new_status`` and stamp completion.

        A missing row is a no-op (returns silently) so a race with a
        concurrent DELETE never crashes the reconciler.
        """
        # #203: previously the row was fetched with ``session.get`` (no
        # lock), inspected in Python, then re-written -- classic TOCTOU
        # against a concurrent hook that stamps a terminal status. The
        # guard is now expressed as a single idempotent UPDATE whose
        # WHERE clause excludes the terminal set, so racing writers
        # either both win a no-op (rowcount 0) or exactly one flips
        # the row and the other observes it as terminal.
        async with async_session_scope() as session:
            row = await session.execute(
                _update(TaskRecord)
                .where(TaskRecord.id == task_id)  # type: ignore[arg-type]
                .where(
                    TaskRecord.status.not_in(  # type: ignore[union-attr]
                        list(_TERMINAL_TASK_STATUSES)
                    )
                )
                .values(
                    status=new_status,
                    completed_at=utc_now(),
                    updated_at=utc_now(),
                    error=_sql_text(
                        "TRIM(COALESCE(error, '') || ' ' || :suffix)"
                    ).bindparams(suffix=error_suffix),
                )
                .execution_options(synchronize_session=False)
            )
            _ = row  # rowcount inspection intentionally skipped: 0 rows
            # is a valid outcome (row missing OR already terminal) and
            # the reconciler treats both as "already consistent".
            await session.commit()

    async def _delete_cursor(self, task_id: str) -> None:
        """Delete the ``workflow_state_cursor`` row for ``task_id``.

        Mirrors the sweep in :func:`aila.platform.tasks.cursor_reaper.sweep_orphan_crashed_cursors`
        narrowed to one row. Safe under concurrent DELETE (rowcount 0
        is not an error) so the reconciler stays idempotent.
        """
        async with async_session_scope() as session:
            stmt = (
                _delete(WorkflowStateCursor)
                .where(WorkflowStateCursor.run_id == task_id)
                .execution_options(synchronize_session=False)
            )
            await session.exec(stmt)
            await session.commit()

    async def _drop_lock(self, task_id: str) -> bool:
        """Delete ``arq:in-progress:<task_id>`` from Redis.

        Best-effort mirror of :func:`aila.platform.tasks.queue._drop_arq_in_progress_key`
        (kept local so the reconciler owns its Redis connection
        lifecycle -- the queue helper opens + closes a client per
        call, which is the right shape for a one-shot heal path but
        doubles the imports). Returns True on a successful delete,
        False when the URL is unset / the client fails to reach Redis.
        """
        redis_url = self._resolve_redis_url()
        if not redis_url:
            return False
        client = aioredis.Redis.from_url(
            redis_url, socket_connect_timeout=2.0,
        )
        try:
            key = f"{ARQ_IN_PROGRESS_PREFIX}{task_id}"
            deleted = await client.delete(key)
        except (OSError, RuntimeError) as exc:
            _log.warning(
                "state_reconciler._drop_lock(%s) failed: %s -- "
                "reaper will reconcile on next sweep", task_id, exc,
            )
            return False
        finally:
            try:
                await client.aclose()
            except (OSError, RuntimeError) as exc:
                _log.debug(
                    "state_reconciler._drop_lock aclose: %s", exc,
                )
        return bool(deleted)


async def _reconciler_periodic_enabled() -> bool:
    """Resolve the ``platform.investigation_reconciler_periodic_enabled`` gate.

    Fail-open to True (the schema default): the periodic
    :func:`sweep_investigations_reconcile` pass is a correctness fix, so an
    unreadable config must not silently disable it (RFC-07 reconcile wave,
    L3.4). The registry import is deferred to call time because config /
    db_models sits on the same import cycle the module docstring documents
    for resilience.
    """
    try:
        from aila.storage.registry import ConfigRegistry

        value = await ConfigRegistry().get(
            "platform", "investigation_reconciler_periodic_enabled",
        )
        return bool(value)
    except (ImportError, AttributeError, RuntimeError, OSError, ValueError, TypeError):
        _log.warning(
            "state_reconciler: periodic-enabled gate lookup failed; "
            "defaulting to enabled (correctness fix)",
            exc_info=True,
        )
        return True


async def sweep_investigations_reconcile(
    binding: InvestigationRecoveryBinding,
    *,
    limit: int = 25,
) -> dict[str, int]:
    """One periodic pass of the investigation-scoped reconciler authority
    (RFC-07 reconcile wave, L3.4).

    Reconciles the oldest ``limit`` non-terminal, non-paused
    investigations each tick (bounded batch). Every candidate is claimed
    with
    :func:`aila.platform.services.recovery_claim.try_claim_recovery`
    (compare-and-set on ``updated_at``) BEFORE the per-investigation
    heal, so multi-worker ticks and the sibling stall/stuck sweeps cannot
    converge on the same row twice (the claim is the same primitive the
    stall/stuck sweeps use -- this pass is the last-resort convergence
    step and must never race them). Fail-open per row: an error is
    logged and the pass continues, matching the sweep-registry error
    posture.

    Gated by ``platform.investigation_reconciler_periodic_enabled``
    (default True). Modules register this callable (bound via
    ``functools.partial``) with
    :func:`aila.platform.tasks.sweeps.register_periodic_sweep` at
    ``SweepPriority.RECONCILE`` (800) so it runs AFTER stall(500) /
    stuck(600) as the last-resort convergence pass.

    Returns ``{"examined": N, "healed": N}`` (or a skip marker when the
    gate is off) for the operator-facing sweep log.
    """
    if not await _reconciler_periodic_enabled():
        return {"skipped": True, "reason": "config_disabled"}

    from aila.platform.services.recovery_claim import try_claim_recovery

    excluded = list(
        _OPERATOR_TERMINAL_INVESTIGATION_STATUSES
        | {InvestigationStatus.PAUSED.value}
        | set(binding.extra_terminal_statuses)
    )
    # Operator-terminal statuses whose stranded cursors we DO reconcile
    # this tick. Bounded by an EXISTS on a live mid-pipeline cursor
    # (:data:`_UNTOUCHABLE_CURSOR_STATES` is the negation), so a normal
    # cleanly-closed operator-terminal investigation is never re-examined
    # -- only rows whose workflow cursor was left parked at a live state
    # get picked up. STALLED stays excluded (stall-recovery pipeline owns
    # its CAS claim). PAUSED stays excluded (operator intent).
    terminal_cleanup_statuses = list(_INVESTIGATION_STATUS_TO_CURSOR_TERMINAL)
    untouchable_cursor_states = list(_UNTOUCHABLE_CURSOR_STATES)
    timestamp_column = binding.timestamp_column
    if binding.sweepable_statuses is not None:
        # Vocabulary-diverging module (forensics): claim ONLY the live
        # statuses so non-live rows are never selected and their claim
        # timestamp never drifts. UNION with operator-terminal rows that
        # still carry a stranded workflow cursor so those get healed too.
        select_stmt = _sql_text(
            f"""
            SELECT id, seen_ts FROM (
                SELECT inv.id::text AS id, inv.{timestamp_column} AS seen_ts
                FROM {binding.investigations_table} inv
                WHERE inv.status = ANY(:sweepable)
                UNION
                SELECT inv.id::text AS id, inv.{timestamp_column} AS seen_ts
                FROM {binding.investigations_table} inv
                WHERE inv.status = ANY(:terminal_cleanup)
                  AND EXISTS (
                    SELECT 1 FROM workflow_state_cursor c
                    WHERE c.investigation_id = inv.id::text
                      AND c.current_state <> ALL(:untouchable)
                  )
            ) AS candidates
            ORDER BY seen_ts ASC
            LIMIT :limit
            """
        ).bindparams(
            sweepable=list(binding.sweepable_statuses),
            terminal_cleanup=terminal_cleanup_statuses,
            untouchable=untouchable_cursor_states,
            limit=limit,
        )
    else:
        select_stmt = _sql_text(
            f"""
            SELECT id, seen_ts FROM (
                SELECT inv.id::text AS id, inv.{timestamp_column} AS seen_ts
                FROM {binding.investigations_table} inv
                WHERE inv.status <> ALL(:excluded)
                UNION
                SELECT inv.id::text AS id, inv.{timestamp_column} AS seen_ts
                FROM {binding.investigations_table} inv
                WHERE inv.status = ANY(:terminal_cleanup)
                  AND EXISTS (
                    SELECT 1 FROM workflow_state_cursor c
                    WHERE c.investigation_id = inv.id::text
                      AND c.current_state <> ALL(:untouchable)
                  )
            ) AS candidates
            ORDER BY seen_ts ASC
            LIMIT :limit
            """
        ).bindparams(
            excluded=excluded,
            terminal_cleanup=terminal_cleanup_statuses,
            untouchable=untouchable_cursor_states,
            limit=limit,
        )

    try:
        async with async_session_scope() as session:
            rows = (await session.execute(select_stmt)).mappings().all()
    except SQLAlchemyError as exc:
        _log.warning(
            "state_reconciler.sweep_investigations_reconcile[%s]: "
            "candidate SELECT failed: %s",
            binding.module_id, exc,
        )
        return {"examined": 0, "healed": 0, "error": "select_failed"}

    reconciler = StateReconciler()
    examined = 0
    healed = 0
    for row in rows:
        inv_id = str(row["id"])
        seen_ts = row["seen_ts"]
        examined += 1
        if seen_ts is None:
            _log.warning(
                "state_reconciler.sweep_investigations_reconcile[%s]: "
                "inv=%s missing updated_at; cannot claim, skipping",
                binding.module_id, inv_id,
            )
            continue
        try:
            claimed = await try_claim_recovery(
                inv_table=binding.investigations_table,
                timestamp_column=timestamp_column,
                inv_id=inv_id,
                seen_timestamp=seen_ts,
            )
        except SQLAlchemyError as exc:
            _log.warning(
                "state_reconciler.sweep_investigations_reconcile[%s]: "
                "claim failed inv=%s: %s",
                binding.module_id, inv_id, exc,
            )
            continue
        if not claimed:
            # A sibling sweep already owns this row this tick; the
            # compare-and-set is the mutual exclusion -- skip.
            continue
        try:
            report = await reconciler.reconcile_investigation(
                inv_id, binding=binding,
            )
        except (SQLAlchemyError, OSError, RuntimeError, ValueError) as exc:
            _log.warning(
                "state_reconciler.sweep_investigations_reconcile[%s]: "
                "reconcile failed inv=%s: %s",
                binding.module_id, inv_id, exc,
            )
            continue
        if report.healed:
            healed += 1
        _log.info(
            "state_reconciler.sweep_investigations_reconcile[%s]: inv=%s "
            "healed=%s refusal=%s action=%s kinds=%s",
            binding.module_id, inv_id, report.healed,
            report.refusal_reason, report.investigation_action,
            report.per_task_action_kinds,
        )
    return {"examined": examined, "healed": healed}


