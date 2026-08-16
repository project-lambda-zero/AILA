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
| RUNNING         | resumable        | absent              | D-86 SKIP path (existing)  |
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
lock, flip a status, delete a stale cursor), which are the same
mutations the periodic sweep does; the reconciler just packages them for
an on-demand per-task call so operators can heal one runaway task
without waiting a minute for the next cron tick or reasoning through the
three tables in the admin console.

Reuse, not reimplementation: the classification predicates delegate to
:func:`aila.platform.tasks.worker._should_drop_lock` and
:func:`aila.platform.tasks.worker._workflow_cursor_is_resumable`. The
delete-cursor path delegates to the same reserved-terminal set the
periodic reaper uses (:mod:`aila.platform.tasks.cursor_reaper`). The
re-enqueue on the D-86 SKIP path is deliberately deferred to the
periodic sweep -- an operator on-demand reconcile records the drift and
flips the status; the next cron tick re-enqueues via the sweep's
existing arq-pool wiring so we don't fork the enqueue plumbing across
two callsites.

Idempotent: a second call finds the drift already healed and returns a
report with ``healed=False``. Operator-set PAUSED or CANCELLED status is
respected -- the reconciler never resurrects an operator-terminated task.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta

from redis import asyncio as aioredis
from sqlalchemy import delete as _delete
from sqlalchemy import text as _sql_text
from sqlalchemy import update as _update

from aila.platform.contracts import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowStateCursor

from .constants import (
    ARQ_IN_PROGRESS_PREFIX,
    REAPER_HEARTBEAT_THRESHOLD_S,
    REAPER_ZOMBIE_THRESHOLD_S,
)
from .models import TaskRecord, TaskStatus

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
    "ReconcileAction",
    "ReconcileReport",
    "StateReconciler",
    "TaskSignals",
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


# Reserved terminal cursor states. Kept in sync with cursor_reaper's list
# (fix §58); duplicated here rather than imported so a rename lands in
# both files at once and the drift itself becomes a merge conflict.
_TERMINAL_CURSOR_STATES: frozenset[str] = frozenset({
    "__crashed__", "__failed__", "__cancelled__", "__succeeded__",
})

_TERMINAL_TASK_STATUSES: frozenset[str] = frozenset({
    TaskStatus.DONE.value,
    TaskStatus.FAILED.value,
    TaskStatus.CANCELLED.value,
    TaskStatus.DEAD_LETTER.value,
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
    """

    task_id: str
    task_status: str | None
    task_heartbeat_at: datetime | None
    task_started_at: datetime | None
    cursor_state: str | None
    lock_present: bool | None
    investigation_id: str | None


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
            # pick up from the last checkpoint. Flip status to CANCELLED
            # so 'is this task active?' queries see a consistent NO;
            # the cursor keeps the next-resume position; re-enqueue
            # itself is deferred to the periodic sweep's existing
            # arq-pool wiring (single owner, no fork of enqueue code).
            if self._cursor_is_resumable(signals.cursor_state):
                await self._flip_status(
                    task_id,
                    new_status=TaskStatus.CANCELLED.value,
                    error_suffix=(
                        f"[state_reconciler: {reap_reason}, cursor "
                        f"resumable ({signals.cursor_state or 'unset'}) "
                        "-- next worker sweep re-enqueues]"
                    ),
                )
                actions.append(ReconcileAction(
                    kind="flip_status_cancelled_resumable",
                    reason=(
                        f"D-86 SKIP: running-without-lock, cursor is "
                        f"resumable ({signals.cursor_state or 'unset'}); "
                        "status -> CANCELLED, cursor left intact"
                    ),
                ))
                await resilience.emit_recovery_event(
                    investigation_id=signals.investigation_id,
                    action="reconcile_cancel_resumable",
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


