"""Periodic sweep for orphan reserved-terminal workflow cursors.

Per CLAUDE.md (D-86 + cursor lifecycle notes): ``workflow_state_cursor``
rows whose ``current_state`` reaches a reserved terminal persist forever
unless explicitly cleared. The terminal itself is recorded; the cursor
row stays so the operator can inspect it. But once the underlying
TaskRecord moves to a terminal status (done / failed / cancelled /
dead_letter), the cursor is dead weight that blocks re-enqueue paths
because they refuse to create a fresh ARQ job for an investigation
whose cursor is still around in a non-resumable state.

This sweep deletes cursors that are unambiguously orphaned across
ALL FOUR reserved terminals (fix §58):

    current_state IN (
        '__crashed__', '__failed__', '__cancelled__', '__succeeded__'
    )
    AND NOT EXISTS (
        SELECT 1 FROM taskrecord t
        WHERE t.id = cursor.run_id
          AND t.status IN ('queued', 'running', 'waiting')
    )

(``__succeeded__`` cleanup was historically owned by the VR module's
masvs reconciler; consolidating here ensures a uniform sweep regardless
of which module owns the workflow.)

Called every minute from the worker reaper cron AFTER the orphan-queued
sweep so a cursor whose TaskRecord just flipped to FAILED in the same
tick is cleared the same tick (fix §57).
"""
from __future__ import annotations

import logging

from sqlalchemy import delete as _delete
from sqlalchemy import select as _select
from sqlalchemy import text as _text
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowStateCursor

from .models import TaskRecord, TaskStatus

__all__ = ["reap_zombie_tasks_and_cursors", "sweep_orphan_crashed_cursors"]

_log = logging.getLogger(__name__)


_ACTIVE_STATUSES = (
    TaskStatus.QUEUED,
    TaskStatus.RUNNING,
    TaskStatus.WAITING,
)

# fix §58 -- sweep covers ALL FOUR reserved terminal cursor states so
# __failed__ / __cancelled__ / __succeeded__ don't accumulate forever
# (previously only __crashed__ was reaped, leaving the other three as
# dead weight that blocked re-enqueue).
_TERMINAL_CURSOR_STATES = (
    "__crashed__",
    "__failed__",
    "__cancelled__",
    "__succeeded__",
)


async def sweep_orphan_crashed_cursors() -> int:
    """Delete reserved-terminal cursors whose TaskRecord is terminal.

    The function name is kept for backwards compatibility (worker.py
    imports it under this name) -- semantically this now sweeps all
    four reserved terminals, not just ``__crashed__``.

    Returns the number of cursor rows deleted. Safe to call every
    minute; no-op when nothing's orphaned.
    """
    deleted = 0
    try:
        async with async_session_scope() as session:
            active_task_ids = _select(TaskRecord.id).where(
                TaskRecord.status.in_(_ACTIVE_STATUSES),  # type: ignore[attr-defined]
            )
            stmt = (
                _delete(WorkflowStateCursor)
                .where(
                    WorkflowStateCursor.current_state.in_(  # type: ignore[attr-defined]
                        _TERMINAL_CURSOR_STATES,
                    ),
                    ~WorkflowStateCursor.run_id.in_(active_task_ids),
                )
                .execution_options(synchronize_session=False)
            )
            result = await session.exec(stmt)
            # fix §69 -- some drivers (asyncpg in certain modes, ODBC)
            # emit -1 from result.rowcount when the deleted count is
            # unknown. ``or 0`` evaluated -1 as truthy, so the commit
            # fired and the log line said "cleared -1 orphan cursors".
            # Clamp at zero before logging / committing.
            rowcount = result.rowcount
            if rowcount is None or rowcount < 0:
                _log.warning(
                    "cursor_reaper: driver returned rowcount=%r; treating "
                    "as zero", rowcount,
                )
                deleted = 0
            else:
                deleted = int(rowcount)
            if deleted > 0:
                await session.commit()
    except (SQLAlchemyError, DBAPIError) as exc:
        # fix §56 (companion): a DB hiccup here used to crash the entire
        # reaper tick; now we log + return zero so the cron continues
        # alongside the remaining sub-sweeps.
        _log.warning("cursor_reaper: db error during sweep: %s", exc)
        return 0
    if deleted:
        _log.info(
            "cursor_reaper: cleared %d orphan reserved-terminal cursors "
            "(states=%s)",
            deleted, ",".join(_TERMINAL_CURSOR_STATES),
        )
    return deleted


async def reap_zombie_tasks_and_cursors(
    *, heartbeat_min: int, batch_cap: int,
) -> dict[str, int]:
    """Cancel zombie tasks (any track) and purge dead workflow cursors.

    Platform-owned queue-maintenance sweep, run from the worker reaper
    cron. This is the single owner of maintenance SQL against
    ``taskrecord`` / ``workflow_state_cursor``; feature modules never
    issue that SQL themselves. Four coupled statements run in one
    transaction so step 3's JOIN observes step 1's UPDATE (READ
    COMMITTED):

      1. cancel any task stuck at ``running`` with a heartbeat older than
         ``heartbeat_min`` minutes -- a stale-running task is a zombie
         regardless of which module's track owns it,
      2. purge orphan cursors (no matching taskrecord at all),
      3. purge cursors whose taskrecord is terminal AND whose cursor
         state is a reserved terminal,
      4. purge ``__succeeded__`` cursors.

    Returns ``{zombies_cancelled, orphan_purged, terminal_purged,
    succeeded_purged, cursors_purged}``. Best-effort: a DB hiccup logs and
    returns zeros so the surrounding cron tick continues.
    """
    counts = {
        "zombies_cancelled": 0,
        "orphan_purged": 0,
        "terminal_purged": 0,
        "succeeded_purged": 0,
        "cursors_purged": 0,
    }
    try:
        async with async_session_scope() as session:
            # 1. Cancel zombie tasks: any track, status=running, heartbeat
            #    older than the threshold (also catches NULL heartbeat with
            #    an old started_at -- both indicate a worker that never
            #    reported life).
            zombie_sql = _text(
                """
                UPDATE taskrecord
                SET status = 'cancelled',
                    completed_at = NOW(),
                    updated_at = NOW(),
                    error = COALESCE(error, '') || ' [reaped: stale heartbeat]'
                WHERE status = 'running'
                  AND COALESCE(heartbeat_at, started_at) < NOW() - (:mins || ' minutes')::interval
                """,
            )
            zombie_result = await session.exec(
                zombie_sql, params={"mins": str(heartbeat_min)},
            )
            counts["zombies_cancelled"] = getattr(zombie_result, "rowcount", 0) or 0

            # 2. Purge orphan cursors (no matching taskrecord row at all).
            orphan_sql = _text(
                """
                DELETE FROM workflow_state_cursor
                WHERE run_id IN (
                    SELECT c.run_id FROM workflow_state_cursor c
                    WHERE NOT EXISTS (
                        SELECT 1 FROM taskrecord t WHERE t.id::text = c.run_id::text
                    )
                    LIMIT :cap
                )
                """,
            )
            orphan_result = await session.exec(orphan_sql, params={"cap": batch_cap})
            counts["orphan_purged"] = getattr(orphan_result, "rowcount", 0) or 0

            # 3. Purge cursors whose taskrecord is terminal AND whose cursor
            #    state is a reserved terminal. Restricting to reserved-terminal
            #    cursor states avoids a race with ARQ retry that would delete a
            #    cursor mid-state and wedge the retry at
            #    cursor_missing_during_commit.
            terminal_sql = _text(
                """
                DELETE FROM workflow_state_cursor
                WHERE run_id IN (
                    SELECT c.run_id FROM workflow_state_cursor c
                    JOIN taskrecord t ON t.id::text = c.run_id::text
                    WHERE t.status IN ('cancelled', 'done', 'failed', 'dead_letter')
                      AND c.current_state IN (
                          '__crashed__', '__failed__',
                          '__cancelled__', '__succeeded__'
                      )
                    LIMIT :cap
                )
                """,
            )
            terminal_result = await session.exec(terminal_sql, params={"cap": batch_cap})
            counts["terminal_purged"] = getattr(terminal_result, "rowcount", 0) or 0

            # 4. Purge __succeeded__ cursors -- terminal in the workflow
            #    engine, never re-read, they only accumulate.
            succeeded_sql = _text(
                """
                DELETE FROM workflow_state_cursor
                WHERE run_id IN (
                    SELECT run_id FROM workflow_state_cursor
                    WHERE current_state = '__succeeded__'
                    LIMIT :cap
                )
                """,
            )
            succeeded_result = await session.exec(succeeded_sql, params={"cap": batch_cap})
            counts["succeeded_purged"] = getattr(succeeded_result, "rowcount", 0) or 0

            counts["cursors_purged"] = (
                counts["orphan_purged"]
                + counts["terminal_purged"]
                + counts["succeeded_purged"]
            )
            if counts["zombies_cancelled"] or counts["cursors_purged"]:
                await session.commit()
    except (SQLAlchemyError, DBAPIError) as exc:
        _log.warning(
            "cursor_reaper: db error during zombie/cursor reap: %s", exc,
        )
        return {key: 0 for key in counts}
    return counts
