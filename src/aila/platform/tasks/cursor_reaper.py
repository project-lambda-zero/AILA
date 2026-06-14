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
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowStateCursor

from .models import TaskRecord, TaskStatus

__all__ = ["sweep_orphan_crashed_cursors"]

_log = logging.getLogger(__name__)


_ACTIVE_STATUSES = (
    TaskStatus.QUEUED,
    TaskStatus.RUNNING,
    TaskStatus.WAITING,
)

# fix §58 — sweep covers ALL FOUR reserved terminal cursor states so
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
    imports it under this name) — semantically this now sweeps all
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
            # fix §69 — some drivers (asyncpg in certain modes, ODBC)
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
