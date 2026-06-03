"""Periodic sweep for orphan ``__crashed__`` workflow cursors.

Per CLAUDE.md (D-86 + cursor lifecycle notes): ``workflow_state_cursor``
rows whose ``current_state = '__crashed__'`` persist forever unless
explicitly cleared. The crash itself is recorded; the cursor row stays
so the operator can inspect it. But once the underlying TaskRecord
moves to a terminal status (done / failed / cancelled / dead_letter),
the cursor is dead weight that blocks re-enqueue paths because they
refuse to create a fresh ARQ job for an investigation whose cursor is
still around in a non-terminal-but-non-resumable state.

This sweep deletes only cursors that are unambiguously orphaned:

    current_state = '__crashed__'
    AND NOT EXISTS (
        SELECT 1 FROM taskrecord t
        WHERE t.id = cursor.run_id
          AND t.status IN ('queued', 'running', 'waiting')
    )

Called every minute from the worker reaper cron alongside the
investigation cap-sweep and the orphan-branch sweep.
"""
from __future__ import annotations

import logging

from sqlalchemy import delete as _delete
from sqlalchemy import select as _select

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


async def sweep_orphan_crashed_cursors() -> int:
    """Delete __crashed__ cursors whose TaskRecord is terminal.

    Returns the number of cursor rows deleted. Safe to call every
    minute; no-op when nothing's orphaned.
    """
    async with async_session_scope() as session:
        active_task_ids = _select(TaskRecord.id).where(
            TaskRecord.status.in_(_ACTIVE_STATUSES),  # type: ignore[attr-defined]
        )
        stmt = (
            _delete(WorkflowStateCursor)
            .where(
                WorkflowStateCursor.current_state == "__crashed__",
                ~WorkflowStateCursor.run_id.in_(active_task_ids),
            )
            .execution_options(synchronize_session=False)
        )
        result = await session.exec(stmt)
        deleted = result.rowcount or 0
        if deleted:
            await session.commit()
    if deleted:
        _log.info(
            "cursor_reaper: cleared %d orphan __crashed__ cursors", deleted,
        )
    return deleted
