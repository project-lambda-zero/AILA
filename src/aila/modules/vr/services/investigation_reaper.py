"""Investigation-level auto-recovery reaper.

Runs periodically (called from platform worker reaper cron) to fix three
classes of stuck state that the task-level reaper can't see:

1. **Orphan investigations**: status='running' but no task in 'running' or
   'queued' state. All their work is done but nobody flipped the status.
   Fix: set to 'completed' (if has outcomes) or 'failed' (if no outcomes).

2. **Crashed workflow cursors**: cursor at '__crashed__' but the associated
   task is already 'done' or 'failed'. These block re-enqueue because the
   workflow engine refuses to start a new run when a crashed cursor exists.
   Fix: delete the orphan cursor row.

3. **Stale sibling branches**: investigation has branches with turn_count=0
   and status='active' for more than 2 hours, but no queued/running task
   exists for that branch. The sibling task was either never enqueued or
   was reaped before it ran.
   Fix: mark as 'abandoned' with reason 'reaper:no_task'.

All three sweeps are idempotent and safe to run concurrently.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlmodel import select

from aila.storage.database import async_session_scope

__all__ = ["reap_stuck_investigations"]

_log = logging.getLogger(__name__)

# Minimum age before we consider an investigation orphaned.
# Prevents false positives on investigations that just finished their
# last task but haven't been status-flipped by investigation_emit yet.
_ORPHAN_GRACE_MINUTES = 10

# Minimum age before a 0-turn branch is considered stale.
_STALE_BRANCH_HOURS = 2


async def reap_stuck_investigations() -> int:
    """Run all three recovery sweeps. Returns total rows fixed."""
    total = 0
    total += await _fix_orphan_investigations()
    total += await _clear_crashed_cursors()
    total += await _abandon_stale_branches()
    return total


async def _fix_orphan_investigations() -> int:
    """Fix investigations that say 'running' but have no active tasks."""
    from aila.modules.vr.db_models import VRInvestigationRecord  # noqa: PLC0415
    from aila.storage.db_models import TaskRecord  # noqa: PLC0415

    reaped = 0
    now = datetime.now(UTC)
    grace = now - timedelta(minutes=_ORPHAN_GRACE_MINUTES)

    async with async_session_scope() as session:
        # Find running investigations older than grace period
        running = (await session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.status == "running",
                VRInvestigationRecord.updated_at < grace,
            )
        )).all()

        for inv in running:
            # Check if ANY task for this investigation is still active
            active_task = (await session.exec(
                select(TaskRecord.id).where(
                    TaskRecord.status.in_(["running", "queued"]),  # type: ignore[union-attr]
                    TaskRecord.kwargs_json.contains(inv.id),  # type: ignore[union-attr]
                ).limit(1)
            )).first()

            if active_task is not None:
                continue  # legit — task is still working

            # No active task. Check if it has outcomes to decide status.
            from aila.modules.vr.db_models import VRInvestigationOutcomeRecord  # noqa: PLC0415
            has_outcome = (await session.exec(
                select(VRInvestigationOutcomeRecord.id).where(
                    VRInvestigationOutcomeRecord.investigation_id == inv.id,
                ).limit(1)
            )).first()

            new_status = "completed" if has_outcome else "failed"
            inv.status = new_status
            inv.updated_at = now
            session.add(inv)
            reaped += 1
            _log.warning(
                "investigation_reaper: orphan inv=%s → %s (no active tasks, "
                "last updated %s)",
                inv.id, new_status, inv.updated_at,
            )

        if reaped:
            await session.commit()
            _log.warning(
                "investigation_reaper: fixed %d orphan investigation(s)", reaped,
            )
    return reaped


async def _clear_crashed_cursors() -> int:
    """Delete __crashed__ workflow cursors whose tasks are already terminal."""
    from sqlalchemy import text as sa_text  # noqa: PLC0415

    cleared = 0
    async with async_session_scope() as session:
        # Direct SQL for efficiency — cursor table doesn't have a SQLModel model
        result = await session.exec(  # type: ignore[call-arg]
            sa_text("""
                DELETE FROM workflow_state_cursor
                WHERE current_state = '__crashed__'
                  AND NOT EXISTS (
                      SELECT 1 FROM taskrecord t
                      WHERE t.id = workflow_state_cursor.run_id
                        AND t.status IN ('queued', 'running')
                  )
            """)
        )
        cleared = result.rowcount  # type: ignore[union-attr]
        if cleared:
            await session.commit()
            _log.warning(
                "investigation_reaper: cleared %d crashed workflow cursor(s)",
                cleared,
            )
    return cleared


async def _abandon_stale_branches() -> int:
    """Abandon branches with 0 turns and no active task after 2+ hours."""
    from aila.modules.vr.db_models import VRInvestigationBranchRecord  # noqa: PLC0415
    from aila.storage.db_models import TaskRecord  # noqa: PLC0415

    abandoned = 0
    now = datetime.now(UTC)
    stale_cutoff = now - timedelta(hours=_STALE_BRANCH_HOURS)

    async with async_session_scope() as session:
        # Find 0-turn active branches older than cutoff
        stale = (await session.exec(
            select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.status == "active",
                VRInvestigationBranchRecord.turn_count == 0,
                VRInvestigationBranchRecord.created_at < stale_cutoff,
            )
        )).all()

        for branch in stale:
            # Check if a task exists for this branch
            active_task = (await session.exec(
                select(TaskRecord.id).where(
                    TaskRecord.status.in_(["running", "queued"]),  # type: ignore[union-attr]
                    TaskRecord.kwargs_json.contains(branch.id),  # type: ignore[union-attr]
                ).limit(1)
            )).first()

            if active_task is not None:
                continue  # task exists, just waiting in queue

            branch.status = "abandoned"
            branch.closed_reason = "reaper:no_task"
            branch.closed_at = now
            session.add(branch)
            abandoned += 1
            _log.warning(
                "investigation_reaper: abandoned stale branch=%s "
                "(0 turns, no task, created %s)",
                branch.id, branch.created_at,
            )

        if abandoned:
            await session.commit()
            _log.warning(
                "investigation_reaper: abandoned %d stale branch(es)",
                abandoned,
            )
    return abandoned
