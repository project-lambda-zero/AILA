"""TaskRepository — scoped DB queries for TaskRecord.

All list/get operations filter by user's group_id (auth.role) unless the
user has admin role. This implements per-user-group task isolation
(D-21/D-22/MOD-13).

Ownership: Platform — not module-specific.
"""

from __future__ import annotations

from sqlmodel import select

from aila.api.auth import AuthContext
from aila.api.constants import ROLE_ADMIN
from aila.platform.tasks.models import TaskRecord, TaskStatus

__all__ = ["TaskRepository"]


class TaskRepository:
    """Scoped DB queries for TaskRecord. Admin sees all; others see their group_id only."""

    @staticmethod
    async def list_for_user(
        session,
        auth: AuthContext,
        track: str | None = None,
        status: str | None = None,
    ) -> list[TaskRecord]:
        stmt = select(TaskRecord)
        if auth.role != ROLE_ADMIN:
            stmt = stmt.where(TaskRecord.group_id == auth.role)
        if track:
            stmt = stmt.where(TaskRecord.track == track)
        if status:
            stmt = stmt.where(TaskRecord.status == status)
        # Newest-first so the dashboard surfaces active / recent work at the
        # top — without this the running scan is buried behind hundreds of
        # older terminal rows.
        stmt = stmt.order_by(TaskRecord.created_at.desc())  # type: ignore[attr-defined]
        result = await session.exec(stmt)
        return list(result.all())

    @staticmethod
    async def get_for_user(
        session,
        task_id: str,
        auth: AuthContext,
    ) -> TaskRecord | None:
        stmt = select(TaskRecord).where(TaskRecord.id == task_id)
        if auth.role != ROLE_ADMIN:
            stmt = stmt.where(TaskRecord.group_id == auth.role)
        result = await session.exec(stmt)
        return result.first()

    @staticmethod
    async def set_paused(session, task_id: str, auth: AuthContext) -> bool:
        """Transition a RUNNING task to PAUSED. Returns False if not found or not RUNNING."""
        record = await TaskRepository.get_for_user(session, task_id, auth)
        if record is None or record.status != TaskStatus.RUNNING:
            return False
        record.status = TaskStatus.PAUSED
        session.add(record)
        await session.commit()
        return True

    @staticmethod
    async def set_queued_from_paused(session, task_id: str, auth: AuthContext) -> bool:
        """Transition a PAUSED task back to QUEUED. Returns False if not found or not PAUSED."""
        record = await TaskRepository.get_for_user(session, task_id, auth)
        if record is None or record.status != TaskStatus.PAUSED:
            return False
        record.status = TaskStatus.QUEUED
        session.add(record)
        await session.commit()
        return True

    @staticmethod
    async def set_cancelled(session, task_id: str, auth: AuthContext) -> bool:
        """Mark a non-terminal task as CANCELLED. Returns False if already terminal or not found."""
        _terminal = {TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.CANCELLED}
        record = await TaskRepository.get_for_user(session, task_id, auth)
        if record is None or record.status in _terminal:
            return False
        record.status = TaskStatus.CANCELLED
        session.add(record)
        await session.commit()
        return True
