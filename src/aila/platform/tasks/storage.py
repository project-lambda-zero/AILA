"""TaskRepository -- scoped DB queries for TaskRecord.

All list/get operations filter by user's group_id (auth.role) unless the
user has admin role. This implements per-user-group task isolation
(D-21/D-22/MOD-13).

Ownership: Platform -- not module-specific.

Status-transition helpers (``set_paused`` / ``set_queued_from_paused`` /
``set_cancelled``) MUST keep the DB row and the ARQ side of the world in
sync. Historically several of them flipped ``TaskRecord.status`` +
committed without issuing the required ARQ side-effect (enqueue on
resume, in-progress-key drop on cancel), so the DB and ARQ silently
diverged and operators saw tasks stuck 'queued' forever or holding
worker slots after cancel. The re-enqueue / key-drop paths here now go
through :func:`aila.platform.tasks.queue._enqueue_arq_job` and
:func:`aila.platform.tasks.queue._drop_arq_in_progress_key` so all
task-side ARQ transitions live in one place.
"""

from __future__ import annotations

import json
import logging

from sqlmodel import select

from aila.api.auth import AuthContext
from aila.api.constants import ROLE_ADMIN
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.queue import (
    _drop_arq_in_progress_key,
    _enqueue_arq_job,
    _env_redis_url,
)

__all__ = ["TaskRepository"]

_log = logging.getLogger(__name__)


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
        # top -- without this the running scan is buried behind hundreds of
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
        """Transition a PAUSED task back to QUEUED and re-enqueue the ARQ job.

        Re-enqueue happens BEFORE the DB flip so a broker outage does not
        leave a PAUSED row flipped to QUEUED with no matching ARQ job -- the
        previous code committed the flip without ever enqueueing (issue
        #40-2), so resume-from-pause left the task stuck 'queued' forever.
        Delegates the actual enqueue to
        :func:`aila.platform.tasks.queue._enqueue_arq_job` so submit / requeue /
        resume all go through one code path.

        Returns False when the row is missing, not PAUSED, Redis is unreachable,
        ``kwargs_json`` is malformed, ``fn_path`` is empty, or the enqueue itself
        fails -- in every False case the row stays PAUSED so the caller can retry
        once the underlying cause clears.
        """
        record = await TaskRepository.get_for_user(session, task_id, auth)
        if record is None or record.status != TaskStatus.PAUSED:
            return False
        redis_url = _env_redis_url()
        if not redis_url:
            _log.warning(
                "set_queued_from_paused: AILA_PLATFORM_REDIS_URL unset -- "
                "leaving %s PAUSED", task_id,
            )
            return False
        try:
            task_kwargs = json.loads(record.kwargs_json) if record.kwargs_json else {}
        except (TypeError, ValueError) as exc:
            _log.warning(
                "set_queued_from_paused: task %s kwargs_json malformed (%s) -- "
                "leaving PAUSED", task_id, exc,
            )
            return False
        fn_short = record.fn_path.rsplit(".", 1)[-1] if record.fn_path else ""
        if not fn_short or not record.track:
            _log.warning(
                "set_queued_from_paused: task %s missing fn_path / track -- "
                "leaving PAUSED", task_id,
            )
            return False
        enqueued = await _enqueue_arq_job(
            track=record.track,
            task_id=task_id,
            fn_short=fn_short,
            kwargs=task_kwargs,
            redis_url=redis_url,
        )
        if not enqueued:
            _log.warning(
                "set_queued_from_paused: enqueue failed for %s -- leaving PAUSED",
                task_id,
            )
            return False
        record.status = TaskStatus.QUEUED
        session.add(record)
        await session.commit()
        return True

    @staticmethod
    async def set_cancelled(session, task_id: str, auth: AuthContext) -> bool:
        """Mark a non-terminal task as CANCELLED and drop its ARQ in-progress key.

        Terminal states -- ``DONE`` / ``FAILED`` / ``CANCELLED`` / ``DEAD_LETTER``
        -- are refused (returns False). ``DEAD_LETTER`` is included because
        dead-lettered tasks are already terminal in the worker's own model
        (see ``worker._TERMINAL_STATUSES``); the previous code omitted it
        (issue #40-3), so dead-lettered rows silently reverted to ``CANCELLED``
        and erased the poison-pill classification.

        After the DB flip commits, ``arq:in-progress:<task_id>`` is
        best-effort deleted via
        :func:`aila.platform.tasks.queue._drop_arq_in_progress_key` -- the
        previous code left the key in place, holding a worker slot until
        the cron reaper picked it up (paired with ``allow_abort_jobs=True``
        on ``WorkerSettings`` so a live executor drops the job on its next
        heartbeat). A key-drop failure does NOT reverse the DB flip; the
        reaper reconciles orphan keys on its next sweep.
        """
        _terminal = {
            TaskStatus.DONE,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.DEAD_LETTER,
        }
        record = await TaskRepository.get_for_user(session, task_id, auth)
        if record is None or record.status in _terminal:
            return False
        record.status = TaskStatus.CANCELLED
        session.add(record)
        await session.commit()
        redis_url = _env_redis_url()
        if redis_url:
            await _drop_arq_in_progress_key(task_id, redis_url)
        else:
            _log.debug(
                "set_cancelled: AILA_PLATFORM_REDIS_URL unset -- arq "
                "in-progress key drop skipped for %s (reaper will "
                "reconcile)", task_id,
            )
        return True
