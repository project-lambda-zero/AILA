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

``set_cancelled`` DOES NOT commit the caller's session (#63). It flushes
the pending status flip so the change is visible to subsequent reads on
that session, and returns whether the transition was staged. The caller
owns the transaction and MUST commit once atomically -- pairing the
task flip with any co-mutated rows (e.g. an investigation row) so a
failed commit cannot leave TaskRecord=CANCELLED while a sibling row
keeps running. After a successful commit the caller invokes
:meth:`TaskRepository.finalize_cancel_side_effects` to drop the ARQ
``in-progress`` key. Splitting the two steps means the ARQ side-effect
cannot fire ahead of a commit that ends up rolling back.
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

    # #40-6: default page size for ``list_for_user``. The historical
    # implementation loaded EVERY row visible to the caller before
    # returning them to the API, which for admin/system callers on a
    # long-lived deployment is an unbounded scan. Callers can page by
    # bumping ``offset`` in ``LIST_PAGE_SIZE``-wide steps; the hard cap
    # ``LIST_PAGE_MAX`` protects the DB from a single request asking for
    # everything.
    LIST_PAGE_SIZE: int = 200
    LIST_PAGE_MAX: int = 1000

    @staticmethod
    async def list_for_user(
        session,
        auth: AuthContext,
        track: str | None = None,
        status: str | None = None,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[TaskRecord]:
        """Return tasks visible to ``auth``, newest first, page-bounded.

        ``limit`` defaults to ``LIST_PAGE_SIZE`` and is silently capped at
        ``LIST_PAGE_MAX`` (#40-6). ``offset`` is clamped at 0. A negative
        or zero ``limit`` falls back to the default page size so a
        misconfigured caller cannot ask for zero rows and rely on the API
        layer to "just work".
        """
        effective_limit = limit if (limit is not None and limit > 0) else TaskRepository.LIST_PAGE_SIZE
        if effective_limit > TaskRepository.LIST_PAGE_MAX:
            effective_limit = TaskRepository.LIST_PAGE_MAX
        effective_offset = max(0, int(offset))

        stmt = select(TaskRecord)
        if auth.role != ROLE_ADMIN:
            stmt = stmt.where(TaskRecord.group_id == auth.role)
        # #53/#36: team-scoped callers see only their team's tasks; a god-tier
        # admin (team_id=None, TEAM-06) is not filtered and sees every team.
        if auth.team_id is not None:
            stmt = stmt.where(TaskRecord.team_id == auth.team_id)
        if track:
            stmt = stmt.where(TaskRecord.track == track)
        if status:
            stmt = stmt.where(TaskRecord.status == status)
        # Newest-first so the dashboard surfaces active / recent work at the
        # top -- without this the running scan is buried behind hundreds of
        # older terminal rows.
        stmt = stmt.order_by(TaskRecord.created_at.desc())  # type: ignore[attr-defined]
        stmt = stmt.limit(effective_limit).offset(effective_offset)
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
        # #53/#36: a team-scoped caller cannot read/transition another team's
        # task; a god-tier admin (team_id=None) is unfiltered.
        if auth.team_id is not None:
            stmt = stmt.where(TaskRecord.team_id == auth.team_id)
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
        # #40-5: enqueue with the fully-qualified ``fn_path``. ARQ's
        # function map is keyed on the qualified registry name
        # (``_Registry.all_functions``); the historical bare
        # ``__qualname__`` would silently miss on any cross-module bare-name
        # collision (CLAUDE.md #19), routing the resumed task id to whichever
        # module was loaded last.
        if not record.fn_path or not record.track:
            _log.warning(
                "set_queued_from_paused: task %s missing fn_path / track -- "
                "leaving PAUSED", task_id,
            )
            return False
        enqueued = await _enqueue_arq_job(
            track=record.track,
            task_id=task_id,
            fn_name=record.fn_path,
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
        """Stage a non-terminal task's CANCELLED transition on ``session``.

        Terminal states -- ``DONE`` / ``FAILED`` / ``CANCELLED`` / ``DEAD_LETTER``
        -- are refused (returns False). ``DEAD_LETTER`` is included because
        dead-lettered tasks are already terminal in the worker's own model
        (see ``worker._TERMINAL_STATUSES``); the previous code omitted it
        (issue #40-3), so dead-lettered rows silently reverted to ``CANCELLED``
        and erased the poison-pill classification.

        Contract (#63): this method DOES NOT commit ``session``. It flushes
        the status flip so the mutation is visible to subsequent reads on
        this session, and returns ``True`` when the transition was staged.
        The caller owns the transaction and MUST issue exactly one commit
        that covers both the task flip and any co-mutated rows in the same
        unit of work. This closes the previous double-commit desync where
        an internal commit here hardened the task's CANCELLED state, then
        the caller's follow-up commit could fail and leave a sibling row
        (e.g. ``InvestigationRunRecord.status``) stuck in RUNNING.

        The ARQ ``in-progress:<task_id>`` key drop is deliberately deferred
        to :meth:`finalize_cancel_side_effects`, which the caller invokes
        AFTER a successful commit. That ordering guarantees the ARQ side-
        effect never fires ahead of a commit that then rolls back.
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
        # Flush so the change is visible to later reads on the same session
        # (e.g. a caller re-selects the row after staging). The caller's
        # commit persists it -- an exception before commit rolls it back.
        await session.flush()
        return True

    @staticmethod
    async def finalize_cancel_side_effects(task_id: str) -> None:
        """Drop the ARQ ``in-progress:<task_id>`` key after a cancel commit.

        The caller invokes this AFTER the commit that flipped the row to
        CANCELLED, so a failed commit does not orphan the worker slot. A
        raising redis client is caught by
        :func:`aila.platform.tasks.queue._drop_arq_in_progress_key` (best-
        effort) and does not surface an error -- the cron reaper reconciles
        orphan keys on its next sweep. When ``AILA_PLATFORM_REDIS_URL`` is
        unset the drop is skipped for the same reason.
        """
        redis_url = _env_redis_url()
        if redis_url:
            await _drop_arq_in_progress_key(task_id, redis_url)
        else:
            _log.debug(
                "finalize_cancel_side_effects: AILA_PLATFORM_REDIS_URL "
                "unset -- arq in-progress key drop skipped for %s (reaper "
                "will reconcile)", task_id,
            )
