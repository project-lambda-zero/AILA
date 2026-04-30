"""Automation runner -- evaluates cron schedules and submits via TaskQueue.

AutomationRunner.tick() is the main entry point: it fetches all enabled
AutomationScheduleRecords, checks each against its cron expression using
croniter, and submits due jobs through the platform TaskQueue.

Called by: CLI command or periodic trigger (e.g., ARQ cron job).
Depends on: AutomationRegistry (action resolution), TaskQueue (job submission).
"""
from __future__ import annotations

__all__ = ["AutomationRunner"]

import json
import logging
from datetime import datetime, timezone

from croniter import croniter
from sqlmodel import select

import sqlalchemy.exc

from aila.platform.automation.models import AutomationScheduleRecord
from aila.platform.automation.registry import AutomationRegistry
from aila.platform.contracts._common import utc_now
from aila.platform.exceptions import AILAError
from aila.platform.tasks.queue import TaskQueue
from aila.storage.database import async_session_scope

_log = logging.getLogger(__name__)


class AutomationRunner:
    """Evaluate enabled automation schedules and submit due jobs.

    The runner is stateless between tick() calls -- all state lives in the
    database (AutomationScheduleRecord.last_run_at). This makes it safe
    to call tick() from multiple processes without double-firing, since
    TaskQueue dedup (SEC-07) catches identical submissions.
    """

    def __init__(self, registry: AutomationRegistry, task_queue: TaskQueue) -> None:
        self._registry = registry
        self._queue = task_queue

    async def tick(self) -> int:
        """Evaluate all enabled schedules. Return count of jobs submitted."""
        now = datetime.now(timezone.utc)
        submitted = 0

        async with async_session_scope() as session:
            schedules = (await session.exec(
                select(AutomationScheduleRecord)
                .where(AutomationScheduleRecord.enabled == True)
            )).all()

        for schedule in schedules:
            if not self._is_due(schedule, now):
                continue

            action = self._registry.get_action(schedule.action_id)
            if action is None:
                _log.warning(
                    "Schedule %s references unknown action %r -- skipping",
                    schedule.id, schedule.action_id,
                )
                continue

            try:
                kwargs = json.loads(schedule.action_kwargs_json)
                kwargs["target_name"] = schedule.target_name

                handle = await self._queue.submit(
                    track=action.module_id,
                    fn=action.handler_fn,
                    kwargs=kwargs,
                    user_id=schedule.created_by,
                    team_id=schedule.team_id,
                )

                # Update last_run metadata
                async with async_session_scope() as session:
                    rec = (await session.exec(
                        select(AutomationScheduleRecord)
                        .where(AutomationScheduleRecord.id == schedule.id)
                    )).one()
                    rec.last_run_at = now
                    rec.last_run_result = f"submitted:{handle.task_id}"
                    rec.updated_at = now
                    session.add(rec)
                    await session.commit()

                submitted += 1
                _log.info(
                    "Automation fired: schedule=%s action=%s task=%s",
                    schedule.id, schedule.action_id, handle.task_id,
                )
            except (AILAError, sqlalchemy.exc.SQLAlchemyError):
                _log.exception("Failed to submit automation schedule %s", schedule.id)
                try:
                    async with async_session_scope() as session:
                        rec = (await session.exec(
                            select(AutomationScheduleRecord)
                            .where(AutomationScheduleRecord.id == schedule.id)
                        )).one()
                        rec.last_run_at = now
                        rec.last_run_result = "error"
                        rec.updated_at = now
                        session.add(rec)
                        await session.commit()
                except sqlalchemy.exc.SQLAlchemyError:
                    _log.debug(
                        "Failed to update error status for schedule %s",
                        schedule.id,
                    )

        return submitted

    @staticmethod
    def _is_due(schedule: AutomationScheduleRecord, now: datetime) -> bool:
        """Check whether a schedule should fire based on its cron expression.

        A schedule with no last_run_at is always due (first run). Otherwise,
        croniter computes the next fire time after last_run_at and compares
        against now.
        """
        if schedule.last_run_at is None:
            return True
        cron = croniter(schedule.cron_expression, schedule.last_run_at)
        next_fire = cron.get_next(datetime)
        return next_fire <= now
