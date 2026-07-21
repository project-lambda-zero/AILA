"""Automation runner -- evaluates cron schedules and submits via TaskQueue.

AutomationRunner.tick() is the main entry point: it fetches all enabled
AutomationScheduleRecords, checks each against its cron expression using
croniter, and submits due jobs through the platform TaskQueue.

Called by: CLI command or periodic trigger (e.g., ARQ cron job).
Depends on: AutomationRegistry (action resolution), TaskQueue (job submission).
"""
from __future__ import annotations

__all__ = ["AutomationRunner"]

import asyncio
import json
import logging
from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import sqlalchemy.exc
from croniter import CroniterError, croniter
from sqlmodel import select
from sqlmodel.sql.expression import SelectOfScalar

from aila.platform.automation.models import AutomationScheduleRecord
from aila.platform.automation.registry import AutomationRegistry
from aila.platform.exceptions import AILAError
from aila.platform.tasks.queue import TaskQueue
from aila.storage.database import async_session_scope

_DEFAULT_TIMEZONE_NAME = "UTC"
_UTC_ZONE = ZoneInfo(_DEFAULT_TIMEZONE_NAME)
_DISABLE_REASON_MAX = 512  # keep disable_reason short so it fits any operator-facing display

# Exception types that indicate a schedule cannot be parsed and MUST be
# auto-disabled (#46-4b) rather than raised on every tick. CroniterError is
# already a ValueError, but we list it explicitly so a reader can see the
# intent; ZoneInfoNotFoundError is a KeyError, listed for the same reason.
_SCHEDULE_PARSE_ERRORS: tuple[type[BaseException], ...] = (
    CroniterError,
    ZoneInfoNotFoundError,
    ValueError,
    KeyError,
)

_log = logging.getLogger(__name__)


# Finding 46-4: per-schedule isolation tuple. Mirrors the emitter's
# _DESTINATION_ISOLATION_ERRORS (platform/events/emitter.py): any
# subclass of Exception a schedule handler / submit path might
# reasonably raise is caught so later schedules in the same tick are
# still processed. BaseException-only subclasses (KeyboardInterrupt,
# SystemExit, asyncio.CancelledError) intentionally propagate -- the
# process is going down and the tick must not swallow that.
_SCHEDULE_ISOLATION_ERRORS: tuple[type[BaseException], ...] = (
    AILAError,
    sqlalchemy.exc.SQLAlchemyError,
    RuntimeError,
    OSError,
    TimeoutError,
    ValueError,
    TypeError,
    AttributeError,
    KeyError,
    IndexError,
    LookupError,
    ArithmeticError,
    ImportError,
    AssertionError,
    ReferenceError,
)


class AutomationRunner:
    """Evaluate enabled automation schedules and submit due jobs.

    The runner is stateless between tick() calls -- all state lives in the
    database (AutomationScheduleRecord.last_run_at). This makes it safe
    to call tick() from multiple processes without double-firing, since
    TaskQueue dedup (SEC-07) catches identical submissions.

    Finding 46-3 (overlap guard): concurrent tick() calls on the same
    runner instance are serialized via an asyncio.Lock. A tick that finds
    the lock already held returns 0 immediately rather than queueing --
    the goal is to skip a redundant scan while an in-progress tick is
    still walking the schedule list, not to block the caller (the
    supervisor loop wakes on a fixed cadence; blocked ticks would just
    stack up).

    Finding 46-3 (ordering): last_run_at is now written BEFORE the
    TaskQueue.submit() call. A crash between the claim and the submit
    marks the schedule as fired for this cycle with last_run_result
    "error"; the cron cadence resumes on the next tick. This trades
    at-most-once semantics on submit failure for the previous
    at-least-twice pathology (slow submit + next tick + same row still
    marked not-yet-run -> two ARQ jobs for one intended fire).
    """

    def __init__(self, registry: AutomationRegistry, task_queue: TaskQueue) -> None:
        self._registry = registry
        self._queue = task_queue
        # Guards concurrent tick() invocations on the same runner instance
        # (finding 46-3). Created lazily so the runner can be constructed
        # outside an event loop (asyncio.Lock binds to the running loop
        # only when first acquired, so lazy construction avoids the
        # "attached to a different loop" trap when tests instantiate a
        # runner per test-loop).
        self._tick_lock: asyncio.Lock | None = None

    async def tick(self) -> int:
        """Evaluate all enabled schedules. Return count of jobs submitted.

        If a previous tick() on this runner is still executing, this call
        returns 0 without touching the database (finding 46-3 overlap
        guard).
        """
        if self._tick_lock is None:
            self._tick_lock = asyncio.Lock()
        if self._tick_lock.locked():
            _log.info(
                "automation tick already in progress; skipping overlapping invocation"
            )
            return 0
        async with self._tick_lock:
            return await self._tick_locked()

    async def _tick_locked(self) -> int:
        """Do the actual per-schedule evaluation under the tick lock."""
        now = datetime.now(UTC)
        submitted = 0

        async with async_session_scope() as session:
            schedules = (await session.exec(self._due_schedules_stmt())).all()

        for schedule in schedules:
            # Finding 46-4b: catch unparseable cron / bad timezone up front
            # and disable the row so the next tick does not raise on the
            # same bad data. The disable is best-effort: if the DB write
            # itself fails we log and skip so one broken row cannot stop
            # the tick from processing the rest.
            disable_reason = self._classify_parse_failure(schedule)
            if disable_reason is not None:
                _log.warning(
                    "Auto-disabling automation schedule %s: %s",
                    schedule.id, disable_reason,
                )
                try:
                    await self._disable_schedule(schedule.id, disable_reason, now)
                except sqlalchemy.exc.SQLAlchemyError:
                    _log.exception(
                        "Failed to persist auto-disable for schedule %s",
                        schedule.id,
                    )
                continue

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

                # Finding 46-3 ordering: claim the schedule by writing
                # last_run_at BEFORE submit. A crash / slow submit
                # between here and the queue write no longer lets the
                # next tick re-fire the same schedule. The result is
                # written as "pending" first and rewritten to
                # "submitted:<task_id>" after the submit returns.
                await self._write_schedule_state(
                    schedule.id,
                    last_run_at=now,
                    last_run_result="pending",
                    updated_at=now,
                )

                handle = await self._queue.submit(
                    track=action.module_id,
                    fn=action.handler_fn,
                    kwargs=kwargs,
                    user_id=schedule.created_by,
                    team_id=schedule.team_id,
                )

                # Rewrite last_run_result now that the submit succeeded.
                # last_run_at stays at the value written above (single
                # timestamp per firing decision).
                await self._write_schedule_state(
                    schedule.id,
                    last_run_at=now,
                    last_run_result=f"submitted:{handle.task_id}",
                    updated_at=now,
                )

                submitted += 1
                _log.info(
                    "Automation fired: schedule=%s action=%s task=%s",
                    schedule.id, schedule.action_id, handle.task_id,
                )
            except _SCHEDULE_ISOLATION_ERRORS:
                # Finding 46-4: isolate one schedule's failure so later
                # schedules in the same tick are still processed. The
                # isolation tuple mirrors the emitter destination
                # isolation set; KeyboardInterrupt / SystemExit /
                # asyncio.CancelledError propagate on purpose so the
                # process still exits cleanly on shutdown.
                _log.exception(
                    "Failed to submit automation schedule %s -- continuing with next schedule",
                    schedule.id,
                )
                try:
                    await self._write_schedule_state(
                        schedule.id,
                        last_run_at=now,
                        last_run_result="error",
                        updated_at=now,
                    )
                except sqlalchemy.exc.SQLAlchemyError:
                    _log.debug(
                        "Failed to update error status for schedule %s",
                        schedule.id,
                    )

        return submitted

    @staticmethod
    async def _write_schedule_state(
        schedule_id: str,
        *,
        last_run_at: datetime,
        last_run_result: str,
        updated_at: datetime,
    ) -> None:
        """Persist last_run_at / last_run_result / updated_at for one schedule.

        Extracted so the claim (before submit) and the finalization (after
        submit) share a single transaction shape. Raises SQLAlchemyError on
        DB failure; callers decide whether to swallow (error-path best
        effort) or propagate (claim-path is inside the try body so an
        exception routes through the isolation guard).
        """
        async with async_session_scope() as session:
            rec = (await session.exec(
                select(AutomationScheduleRecord)
                .where(AutomationScheduleRecord.id == schedule_id)
            )).one()
            rec.last_run_at = last_run_at
            rec.last_run_result = last_run_result
            rec.updated_at = updated_at
            session.add(rec)
            await session.commit()

    @staticmethod
    def _due_schedules_stmt() -> SelectOfScalar[AutomationScheduleRecord]:
        """Build the SELECT that claims due schedules for this tick.

        Finding 46-6: adds ``FOR UPDATE SKIP LOCKED`` so two runner
        processes ticking at the same instant cannot double-fire the
        same row. Rows a peer runner already holds a row lock on are
        silently skipped for the duration of that peer's transaction;
        TaskQueue dedup (SEC-07) is the final backstop.
        """
        return (
            select(AutomationScheduleRecord)
            .where(AutomationScheduleRecord.enabled == True)
            .with_for_update(skip_locked=True)
        )

    @staticmethod
    def _resolve_timezone(name: str | None) -> ZoneInfo:
        """Return the ZoneInfo for ``name``, falling back to UTC on null / bad input.

        Finding 46-2 defensive fallback: an unrecognized IANA name (data
        drift, typo, missing tzdata) becomes UTC here so ``_is_due``
        stays total. The tick loop's ``_classify_parse_failure`` catches
        the same condition earlier and disables the row (#46-4b); this
        method is the belt inside the suspenders.
        """
        if not name:
            return _UTC_ZONE
        try:
            return ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError):
            return _UTC_ZONE

    @staticmethod
    def _classify_parse_failure(schedule: AutomationScheduleRecord) -> str | None:
        """Return a short disable reason when the schedule cannot be parsed.

        Finding 46-4b: instead of letting a malformed schedule raise on
        every tick forever, the runner disables the row and records the
        cause. Two conditions trigger a disable:

        1. ``cron_timezone`` is a non-empty string that is not a
           recognized IANA zone (ZoneInfo lookup raises).
        2. ``cron_expression`` does not parse under croniter against
           the (validated) timezone.

        Returns None when both fields parse cleanly. The returned string
        is length-capped so the column stays readable in operator UIs.
        """
        tz_name = schedule.cron_timezone
        if tz_name:
            try:
                tz = ZoneInfo(tz_name)
            except _SCHEDULE_PARSE_ERRORS as exc:
                return AutomationRunner._short_reason(
                    f"invalid cron_timezone {tz_name!r}: {exc}"
                )
        else:
            tz = _UTC_ZONE

        reference = schedule.last_run_at or datetime.now(tz)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=tz)
        else:
            reference = reference.astimezone(tz)

        try:
            croniter(schedule.cron_expression, reference)
        except _SCHEDULE_PARSE_ERRORS as exc:
            return AutomationRunner._short_reason(
                f"invalid cron_expression {schedule.cron_expression!r}: {exc}"
            )
        return None

    @staticmethod
    def _short_reason(text: str) -> str:
        """Truncate a disable reason to _DISABLE_REASON_MAX so the row stays readable."""
        if len(text) <= _DISABLE_REASON_MAX:
            return text
        return text[: _DISABLE_REASON_MAX - 3] + "..."

    @staticmethod
    async def _disable_schedule(
        schedule_id: str,
        reason: str,
        now: datetime,
    ) -> None:
        """Persist enabled=False + disable_reason for a malformed schedule (#46-4b).

        Kept parallel to ``_write_schedule_state`` so the two DB write
        paths in this file share the same session shape. Raises
        SQLAlchemyError on failure; the tick loop catches it and moves
        on to the next schedule.
        """
        async with async_session_scope() as session:
            rec = (await session.exec(
                select(AutomationScheduleRecord)
                .where(AutomationScheduleRecord.id == schedule_id)
            )).one()
            rec.enabled = False
            rec.disable_reason = reason
            rec.updated_at = now
            session.add(rec)
            await session.commit()

    @staticmethod
    def _is_due(schedule: AutomationScheduleRecord, now: datetime) -> bool:
        """Check whether a schedule should fire based on its cron expression.

        A schedule with no last_run_at is always due (first run).
        Otherwise, the cron expression is evaluated against the
        schedule's ``cron_timezone`` (defaulting to UTC when null /
        unrecognized -- see ``_resolve_timezone``): croniter computes
        the next fire time after ``last_run_at`` in that zone and the
        result is compared against ``now`` converted to the same zone.

        Finding 46-2: interpreting the cron expression against a
        wall-clock timezone lets ``0 9 * * *`` mean 9 AM local rather
        than 9 AM UTC. Assumes the schedule has already passed
        ``_classify_parse_failure``; callers outside the tick loop that
        might hand a malformed row still get UTC + a croniter raise
        rather than silent misfires.
        """
        if schedule.last_run_at is None:
            return True
        tz = AutomationRunner._resolve_timezone(schedule.cron_timezone)
        last_run_local = schedule.last_run_at.astimezone(tz)
        cron = croniter(schedule.cron_expression, last_run_local)
        next_fire = cron.get_next(datetime)
        if next_fire.tzinfo is None:
            next_fire = next_fire.replace(tzinfo=tz)
        return next_fire <= now.astimezone(tz)
