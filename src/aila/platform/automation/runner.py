"""Automation runner -- evaluates cron schedules and submits via TaskQueue.

AutomationRunner.tick() is the main entry point: it fetches all enabled
AutomationScheduleRecords, checks each against its cron expression using
croniter, and submits due jobs through the platform TaskQueue.

Called by: CLI command or periodic trigger (e.g., ARQ cron job).
Depends on: AutomationRegistry (action resolution), TaskQueue (job submission).

Issue #46 cross-process safety (added 2026-07-27): each due occurrence
is guarded by a distributed lock (``platform/automation/lock.py``,
Redis SET NX PX) AND recorded in ``automation_run_records`` with a
``UNIQUE(schedule_id, occurrence_at)`` constraint. The lock is the
fast path; the DB unique constraint is the second-order backstop that
kicks in when Redis is unavailable so exactly one runner process
executes any given occurrence regardless of worker replica count.
"""
from __future__ import annotations

__all__ = ["AutomationRunner"]

import asyncio
import json
import logging
import os
import socket
import uuid
from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import sqlalchemy.exc
from croniter import CroniterError, croniter
from sqlmodel import select
from sqlmodel.sql.expression import SelectOfScalar

from aila.platform.automation.lock import (
    AutomationOccurrenceLock,
    LockBackendUnavailableError,
    acquire_occurrence_lock,
    release_occurrence_lock,
)
from aila.platform.automation.models import (
    AutomationRunRecord,
    AutomationScheduleRecord,
)
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

    The runner is stateless between tick() calls -- all state lives in
    the database (AutomationScheduleRecord.last_run_at plus the
    per-occurrence AutomationRunRecord rows).

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

    Issue #46 cross-process exactly-once: two runner processes ticking
    the same schedule at the same wall-clock instant would each pass
    the intra-process overlap guard AND the same-transaction
    ``SELECT ... FOR UPDATE SKIP LOCKED`` (that row-lock is only held
    for the duration of the SELECT). Each due occurrence is therefore
    guarded by two layers:

      1. Redis ``SET NX PX`` on ``automation:lock:{schedule}:{epoch}``
         (``platform/automation/lock.py``) -- the fast path.
      2. ``UNIQUE(schedule_id, occurrence_at)`` on the
         ``automation_run_records`` row inserted at run start -- the
         backstop that also serves as run-history and takes over when
         the Redis backend is unavailable (documented degrade path).

    Every attempted execution writes an ``AutomationRunRecord`` with
    ``started_at`` / ``finished_at`` / ``outcome`` so a missed or
    duplicated run is observable.
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
        # Stable per-process identifier stamped on every run-record so an
        # operator inspecting automation_run_records can tell WHICH
        # replica served a given occurrence. hostname:pid:uuid8 is
        # unique across replicas AND across restarts.
        self._runner_id: str = (
            f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        )

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

            # Issue #46: compute a stable occurrence bucket so two
            # runners racing on the same tick derive the same lock key
            # AND the same UNIQUE(schedule_id, occurrence_at) row. The
            # bucket is the last cron-scheduled instant at or before
            # now; both racing processes see the same value as long as
            # their clocks agree to within one cron tick.
            occurrence_at = self._occurrence_bucket(schedule, now)

            # First barrier: Redis SET NX PX. Winner proceeds; loser
            # skips silently (the peer that holds the lock is running
            # this occurrence). LockBackendUnavailable is the documented
            # degrade path -- we fall through to the DB-level unique
            # constraint on automation_run_records as the second barrier.
            lock_handle: AutomationOccurrenceLock | None = None
            lock_backend_up = True
            try:
                lock_handle = await acquire_occurrence_lock(
                    schedule.id, occurrence_at,
                )
            except LockBackendUnavailableError as exc:
                lock_backend_up = False
                _log.info(
                    "automation lock backend unavailable for schedule=%s occurrence=%s: %s -- "
                    "degrading to automation_run_records unique-constraint claim",
                    schedule.id, occurrence_at.isoformat(), exc,
                )

            if lock_backend_up and lock_handle is None:
                # Peer runner holds the occurrence lock. The peer will
                # write the run-record; nothing to do here.
                _log.info(
                    "automation occurrence held by peer -- skipping schedule=%s occurrence=%s",
                    schedule.id, occurrence_at.isoformat(),
                )
                continue

            # Second barrier: INSERT into automation_run_records. The
            # UNIQUE(schedule_id, occurrence_at) constraint means the
            # race resolves atomically at the DB level even when the
            # Redis lock was unavailable. Loser sees IntegrityError and
            # skips this occurrence.
            try:
                run_record_id = await self._start_run_record(
                    schedule.id, occurrence_at, now,
                )
            except sqlalchemy.exc.IntegrityError:
                _log.info(
                    "automation occurrence already claimed in run-history -- skipping "
                    "schedule=%s occurrence=%s (peer INSERT won the unique-constraint race)",
                    schedule.id, occurrence_at.isoformat(),
                )
                if lock_handle is not None:
                    await release_occurrence_lock(lock_handle)
                continue
            except sqlalchemy.exc.SQLAlchemyError:
                # A non-integrity DB error at run-record insert is a
                # genuine failure of the storage layer; log and skip the
                # occurrence so the tick keeps processing later
                # schedules (finding 46-4 isolation shape).
                _log.exception(
                    "Failed to insert automation_run_records row for schedule=%s occurrence=%s",
                    schedule.id, occurrence_at.isoformat(),
                )
                if lock_handle is not None:
                    await release_occurrence_lock(lock_handle)
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

                await self._finish_run_record(
                    run_record_id,
                    outcome=f"submitted:{handle.task_id}",
                    task_id=handle.task_id,
                )

                submitted += 1
                _log.info(
                    "Automation fired: schedule=%s action=%s task=%s",
                    schedule.id, schedule.action_id, handle.task_id,
                )
            except _SCHEDULE_ISOLATION_ERRORS as exc:
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
                # Record the failure on the run-history row so a missed
                # execution is observable even when the schedule row's
                # last_run_result was clobbered by a peer's later fire.
                try:
                    await self._finish_run_record(
                        run_record_id,
                        outcome=f"error:{type(exc).__name__}",
                        task_id=None,
                    )
                except sqlalchemy.exc.SQLAlchemyError:
                    _log.debug(
                        "Failed to finalize error run-history row for schedule %s",
                        schedule.id,
                    )
            finally:
                if lock_handle is not None:
                    await release_occurrence_lock(lock_handle)

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

    async def _start_run_record(
        self,
        schedule_id: str,
        occurrence_at: datetime,
        started_at: datetime,
    ) -> str:
        """Insert the run-history row that claims this occurrence.

        Raises ``IntegrityError`` when a peer runner has already
        inserted a row for the same ``(schedule_id, occurrence_at)``
        tuple -- the caller treats that as "another process owns this
        occurrence, skip". Returns the new row's id on success so the
        caller can pass it to ``_finish_run_record`` when the submit
        completes.
        """
        record = AutomationRunRecord(
            schedule_id=schedule_id,
            occurrence_at=occurrence_at,
            started_at=started_at,
            outcome="running",
            runner_id=self._runner_id,
        )
        async with async_session_scope() as session:
            session.add(record)
            # The commit is where a UNIQUE(schedule_id, occurrence_at)
            # collision surfaces as IntegrityError; the caller catches
            # it and skips the occurrence.
            await session.commit()
        return record.id

    @staticmethod
    async def _finish_run_record(
        run_record_id: str,
        *,
        outcome: str,
        task_id: str | None,
    ) -> None:
        """Finalize a run-history row with finished_at + outcome + task_id.

        Raises SQLAlchemyError on DB failure; callers decide whether to
        propagate or swallow. Not a staticmethod on purpose -- callers
        can pass ``self._finish_run_record`` as a bound method to future
        helpers without capturing a wrapping ``lambda``.
        """
        async with async_session_scope() as session:
            rec = (await session.exec(
                select(AutomationRunRecord)
                .where(AutomationRunRecord.id == run_record_id)
            )).one()
            rec.finished_at = datetime.now(UTC)
            rec.outcome = outcome
            rec.task_id = task_id
            session.add(rec)
            await session.commit()

    @staticmethod
    def _occurrence_bucket(
        schedule: AutomationScheduleRecord, now: datetime,
    ) -> datetime:
        """Return the last cron-scheduled instant at or before ``now`` in UTC.

        Two runner processes that call ``tick()`` at the same wall-clock
        instant MUST derive the same bucket so the distributed lock key
        AND the ``UNIQUE(schedule_id, occurrence_at)`` row collide
        instead of appearing to be distinct occurrences. ``get_prev`` on
        the schedule's timezone-adjusted ``now`` gives that guarantee
        without depending on the schedule's own ``last_run_at`` (which
        the winner may already have advanced by the time the loser
        reads it).

        Falls back to ``now`` if croniter cannot compute a previous fire
        for any reason -- the classify-parse-failure guard above the
        due-check already disables malformed schedules, so this is
        belt-and-suspenders for a cron that somehow parses but has no
        past.
        """
        tz = AutomationRunner._resolve_timezone(schedule.cron_timezone)
        now_local = now.astimezone(tz)
        try:
            cron = croniter(schedule.cron_expression, now_local)
            prev_fire = cron.get_prev(datetime)
        except _SCHEDULE_PARSE_ERRORS:
            # A cron that parsed at classify time but fails get_prev
            # (extremely unusual, e.g. an intentionally empty schedule)
            # gets bucketed to ``now`` -- that keeps the lock key
            # stable within one tick without pretending the schedule
            # has a past.
            return now.astimezone(UTC)
        if prev_fire.tzinfo is None:
            prev_fire = prev_fire.replace(tzinfo=tz)
        return prev_fire.astimezone(UTC)

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
