"""Tests for AutomationRunner cron correctness (issue #46 -- three coupled fixes).

Covers:

- 46-2 timezone-aware due evaluation: ``AutomationRunner._is_due`` interprets
  the cron expression against the schedule's ``cron_timezone`` (falling
  back to UTC on null / unrecognized names). A schedule cron'd at
  ``0 9 * * *`` fires at 09:00 in that zone, not 09:00 UTC, so two
  schedules with the same last-run instant and the same cron expression
  reach different due states at the same wall-clock ``now`` when their
  ``cron_timezone`` differs.

- 46-4b auto-disable on parse error: when the cron expression or the
  timezone name cannot be parsed, the runner disables the schedule
  (``enabled=False``, ``disable_reason`` populated) instead of raising
  every tick. A subsequent tick sees the row as disabled and skips it.

- 46-6 concurrent-runner guard: the SELECT that claims due schedules
  carries ``FOR UPDATE SKIP LOCKED``. Verified by inspecting the
  compiled statement + the statement's ``_for_update_arg``, since two
  live transactions cannot be forced against the same asyncpg pool
  from inside a unit test without materially reshaping the fixture.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql
from sqlmodel import select

from aila.platform.automation import runner as runner_module
from aila.platform.automation.models import AutomationScheduleRecord
from aila.platform.automation.runner import AutomationRunner
from aila.platform.tasks.models import TaskHandle
from aila.storage.database import async_session_scope

# ---------------------------------------------------------------------------
# 46-6 concurrent-runner guard -- static-only assertions on the compiled SELECT
#
# Kept above the DB-backed tests because the assertion is purely on the
# statement shape; the acceptance criterion is "the due-selection statement
# carries FOR UPDATE SKIP LOCKED", not "two live transactions observe a
# lock race" (which would demand a second asyncpg session inside the
# fixture -- out of scope for a unit test).
# ---------------------------------------------------------------------------


def test_due_schedules_stmt_carries_for_update_skip_locked() -> None:
    """The claim-select MUST carry FOR UPDATE SKIP LOCKED so two runner
    processes ticking at the same instant cannot both grab the same row.

    Without this, two supervisor loops in different processes each fetch
    the full enabled set and each submit a job for the same schedule id;
    TaskQueue dedup catches the exact-input case but not schedules whose
    kwargs vary by call-time metadata.
    """
    stmt = AutomationRunner._due_schedules_stmt()

    for_update_arg = stmt._for_update_arg
    assert for_update_arg is not None, (
        "due-selection stmt has no _for_update_arg -- .with_for_update() "
        "was not chained onto the SELECT"
    )
    assert for_update_arg.skip_locked is True, (
        f"expected skip_locked=True, got {for_update_arg.skip_locked!r} -- "
        "a runner that blocks on the peer's row lock defeats the guard's "
        "point (SKIP means walk past locked rows, not wait on them)"
    )
    assert for_update_arg.read is False, (
        "FOR UPDATE (write intent) required for row-level exclusive lock; "
        "FOR SHARE (read=True) does not serialize the claim"
    )

    compiled = str(stmt.compile(dialect=postgresql.dialect())).upper()
    assert "FOR UPDATE" in compiled, (
        f"compiled SQL missing FOR UPDATE clause: {compiled!r}"
    )
    assert "SKIP LOCKED" in compiled, (
        f"compiled SQL missing SKIP LOCKED clause: {compiled!r}"
    )


def test_due_schedules_stmt_still_filters_enabled_only() -> None:
    """46-6 regression guard: adding FOR UPDATE SKIP LOCKED must not have
    dropped the ``enabled == True`` predicate. A stmt that also grabs
    disabled rows would re-fire schedules the runner auto-disabled in
    the previous tick (interacts with #46-4b).
    """
    compiled = str(
        AutomationRunner._due_schedules_stmt().compile(dialect=postgresql.dialect())
    ).lower()
    # Postgres compiler renders bools as true / false literals.
    assert "enabled = true" in compiled, (
        f"due-selection stmt lost the enabled filter: {compiled!r}"
    )


# ---------------------------------------------------------------------------
# 46-2 timezone-aware due evaluation
#
# No DB required: _is_due is a pure function over an AutomationScheduleRecord
# and a datetime. Non-persisted records exercise the behavior directly and
# keep this suite fast enough to run per-commit without the postgres fixture.
# ---------------------------------------------------------------------------


def _sched(
    *,
    cron_expression: str,
    cron_timezone: str | None,
    last_run_at: datetime | None,
) -> AutomationScheduleRecord:
    """Build a non-persisted schedule for _is_due assertions.

    Only the fields _is_due reads are set explicitly; the rest keep model
    defaults so the record is valid enough to construct without touching
    the DB.
    """
    return AutomationScheduleRecord(
        id=str(uuid.uuid4()),
        action_id="tests.action",
        target_name="tests.target",
        cron_expression=cron_expression,
        cron_timezone=cron_timezone,
        created_by="tests",
        last_run_at=last_run_at,
    )


def test_is_due_null_last_run_at_is_always_due() -> None:
    """First-run schedules stay due regardless of timezone.

    Baseline preserved across the 46-2 rewrite: a schedule that has
    never fired MUST be treated as due so the first tick after creation
    picks it up.
    """
    schedule = _sched(
        cron_expression="0 9 * * *",
        cron_timezone="America/New_York",
        last_run_at=None,
    )
    assert AutomationRunner._is_due(schedule, datetime.now(UTC)) is True


def test_is_due_wall_clock_9am_differs_across_timezones() -> None:
    """The core 46-2 acceptance: same cron, same last-run instant expressed
    as 09:00 in each schedule's local zone, same UTC ``now`` -- but the
    UTC-scoped schedule is due while the New-York-scoped one is not.

    Pre-fix, _is_due ignored cron_timezone and evaluated both as UTC.
    The NY-scoped schedule would have fired 4 hours early every day.

    Timeline:
      last_run for the UTC schedule  = 2026-07-20 09:00 UTC (=09:00 UTC)
      last_run for the NY  schedule  = 2026-07-20 13:00 UTC (=09:00 NY)
      now                            = 2026-07-21 12:00 UTC (=08:00 NY)
      next fire, UTC schedule        = 2026-07-21 09:00 UTC   (<= now -> due)
      next fire, NY  schedule        = 2026-07-21 09:00 NY = 13:00 UTC
                                       (> now                -> NOT due)
    """
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    utc_schedule = _sched(
        cron_expression="0 9 * * *",
        cron_timezone="UTC",
        last_run_at=datetime(2026, 7, 20, 9, 0, tzinfo=UTC),
    )
    ny_schedule = _sched(
        cron_expression="0 9 * * *",
        cron_timezone="America/New_York",
        last_run_at=datetime(2026, 7, 20, 13, 0, tzinfo=UTC),
    )

    assert AutomationRunner._is_due(utc_schedule, now) is True, (
        "UTC-scoped 09:00 cron should fire at 12:00 UTC when last_run "
        "was 09:00 UTC the previous day"
    )
    assert AutomationRunner._is_due(ny_schedule, now) is False, (
        "NY-scoped 09:00 cron must NOT fire at 12:00 UTC (=08:00 NY) "
        "-- 46-2 mandates wall-clock interpretation in the schedule's "
        "cron_timezone, not UTC"
    )


def test_is_due_ny_schedule_becomes_due_at_9am_local() -> None:
    """Follow-through on the NY schedule from the previous test: once the
    UTC clock rolls past 13:00 UTC (=09:00 NY), the NY schedule IS due.
    Confirms the tz-aware evaluation is bidirectional (not merely
    "always defers" for non-UTC zones).
    """
    ny_schedule = _sched(
        cron_expression="0 9 * * *",
        cron_timezone="America/New_York",
        last_run_at=datetime(2026, 7, 20, 13, 0, tzinfo=UTC),
    )
    now = datetime(2026, 7, 21, 13, 30, tzinfo=UTC)  # 09:30 NY
    assert AutomationRunner._is_due(ny_schedule, now) is True


def test_is_due_null_cron_timezone_falls_back_to_utc() -> None:
    """46-2 fallback: a schedule with cron_timezone=None must be evaluated
    as if the zone were UTC (the historical behavior). Prevents the tz
    rewrite from silently changing the fire time of every schedule
    that predates the column.
    """
    schedule = _sched(
        cron_expression="0 9 * * *",
        cron_timezone=None,
        last_run_at=datetime(2026, 7, 20, 9, 0, tzinfo=UTC),
    )
    # 08:30 UTC -- before the next 09:00 UTC fire
    assert AutomationRunner._is_due(
        schedule, datetime(2026, 7, 21, 8, 30, tzinfo=UTC)
    ) is False
    # 09:30 UTC -- after the next 09:00 UTC fire
    assert AutomationRunner._is_due(
        schedule, datetime(2026, 7, 21, 9, 30, tzinfo=UTC)
    ) is True


def test_is_due_unknown_cron_timezone_falls_back_to_utc() -> None:
    """46-2 defensive path: if _is_due is somehow called on a row whose
    cron_timezone is not a valid IANA name (data drift, missing tzdata
    on the host), it must fall back to UTC rather than raising. The
    tick loop catches this earlier and disables the row (#46-4b), so
    this path only fires when _is_due is invoked outside the tick loop
    (tests, admin tooling).
    """
    schedule = _sched(
        cron_expression="0 9 * * *",
        cron_timezone="Not/A/Real/Zone",
        last_run_at=datetime(2026, 7, 20, 9, 0, tzinfo=UTC),
    )
    # Same expectations as the UTC fallback above.
    assert AutomationRunner._is_due(
        schedule, datetime(2026, 7, 21, 8, 30, tzinfo=UTC)
    ) is False
    assert AutomationRunner._is_due(
        schedule, datetime(2026, 7, 21, 9, 30, tzinfo=UTC)
    ) is True


# ---------------------------------------------------------------------------
# 46-4b auto-disable on parse error
#
# DB-backed: exercises the full tick loop against real inserts so the
# enabled flip + disable_reason write is observed the way the runner
# performs it in production.
# ---------------------------------------------------------------------------


class _RecordingQueue:
    """Minimal TaskQueue stand-in modelling only AutomationRunner.tick()'s
    call surface: ``submit(track, fn, kwargs, user_id, team_id) -> TaskHandle``.

    Duplicated here rather than imported from the sibling suite so this
    file stays independently runnable and future refactors of that suite
    do not silently break these tests.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def submit(
        self,
        *,
        track: str,
        fn: Any,
        kwargs: dict[str, Any],
        user_id: str,
        team_id: str | None,
    ) -> TaskHandle:
        self.calls.append(
            {
                "track": track,
                "fn": fn,
                "kwargs": dict(kwargs),
                "user_id": user_id,
                "team_id": team_id,
            }
        )
        return TaskHandle(task_id=f"task-{len(self.calls):04d}")


@dataclass
class _StubAction:
    action_id: str
    module_id: str

    @staticmethod
    def handler_fn(**_kwargs: Any) -> None:
        return None


@dataclass
class _StubRegistry:
    """Registry stand-in returning a stub AutomationAction for any id.

    The unparseable-schedule tests never actually reach the action lookup
    (the parse-failure check runs first and short-circuits with a
    continue), but the runner still constructs a Registry reference at
    __init__, so we hand it a stable stand-in.
    """
    module_id: str = "platform"

    def get_action(self, action_id: str) -> Any:
        return _StubAction(action_id=action_id, module_id=self.module_id)


async def _insert_schedule(
    *,
    cron_expression: str,
    cron_timezone: str | None,
    enabled: bool = True,
) -> str:
    """Insert a single AutomationScheduleRecord and return its id."""
    schedule_id = str(uuid.uuid4())
    async with async_session_scope() as session:
        rec = AutomationScheduleRecord(
            id=schedule_id,
            action_id="platform.alpha",
            target_name="tests.target",
            cron_expression=cron_expression,
            cron_timezone=cron_timezone,
            action_kwargs_json="{}",
            enabled=enabled,
            created_by="tests",
        )
        session.add(rec)
        await session.commit()
    return schedule_id


async def _load_schedule(schedule_id: str) -> AutomationScheduleRecord:
    async with async_session_scope() as session:
        return (await session.exec(
            select(AutomationScheduleRecord)
            .where(AutomationScheduleRecord.id == schedule_id)
        )).one()


@pytest.mark.usefixtures("test_db")
async def test_tick_disables_schedule_with_unparseable_cron() -> None:
    """46-4b: a schedule whose cron expression fails to parse MUST be
    disabled with a non-null disable_reason on the tick that discovers
    it, and the runner MUST NOT raise.

    Pre-fix, ``croniter("not a cron", now)`` raised CroniterNotAlphaError
    inside ``_is_due``. The narrow isolation tuple did not cover it, so
    the tick died and every schedule after the bad row was starved.
    Even a later fix to widen the isolation set would still let the bad
    row re-raise on every subsequent tick, wasting CPU forever.
    """
    queue = _RecordingQueue()
    bad_id = await _insert_schedule(
        cron_expression="this is not a cron expression",
        cron_timezone="UTC",
    )
    good_id = await _insert_schedule(
        cron_expression="* * * * *",
        cron_timezone="UTC",
    )

    runner = AutomationRunner(_StubRegistry(), queue)  # type: ignore[arg-type]

    submitted = await runner.tick()  # MUST NOT raise

    # The good schedule fired; the bad one never reached submit.
    assert submitted == 1
    call_targets = [c["kwargs"]["target_name"] for c in queue.calls]
    assert call_targets == ["tests.target"], (
        f"only the good schedule should reach submit(), got {call_targets!r}"
    )

    bad_row = await _load_schedule(bad_id)
    assert bad_row.enabled is False, (
        "unparseable-cron schedule must be disabled by the tick that "
        "discovers it (finding 46-4b)"
    )
    assert bad_row.disable_reason is not None, (
        "disable_reason must be populated with the cause"
    )
    assert "cron_expression" in bad_row.disable_reason, (
        f"disable_reason should mention the failing field, got "
        f"{bad_row.disable_reason!r}"
    )

    good_row = await _load_schedule(good_id)
    assert good_row.enabled is True
    assert good_row.disable_reason is None


@pytest.mark.usefixtures("test_db")
async def test_tick_disables_schedule_with_unknown_timezone() -> None:
    """46-4b: an unrecognized cron_timezone (typo, missing tzdata) triggers
    the same auto-disable path so the runner does not silently reinterpret
    the schedule against UTC and misfire.

    The defensive ``_is_due`` fallback also uses UTC on bad tz, but that
    is a belt-and-suspenders inside a pure function; the tick loop MUST
    surface the bad configuration to the operator via disable_reason.
    """
    queue = _RecordingQueue()
    bad_id = await _insert_schedule(
        cron_expression="* * * * *",
        cron_timezone="Not/A/Real/Zone",
    )

    runner = AutomationRunner(_StubRegistry(), queue)  # type: ignore[arg-type]

    submitted = await runner.tick()

    assert submitted == 0
    assert queue.calls == [], (
        "submit() must not be called for a bad-tz schedule -- the runner "
        "cannot know when the schedule was intended to fire"
    )

    row = await _load_schedule(bad_id)
    assert row.enabled is False
    assert row.disable_reason is not None
    assert "cron_timezone" in row.disable_reason, (
        f"disable_reason should mention the failing field, got "
        f"{row.disable_reason!r}"
    )


@pytest.mark.usefixtures("test_db")
async def test_next_tick_does_not_reraise_after_auto_disable() -> None:
    """46-4b end-to-end: after the runner disables a malformed schedule,
    the NEXT tick MUST be a clean no-op on that row -- no re-parse, no
    raise, no submit -- because the SELECT filters on enabled=True.

    Without the disable, the same bad cron would raise every tick forever.
    """
    queue = _RecordingQueue()
    bad_id = await _insert_schedule(
        cron_expression="also not a cron",
        cron_timezone="UTC",
    )

    runner = AutomationRunner(_StubRegistry(), queue)  # type: ignore[arg-type]

    # First tick: discovers the bad row, disables it.
    assert await runner.tick() == 0
    disabled_row = await _load_schedule(bad_id)
    assert disabled_row.enabled is False
    assert disabled_row.disable_reason is not None

    # Second tick: the row is no longer selected. No raise, no queue call,
    # no state change on the disabled row.
    original_reason = disabled_row.disable_reason
    original_updated_at = disabled_row.updated_at

    assert await runner.tick() == 0  # MUST NOT raise
    assert queue.calls == []

    still_disabled_row = await _load_schedule(bad_id)
    assert still_disabled_row.enabled is False
    assert still_disabled_row.disable_reason == original_reason, (
        "second tick must not rewrite disable_reason on an already-disabled row"
    )
    assert still_disabled_row.updated_at == original_updated_at, (
        "second tick must not touch updated_at on an already-disabled row"
    )


@pytest.mark.usefixtures("test_db")
async def test_tick_isolates_bad_and_good_schedules_in_same_batch() -> None:
    """46-4b isolation: a bad schedule in the middle of a batch must not
    stop earlier or later good schedules from firing. Guards the
    ordering of the classify-then-continue path in the tick loop --
    a `raise` where a `continue` belongs would starve the tail of the batch.
    """
    queue = _RecordingQueue()
    good_before_id = await _insert_schedule(
        cron_expression="* * * * *", cron_timezone="UTC"
    )
    bad_id = await _insert_schedule(
        cron_expression="totally bogus", cron_timezone="UTC"
    )
    good_after_id = await _insert_schedule(
        cron_expression="* * * * *", cron_timezone="UTC"
    )

    runner = AutomationRunner(_StubRegistry(), queue)  # type: ignore[arg-type]
    submitted = await runner.tick()

    assert submitted == 2
    assert len(queue.calls) == 2

    bad_row = await _load_schedule(bad_id)
    assert bad_row.enabled is False
    assert bad_row.disable_reason is not None

    for good_id in (good_before_id, good_after_id):
        row = await _load_schedule(good_id)
        assert row.enabled is True
        assert row.disable_reason is None
        assert row.last_run_result is not None
        assert row.last_run_result.startswith("submitted:"), (
            f"good schedule {good_id} did not reach submit -- bad row "
            "in the same batch swallowed it"
        )


@pytest.mark.usefixtures("test_db")
async def test_tick_respects_cron_timezone_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """46-2 through the real tick loop: two schedules with the same cron
    and the same last_run_at differ in due-ness ONLY because their
    ``cron_timezone`` differs. Proves the tick path actually passes the
    schedule (with its tz) into ``_is_due`` -- not just that ``_is_due``
    unit-tests are green.

    Freezes the runner's notion of ``now`` by monkeypatching
    ``aila.platform.automation.runner.datetime`` so the assertion does
    not race against wall-clock. Both schedules fired at
    ``2026-07-20 09:00 UTC`` a day ago; ``now`` is fixed at
    ``2026-07-21 12:00 UTC`` (=08:00 NY today, before its 09:00 local
    fire). Only the UTC schedule's next fire (09:00 UTC today) is
    already in the past.
    """
    frozen_now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)

    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]
            return frozen_now if tz is None else frozen_now.astimezone(tz)

    monkeypatch.setattr(runner_module, "datetime", _FrozenDatetime)

    queue = _RecordingQueue()

    # Both schedules last fired at 09:00 local on 2026-07-20:
    #   UTC schedule: 2026-07-20 09:00 UTC
    #   NY schedule : 2026-07-20 13:00 UTC (=09:00 NY, DST)
    # frozen_now = 2026-07-21 12:00 UTC (=08:00 NY today).
    # UTC schedule next fire = 2026-07-21 09:00 UTC   -> in the past   -> DUE
    # NY  schedule next fire = 2026-07-21 09:00 NY = 13:00 UTC -> future -> NOT due
    async with async_session_scope() as session:
        session.add(
            AutomationScheduleRecord(
                id="utc-sched",
                action_id="platform.alpha",
                target_name="utc-target",
                cron_expression="0 9 * * *",
                cron_timezone="UTC",
                action_kwargs_json="{}",
                enabled=True,
                created_by="tests",
                last_run_at=datetime(2026, 7, 20, 9, 0, tzinfo=UTC),
            )
        )
        session.add(
            AutomationScheduleRecord(
                id="ny-sched",
                action_id="platform.alpha",
                target_name="ny-target",
                cron_expression="0 9 * * *",
                cron_timezone="America/New_York",
                action_kwargs_json="{}",
                enabled=True,
                created_by="tests",
                last_run_at=datetime(2026, 7, 20, 13, 0, tzinfo=UTC),
            )
        )
        await session.commit()

    runner = AutomationRunner(_StubRegistry(), queue)  # type: ignore[arg-type]
    submitted = await runner.tick()

    # Exactly one schedule (the UTC one) fired.
    assert submitted == 1
    call_targets = [c["kwargs"]["target_name"] for c in queue.calls]
    assert call_targets == ["utc-target"], (
        f"only utc-target should have fired, got {call_targets!r} -- "
        "46-2 tz interpretation is broken if ny-target also fires here"
    )

    utc_row = await _load_schedule("utc-sched")
    ny_row = await _load_schedule("ny-sched")
    assert utc_row.last_run_result is not None
    assert utc_row.last_run_result.startswith("submitted:")
    # ny_row must be untouched -- its last_run_at stays at the seed.
    assert ny_row.last_run_result is None
    assert ny_row.last_run_at == datetime(2026, 7, 20, 13, 0, tzinfo=UTC)
