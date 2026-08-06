"""Tests for AutomationRunner + AutomationRegistry hardening.

Covers findings from `.run/designs/DESIGN_automation_events_reporting.md` #46:

- 46-3 overlap guard: concurrent tick() invocations serialize; the second
  returns 0 without touching the database.
- 46-3 ordering: last_run_at is claimed BEFORE the queue submit, so a
  submit failure marks the schedule as fired (with result "error") for
  this cron cycle instead of letting the next tick re-fire the same row.
- 46-4 per-schedule isolation: a handler / submit path that raises
  RuntimeError (or any other member of the broadened isolation tuple)
  does not stop later schedules in the same tick from being processed.
- 46-8 registry thread-safety: register_action is atomic under concurrent
  callers, and list_actions returns a stable snapshot even when
  register_action is running in parallel.
"""
from __future__ import annotations

import asyncio
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlmodel import select

from aila.platform.automation.models import AutomationScheduleRecord
from aila.platform.automation.registry import AutomationRegistry
from aila.platform.automation.runner import AutomationRunner
from aila.platform.tasks.models import TaskHandle
from aila.storage.database import async_session_scope

# ---------------------------------------------------------------------------
# 46-8 -- AutomationRegistry thread-safety
# ---------------------------------------------------------------------------


def _noop_handler(**_kwargs: Any) -> None:
    """Handler stub used as a stand-in callable in registry tests."""
    return None


def test_register_action_rejects_duplicate_in_single_thread() -> None:
    """Baseline: register_action is still ValueError on a same-thread duplicate."""
    reg = AutomationRegistry()
    reg.register_action(
        action_id="tests.dup",
        handler_fn=_noop_handler,
        description="first",
        module_id="tests",
    )
    with pytest.raises(ValueError, match="Duplicate automation action"):
        reg.register_action(
            action_id="tests.dup",
            handler_fn=_noop_handler,
            description="second",
            module_id="tests",
        )


def test_register_action_is_atomic_under_concurrent_callers() -> None:
    """46-8: N threads racing register_action on the same id produce exactly
    one success and N-1 ValueErrors.

    Without the lock, the check-then-set inside register_action can let
    multiple threads pass the `action_id in self._actions` guard and each
    proceed to overwrite the previous insertion. Because the winner would
    be whichever thread commits last, the surviving action's description
    would be non-deterministic AND no thread would see the ValueError that
    duplicate registration is documented to raise.
    """
    reg = AutomationRegistry()
    thread_count = 24
    barrier = threading.Barrier(thread_count)
    errors: list[BaseException] = []
    successes: list[str] = []
    lock = threading.Lock()

    def _worker(tag: str) -> None:
        barrier.wait()
        try:
            reg.register_action(
                action_id="tests.race",
                handler_fn=_noop_handler,
                description=tag,
                module_id="tests",
            )
        except ValueError as exc:
            with lock:
                errors.append(exc)
        else:
            with lock:
                successes.append(tag)

    threads = [
        threading.Thread(target=_worker, args=(f"caller-{i}",), name=f"reg-{i}")
        for i in range(thread_count)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    # Exactly one thread inserted; every other thread saw ValueError.
    assert len(successes) == 1, (
        f"expected exactly one winner, got {len(successes)}: {successes!r}"
    )
    assert len(errors) == thread_count - 1
    # The action stored is the one the winning thread inserted.
    stored = reg.require_action("tests.race")
    assert stored.description == successes[0]


def test_list_actions_returns_stable_snapshot_under_concurrent_writes() -> None:
    """46-8: list_actions never raises RuntimeError('dictionary changed size
    during iteration') while a concurrent thread is calling register_action.

    Without the lock, `list(self._actions.values())` iterates the live dict
    view; a concurrent insert during that iteration raises RuntimeError.
    With the lock, the snapshot is taken atomically and sort() runs on a
    plain list that no one else touches.
    """
    reg = AutomationRegistry()
    # Prime with a few actions so list_actions has real work to do.
    for i in range(50):
        reg.register_action(
            action_id=f"tests.seed.{i:03d}",
            handler_fn=_noop_handler,
            description=f"seed-{i}",
            module_id="tests",
        )

    stop = threading.Event()
    writer_errors: list[BaseException] = []
    reader_errors: list[BaseException] = []

    def _writer() -> None:
        i = 0
        while not stop.is_set():
            try:
                reg.register_action(
                    action_id=f"tests.concurrent.{i:06d}",
                    handler_fn=_noop_handler,
                    description=f"w{i}",
                    module_id="tests",
                )
            except ValueError:
                # Same id twice from the same writer -- benign, not the
                # race under test.
                pass
            except RuntimeError as exc:
                # RuntimeError('dict changed size during iteration') from
                # an internal race is the exact failure mode 46-8 fixes;
                # stash for the main-thread assertion.
                writer_errors.append(exc)
                return
            i += 1

    def _reader() -> None:
        for _ in range(200):
            try:
                snapshot = reg.list_actions()
            except RuntimeError as exc:
                # RuntimeError('dictionary changed size during iteration')
                # is precisely the observable race the lock closes. Any
                # other exception type would indicate an unrelated bug;
                # let it propagate so the thread dies loudly rather than
                # masking the real failure.
                reader_errors.append(exc)
                return
            # Snapshot must be a plain list with sorted, unique ids.
            ids = [a.action_id for a in snapshot]
            if ids != sorted(ids):
                reader_errors.append(
                    AssertionError(f"snapshot not sorted: {ids[:5]!r}...")
                )
                return
            if len(set(ids)) != len(ids):
                reader_errors.append(
                    AssertionError(f"snapshot has duplicate ids: {ids!r}")
                )
                return

    writer_thread = threading.Thread(target=_writer, name="reg-writer")
    reader_threads = [
        threading.Thread(target=_reader, name=f"reg-reader-{i}") for i in range(4)
    ]
    writer_thread.start()
    for t in reader_threads:
        t.start()
    for t in reader_threads:
        t.join(timeout=10.0)
    stop.set()
    writer_thread.join(timeout=5.0)

    assert writer_errors == [], f"writer raised: {writer_errors!r}"
    assert reader_errors == [], f"reader raised: {reader_errors!r}"


# ---------------------------------------------------------------------------
# 46-3 overlap guard (no DB required; the guard short-circuits before the
# session is opened)
# ---------------------------------------------------------------------------


class _RecordingQueue:
    """Minimal TaskQueue stand-in that records submit calls and (optionally)
    raises on demand.

    Kept in this module so runner tests do not import fixtures or fakes from
    unrelated modules. Only the surface AutomationRunner.tick() touches is
    modelled: submit(track, fn, kwargs, user_id, team_id) -> TaskHandle.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.raise_for_targets: set[str] = set()
        self.raise_exc: BaseException = RuntimeError(
            "recording-queue: injected submit failure"
        )

    async def submit(
        self,
        *,
        track: str,
        fn: Any,
        kwargs: dict[str, Any],
        user_id: str,
        team_id: str | None,
    ) -> TaskHandle:
        target = kwargs.get("target_name", "")
        self.calls.append(
            {
                "track": track,
                "fn": fn,
                "kwargs": dict(kwargs),
                "user_id": user_id,
                "team_id": team_id,
            }
        )
        if target in self.raise_for_targets:
            raise self.raise_exc
        return TaskHandle(task_id=f"task-{len(self.calls):04d}")


@dataclass
class _StubRegistry:
    """Registry stand-in that returns a stub AutomationAction for any id."""

    module_id: str = "platform"

    def get_action(self, action_id: str) -> Any:
        return _StubAction(action_id=action_id, module_id=self.module_id)


@dataclass
class _StubAction:
    action_id: str
    module_id: str

    @staticmethod
    def handler_fn(**_kwargs: Any) -> None:
        return None


async def test_tick_overlap_guard_skips_second_concurrent_invocation() -> None:
    """46-3: while a tick() is executing, a second concurrent tick() returns
    0 without touching the database or the queue.

    The guard is verified by holding runner._tick_lock manually and then
    invoking tick(); the second entry short-circuits at the lock check
    before any I/O happens, which is what production sees when two
    overlapping supervisor cycles collide.
    """
    runner = AutomationRunner(_StubRegistry(), _RecordingQueue())  # type: ignore[arg-type]

    # Force lazy lock construction on this loop.
    runner._tick_lock = asyncio.Lock()

    async with runner._tick_lock:
        # tick() must not attempt to acquire the lock or read schedules;
        # it should short-circuit at `if self._tick_lock.locked(): return 0`.
        # If the guard were missing, this call would deadlock (the lock is
        # already held on this task) or open a session (which fails without
        # test_db here) -- either would surface loudly.
        submitted = await asyncio.wait_for(runner.tick(), timeout=1.0)

    assert submitted == 0


# ---------------------------------------------------------------------------
# 46-3 ordering + 46-4 per-schedule isolation
#
# These tests use the real DB via the test_db fixture: they insert
# AutomationScheduleRecord rows and let tick() drive the read + claim +
# submit + finalize path against them.
# ---------------------------------------------------------------------------


async def _insert_schedule(
    *,
    action_id: str,
    target_name: str,
    cron_expression: str = "* * * * *",
    last_run_at: datetime | None = None,
    enabled: bool = True,
) -> str:
    """Insert a single AutomationScheduleRecord and return its id."""
    schedule_id = str(uuid.uuid4())
    async with async_session_scope() as session:
        rec = AutomationScheduleRecord(
            id=schedule_id,
            action_id=action_id,
            target_name=target_name,
            cron_expression=cron_expression,
            action_kwargs_json="{}",
            enabled=enabled,
            created_by="tests",
            last_run_at=last_run_at,
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


async def test_tick_isolates_per_schedule_exception_and_processes_later_schedules(
    test_db: None,
) -> None:
    """46-4: a schedule whose submit raises RuntimeError must not abort the
    tick; every later schedule in the same read still runs.

    Before the fix, the per-schedule catch was `except (AILAError,
    SQLAlchemyError)`; a RuntimeError from the queue submit escaped the
    for-loop and every subsequent schedule was starved on that tick.
    """
    queue = _RecordingQueue()
    # Force target "boom" to raise RuntimeError inside submit().
    queue.raise_for_targets = {"boom"}

    boom_id = await _insert_schedule(action_id="platform.alpha", target_name="boom")
    ok1_id = await _insert_schedule(action_id="platform.alpha", target_name="ok-1")
    ok2_id = await _insert_schedule(action_id="platform.alpha", target_name="ok-2")

    runner = AutomationRunner(_StubRegistry(), queue)  # type: ignore[arg-type]

    submitted = await runner.tick()

    # tick() called submit() for all three targets (the read snapshot is
    # not filtered by the failure), so RecordingQueue observed three calls.
    call_targets = [c["kwargs"]["target_name"] for c in queue.calls]
    assert set(call_targets) == {"boom", "ok-1", "ok-2"}, (
        f"expected every schedule to reach submit(), got {call_targets!r}"
    )
    # Two submits succeeded; the failing one is not counted in the return.
    assert submitted == 2

    boom_row = await _load_schedule(boom_id)
    ok1_row = await _load_schedule(ok1_id)
    ok2_row = await _load_schedule(ok2_id)

    assert boom_row.last_run_result == "error", (
        f"failing schedule should record 'error', got {boom_row.last_run_result!r}"
    )
    assert ok1_row.last_run_result is not None
    assert ok1_row.last_run_result.startswith("submitted:")
    assert ok2_row.last_run_result is not None
    assert ok2_row.last_run_result.startswith("submitted:")


async def test_tick_writes_last_run_at_before_submit(test_db: None) -> None:
    """46-3 ordering: last_run_at must be persisted BEFORE TaskQueue.submit is
    called, so a hard crash (or a submit that raises after enqueue) does not
    let the next tick re-fire the same schedule.

    The old code wrote last_run_at AFTER submit returned successfully. If
    the process died between submit and that write -- or if submit raised
    an exception type the narrow (AILAError, SQLAlchemyError) catch did
    not cover -- the row stayed at its previous last_run_at and the next
    tick re-selected it as due.

    This test proves the ordering directly: an intercepting queue reads
    last_run_at from the DB during submit() and captures whatever value
    the runner has already committed. Post-fix that value must equal the
    tick's `now`; pre-fix it would still be `long_ago`.
    """
    long_ago = datetime.now(UTC) - timedelta(days=7)
    schedule_id = await _insert_schedule(
        action_id="platform.alpha",
        target_name="claim-then-submit",
        cron_expression="* * * * *",
        last_run_at=long_ago,
    )

    observed_last_run_at: list[datetime | None] = []

    class _IntrospectingQueue(_RecordingQueue):
        async def submit(self, **kwargs: Any) -> TaskHandle:  # type: ignore[override]
            # Read the row via a fresh session to see the runner's commit.
            async with async_session_scope() as session:
                row = (await session.exec(
                    select(AutomationScheduleRecord)
                    .where(AutomationScheduleRecord.id == schedule_id)
                )).one()
                observed_last_run_at.append(row.last_run_at)
            return await super().submit(**kwargs)

    queue = _IntrospectingQueue()
    runner = AutomationRunner(_StubRegistry(), queue)  # type: ignore[arg-type]

    submitted = await runner.tick()
    assert submitted == 1

    # submit() ran exactly once and saw last_run_at ALREADY advanced past
    # the seeded long_ago timestamp.
    assert len(observed_last_run_at) == 1
    seen = observed_last_run_at[0]
    assert seen is not None, "runner never claimed the row before submit"
    assert seen > long_ago, (
        f"last_run_at was not advanced before submit: still {seen!r}; "
        "finding 46-3 ordering says the claim MUST precede the enqueue."
    )


async def test_tick_ordering_preserves_claim_when_submit_fails(
    test_db: None,
) -> None:
    """46-3 ordering (failure path): if submit raises, the pre-submit claim
    on last_run_at must survive so the next tick does not re-fire the row.

    Complements the positive test above: with the pre-fix code, a
    RuntimeError from submit escaped the narrow (AILAError,
    SQLAlchemyError) catch and killed the tick, leaving last_run_at at
    its previous value. With the fix, the claim happens first and the
    broadened isolation catch writes an "error" result on top.
    """
    queue = _RecordingQueue()
    queue.raise_for_targets = {"boom"}

    long_ago = datetime.now(UTC) - timedelta(days=7)
    boom_id = await _insert_schedule(
        action_id="platform.alpha",
        target_name="boom",
        cron_expression="* * * * *",
        last_run_at=long_ago,
    )

    runner = AutomationRunner(_StubRegistry(), queue)  # type: ignore[arg-type]

    submitted = await runner.tick()
    assert submitted == 0
    assert queue.calls  # submit was attempted

    row = await _load_schedule(boom_id)
    assert row.last_run_at is not None
    assert row.last_run_at > long_ago, (
        "last_run_at must advance even when submit fails, otherwise the "
        "next tick re-fires this schedule (finding 46-3 ordering)."
    )
    assert row.last_run_result == "error"


async def test_tick_records_task_id_on_successful_submit(test_db: None) -> None:
    """Baseline for the ordering rewrite: on success, last_run_result carries
    the submitted task id and last_run_at is set.
    """
    queue = _RecordingQueue()
    schedule_id = await _insert_schedule(
        action_id="platform.alpha", target_name="target-ok"
    )
    runner = AutomationRunner(_StubRegistry(), queue)  # type: ignore[arg-type]

    submitted = await runner.tick()

    assert submitted == 1
    row = await _load_schedule(schedule_id)
    assert row.last_run_at is not None
    assert row.last_run_result is not None
    assert row.last_run_result.startswith("submitted:")
