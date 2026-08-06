"""Tests for the automation distributed lock + run-history (issue #46).

Acceptance from the fix ticket:

- Concurrent due-run attempts (two runner invocations racing on a
  fake/real lock) MUST result in a single execution.
- Run-history rows are written for every attempted occurrence with
  ``started_at`` / ``finished_at`` / ``outcome``.
- The lock backend degrades safely when Redis is unavailable
  (documented behaviour, no crash) -- the DB
  ``UNIQUE(schedule_id, occurrence_at)`` constraint on
  ``automation_run_records`` becomes the fallback claim.
"""
from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlmodel import select

from aila.platform.automation import lock as _lock_module
from aila.platform.automation.lock import (
    LockBackendUnavailableError,
    acquire_occurrence_lock,
    occurrence_lock_key,
    release_occurrence_lock,
)
from aila.platform.automation.models import (
    AutomationRunRecord,
    AutomationScheduleRecord,
)
from aila.platform.automation.runner import AutomationRunner
from aila.platform.tasks.models import TaskHandle
from aila.storage.database import async_session_scope

# ---------------------------------------------------------------------------
# In-memory Redis stand-in
#
# Implements only the surface acquire_occurrence_lock / release_occurrence_lock
# touch: ``set(key, value, nx=..., px=...)`` and ``eval(script, 1, key, val)``.
# Sufficient for the mutual-exclusion contract; a real Redis race adds nothing
# a fake with the same NX semantics does not already prove.
# ---------------------------------------------------------------------------


class _FakeRedis:
    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self.set_calls: int = 0
        self.eval_calls: int = 0

    async def set(
        self,
        key: str,
        value: str,
        *,
        nx: bool = False,
        px: int | None = None,
    ) -> bool | None:
        self.set_calls += 1
        # px is stored implicitly via the fact that the test never advances
        # the clock; the real Redis TTL contract is exercised by production
        # deployments, not by this unit test.
        del px
        if nx and key in self._store:
            return None
        self._store[key] = value
        return True

    async def eval(self, script: str, numkeys: int, *args: str) -> int:
        # Matches the compare-and-delete Lua in lock._RELEASE_LUA: DEL only
        # when the current value equals the caller's token.
        del script, numkeys
        key, token = args[0], args[1]
        self.eval_calls += 1
        if self._store.get(key) == token:
            self._store.pop(key, None)
            return 1
        return 0

    async def aclose(self) -> None:
        return None


@asynccontextmanager
async def _fake_get_redis_ctx(fake: _FakeRedis):
    yield fake


def _install_fake_redis(monkeypatch: pytest.MonkeyPatch, fake: _FakeRedis) -> None:
    """Wire a fake Redis client into the lock module for one test.

    ``acquire_occurrence_lock`` short-circuits with
    ``LockBackendUnavailableError`` when ``pool_available()`` is False
    (fast-path degrade so a runner in a test without Redis wired does
    not auto-init the pool via ``get_redis``). Tests that WANT the
    fake to be exercised must therefore also make ``pool_available``
    report True; the lock module never actually reads the real pool
    once ``get_redis`` is stubbed.
    """
    monkeypatch.setattr(
        _lock_module, "get_redis", lambda: _fake_get_redis_ctx(fake),
    )
    monkeypatch.setattr(_lock_module, "pool_available", lambda: True)


# ---------------------------------------------------------------------------
# Runner-side fakes (mirrors the shapes in test_runner_and_registry.py so
# runner tests do not import fixtures across files).
# ---------------------------------------------------------------------------


class _RecordingQueue:
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
        return TaskHandle(task_id=f"task-{uuid.uuid4().hex[:8]}")


@dataclass
class _StubAction:
    action_id: str
    module_id: str

    @staticmethod
    def handler_fn(**_kwargs: Any) -> None:
        return None


@dataclass
class _StubRegistry:
    module_id: str = "platform"

    def get_action(self, action_id: str) -> Any:
        return _StubAction(action_id=action_id, module_id=self.module_id)


async def _insert_schedule(
    *,
    action_id: str = "platform.alpha",
    target_name: str = "race-target",
    cron_expression: str = "* * * * *",
) -> str:
    schedule_id = str(uuid.uuid4())
    async with async_session_scope() as session:
        session.add(
            AutomationScheduleRecord(
                id=schedule_id,
                action_id=action_id,
                target_name=target_name,
                cron_expression=cron_expression,
                action_kwargs_json="{}",
                enabled=True,
                created_by="tests",
                last_run_at=None,
            )
        )
        await session.commit()
    return schedule_id


async def _run_records(schedule_id: str) -> list[AutomationRunRecord]:
    async with async_session_scope() as session:
        return list(
            (
                await session.exec(
                    select(AutomationRunRecord).where(
                        AutomationRunRecord.schedule_id == schedule_id,
                    )
                )
            ).all()
        )


# ---------------------------------------------------------------------------
# Lock primitive: mutual exclusion + degrade
# ---------------------------------------------------------------------------


async def test_occurrence_lock_second_acquire_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Redis SET NX PX must reject a second acquire on the same key.

    First caller receives a handle; second caller (before release) sees
    ``None`` and MUST skip. This is the invariant the runner relies on
    to guarantee exactly-once execution across processes.
    """
    fake = _FakeRedis()
    _install_fake_redis(monkeypatch, fake)

    schedule_id = "sched-A"
    occurrence = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)

    first = await acquire_occurrence_lock(schedule_id, occurrence)
    second = await acquire_occurrence_lock(schedule_id, occurrence)

    assert first is not None, "first acquire must win"
    assert second is None, "second acquire on the same key must be rejected"
    # Sanity: the key stored in the fake matches the deterministic derivation.
    key = occurrence_lock_key(schedule_id, occurrence)
    assert key in fake._store

    # After release, a third caller can acquire again.
    await release_occurrence_lock(first)
    third = await acquire_occurrence_lock(schedule_id, occurrence)
    assert third is not None, "acquire after release must win"
    await release_occurrence_lock(third)


async def test_occurrence_lock_raises_when_pool_not_initialised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pool absent -> LockBackendUnavailableError WITHOUT touching Redis.

    The fast-path degrade short-circuits on ``pool_available() ==
    False`` so a runner in a context that never wired Redis does not
    trigger ``get_redis``' auto-init side effect. The runner catches
    ``LockBackendUnavailableError`` specifically and falls back to the
    DB unique-constraint claim on automation_run_records; any other
    exception would surface as an unhandled tick failure.
    """
    # Force pool_available() False regardless of the environment's
    # AILA_PLATFORM_REDIS_URL setting, and prove get_redis is never
    # even reached by wiring a sentinel that would blow up loudly.
    def _fail_if_called():
        raise AssertionError(
            "get_redis MUST NOT be called when pool_available() is False"
        )

    monkeypatch.setattr(_lock_module, "pool_available", lambda: False)
    monkeypatch.setattr(_lock_module, "get_redis", _fail_if_called)

    with pytest.raises(LockBackendUnavailableError):
        await acquire_occurrence_lock(
            "sched-B", datetime(2026, 7, 27, 12, 0, tzinfo=UTC),
        )


async def test_occurrence_lock_raises_when_backend_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pool present but backend errors on SET -> LockBackendUnavailableError.

    Covers the second-branch degrade where pool_available() reports
    True (production already initialised the pool at startup) but a
    later Redis fault (connection drop, timeout) hits the SET NX call.
    """

    @asynccontextmanager
    async def _flaky():
        raise RedisConnectionError("simulated: redis dropped mid-tick")
        yield  # pragma: no cover -- unreachable but required by shape

    monkeypatch.setattr(_lock_module, "pool_available", lambda: True)
    monkeypatch.setattr(_lock_module, "get_redis", _flaky)

    with pytest.raises(LockBackendUnavailableError):
        await acquire_occurrence_lock(
            "sched-B", datetime(2026, 7, 27, 12, 0, tzinfo=UTC),
        )


# ---------------------------------------------------------------------------
# Runner: two racing runner instances execute a schedule exactly once
# ---------------------------------------------------------------------------


async def test_two_racing_runners_execute_schedule_exactly_once(
    test_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two runner instances (as if two processes) tick the same due
    schedule concurrently, sharing one Redis backend. Exactly one
    executes and exactly one run-history row is written.

    Without the distributed lock + unique constraint, both runners
    would pass the intra-process asyncio.Lock (separate instances) and
    the SELECT ... FOR UPDATE SKIP LOCKED (the row-lock releases as
    soon as the SELECT completes), then both would submit -- the
    exact double-fire pathology issue #46 opens with.
    """
    fake = _FakeRedis()
    _install_fake_redis(monkeypatch, fake)

    schedule_id = await _insert_schedule(target_name="race-once")

    queue_a = _RecordingQueue()
    queue_b = _RecordingQueue()
    runner_a = AutomationRunner(_StubRegistry(), queue_a)  # type: ignore[arg-type]
    runner_b = AutomationRunner(_StubRegistry(), queue_b)  # type: ignore[arg-type]

    result_a, result_b = await asyncio.gather(runner_a.tick(), runner_b.tick())

    total_submits = len(queue_a.calls) + len(queue_b.calls)
    assert total_submits == 1, (
        f"expected exactly one submit across both runners, got {total_submits} "
        f"(a={len(queue_a.calls)}, b={len(queue_b.calls)}); this is the "
        "double-fire regression issue #46 fixes."
    )
    assert (result_a + result_b) == 1

    rows = await _run_records(schedule_id)
    assert len(rows) == 1, (
        f"expected exactly one automation_run_records row, got {len(rows)}: "
        f"{[(r.occurrence_at, r.outcome) for r in rows]!r}"
    )
    row = rows[0]
    assert row.started_at is not None
    assert row.finished_at is not None
    assert row.finished_at >= row.started_at
    assert row.outcome.startswith("submitted:"), (
        f"expected outcome to record the task id; got {row.outcome!r}"
    )
    assert row.task_id is not None
    assert row.runner_id is not None


# ---------------------------------------------------------------------------
# Degrade path: Redis unavailable => DB unique constraint is the barrier
# ---------------------------------------------------------------------------


async def test_degrades_to_db_unique_constraint_when_redis_unavailable(
    test_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``get_redis`` raises, both runners see
    ``LockBackendUnavailableError`` and fall through to the DB claim.
    The UNIQUE(schedule_id, occurrence_at) constraint on
    automation_run_records serves as the second-order lock: one INSERT
    wins, the other sees IntegrityError and skips.
    """

    @asynccontextmanager
    async def _dead_redis():
        raise RuntimeError("simulated: redis pool not initialized")
        yield  # pragma: no cover

    monkeypatch.setattr(_lock_module, "get_redis", _dead_redis)

    schedule_id = await _insert_schedule(target_name="degrade-target")

    queue_a = _RecordingQueue()
    queue_b = _RecordingQueue()
    runner_a = AutomationRunner(_StubRegistry(), queue_a)  # type: ignore[arg-type]
    runner_b = AutomationRunner(_StubRegistry(), queue_b)  # type: ignore[arg-type]

    result_a, result_b = await asyncio.gather(runner_a.tick(), runner_b.tick())

    total_submits = len(queue_a.calls) + len(queue_b.calls)
    assert total_submits == 1, (
        "even with Redis down, exactly one runner MUST execute the "
        f"occurrence; got {total_submits} (a={len(queue_a.calls)}, "
        f"b={len(queue_b.calls)})."
    )
    assert (result_a + result_b) == 1

    rows = await _run_records(schedule_id)
    assert len(rows) == 1, (
        "the DB unique constraint MUST prevent a second row for the same "
        f"occurrence; got {len(rows)} rows: "
        f"{[(r.occurrence_at, r.outcome) for r in rows]!r}"
    )


# ---------------------------------------------------------------------------
# Single-runner positive: run-history is written with start/finish/outcome
# ---------------------------------------------------------------------------


async def test_single_tick_writes_run_history_row(
    test_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Baseline: one runner, one due schedule -> one run_history row with
    outcome ``submitted:<task_id>`` and both timestamps populated.
    """
    fake = _FakeRedis()
    _install_fake_redis(monkeypatch, fake)

    schedule_id = await _insert_schedule(target_name="single-target")

    queue = _RecordingQueue()
    runner = AutomationRunner(_StubRegistry(), queue)  # type: ignore[arg-type]

    submitted = await runner.tick()

    assert submitted == 1
    assert len(queue.calls) == 1

    rows = await _run_records(schedule_id)
    assert len(rows) == 1
    row = rows[0]
    assert row.outcome.startswith("submitted:")
    assert row.task_id == queue.calls[0]["fn"].__name__ or row.task_id is not None
    assert row.started_at is not None
    assert row.finished_at is not None
    # The Redis lock was acquired then released -- eval fired exactly once.
    assert fake.set_calls >= 1
    assert fake.eval_calls == 1


# ---------------------------------------------------------------------------
# Isolation: error path also finalizes the run-history row
# ---------------------------------------------------------------------------


async def test_error_path_finalizes_run_history_with_error_outcome(
    test_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the submit path raises inside the isolation guard, the
    run-history row is finalized with outcome ``error:<ExcType>`` so an
    operator can observe the failure even after the schedule row's
    last_run_result is clobbered by a peer's later fire.
    """
    fake = _FakeRedis()
    _install_fake_redis(monkeypatch, fake)

    schedule_id = await _insert_schedule(target_name="error-target")

    class _BoomQueue(_RecordingQueue):
        async def submit(self, **kwargs: Any) -> TaskHandle:  # type: ignore[override]
            await super().submit(**kwargs)
            raise RuntimeError("simulated submit failure")

    queue = _BoomQueue()
    runner = AutomationRunner(_StubRegistry(), queue)  # type: ignore[arg-type]

    submitted = await runner.tick()
    assert submitted == 0, "failing submit must not be counted"

    rows = await _run_records(schedule_id)
    assert len(rows) == 1
    row = rows[0]
    assert row.outcome == "error:RuntimeError", (
        f"expected 'error:RuntimeError'; got {row.outcome!r}"
    )
    assert row.finished_at is not None
