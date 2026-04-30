"""Phase 179 Task 2 — ARQ hook matrix (_on_job_start / _on_job_end).

Exercises each of the six D-14 branches in :func:`_on_job_end` against
real Postgres + real Memurai. Also proves :func:`_on_job_start` sets
RUNNING + started_at on first try and populates ``WorkflowRunRecord.plan_json``
for workflow-engine tasks.
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
import pytest_asyncio
from sqlmodel import select

from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.hooks import (
    _JobOutcome,
    _on_job_end,
    _on_job_start,
    _stash_outcome,
)
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.template import _REGISTRY, platform_task
from aila.platform.workflows import StateResult, StateSpec, WorkflowDefinition, WorkflowServices
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord


@pytest.fixture(autouse=True)
def _isolate_registry() -> Any:
    snapshot = dict(_REGISTRY._tasks)  # noqa: SLF001
    _REGISTRY.clear()
    try:
        yield
    finally:
        _REGISTRY.clear()
        _REGISTRY._tasks.update(snapshot)  # noqa: SLF001


@pytest_asyncio.fixture
async def seeded(test_db: None) -> str:  # noqa: ARG001
    tid = str(uuid.uuid4())
    async with async_session_scope() as session:
        session.add(
            TaskRecord(
                id=tid,
                track="vulnerability",
                fn_path="tests.fake",
                fn_module="tests",
                status=TaskStatus.RUNNING,
                user_id="user-9",
                group_id="operator",
                kwargs_json="{}",
            ),
        )
        await session.commit()
    return tid


async def _get(tid: str) -> TaskRecord:
    async with async_session_scope() as session:
        rec = (
            await session.exec(select(TaskRecord).where(TaskRecord.id == tid))
        ).first()
    assert rec is not None
    return rec


# --- _on_job_start --------------------------------------------------------


@pytest.mark.asyncio
async def test_on_job_start_first_try_sets_running(seeded: str) -> None:
    # Start from QUEUED to observe the transition.
    async with async_session_scope() as session:
        rec = (
            await session.exec(select(TaskRecord).where(TaskRecord.id == seeded))
        ).first()
        assert rec is not None
        rec.status = TaskStatus.QUEUED
        rec.started_at = None
        session.add(rec)
        await session.commit()

    await _on_job_start({"job_id": seeded, "job_try": 1})

    rec = await _get(seeded)
    assert rec.status == TaskStatus.RUNNING
    assert rec.started_at is not None


@pytest.mark.asyncio
async def test_on_job_start_second_try_leaves_started_at(seeded: str) -> None:
    from aila.platform.contracts._common import utc_now

    original_started = utc_now()
    async with async_session_scope() as session:
        rec = (
            await session.exec(select(TaskRecord).where(TaskRecord.id == seeded))
        ).first()
        assert rec is not None
        rec.status = TaskStatus.RUNNING
        rec.started_at = original_started
        session.add(rec)
        await session.commit()

    await _on_job_start({"job_id": seeded, "job_try": 2})

    rec = await _get(seeded)
    assert rec.status == TaskStatus.RUNNING
    assert rec.started_at is not None
    # started_at preserved (not rewritten to utc_now on retry)
    assert abs((rec.started_at - original_started).total_seconds()) < 1


@pytest.mark.asyncio
async def test_on_job_start_populates_plan_json(seeded: str) -> None:
    async def _h(_inp: dict[str, Any], _svc: object) -> StateResult:
        return StateResult(next_state="__succeeded__", output={})

    async def _factory(_rid: str) -> WorkflowServices:
        class _S:
            pass
        return _S()  # type: ignore[return-value]

    definition = WorkflowDefinition(
        definition_id="test.plan.v1",
        start_state="start",
        states={"start": StateSpec(handler=_h)},
        services_factory=_factory,
    )

    @platform_task(
        track="vulnerability",
        module_id="vulnerability",
        definition=definition,
    )
    async def my_task(ctx: TaskContext, **_kw: Any) -> dict[str, Any]:
        return {}

    # Seed a WorkflowRunRecord; fn_path must match the registry key's
    # last-segment for the hook lookup.
    async with async_session_scope() as session:
        session.add(
            WorkflowRunRecord(
                id=seeded,
                query_text="q",
                action_id="a",
                module_id="m",
            ),
        )
        rec = (
            await session.exec(select(TaskRecord).where(TaskRecord.id == seeded))
        ).first()
        assert rec is not None
        # Set fn_path so the registry lookup keyed by fn_path finds the task.
        registered_name = next(iter(_REGISTRY.tasks)).name
        rec.fn_path = registered_name
        session.add(rec)
        await session.commit()

    await _on_job_start({"job_id": seeded, "job_try": 1})

    async with async_session_scope() as session:
        wr = (
            await session.exec(
                select(WorkflowRunRecord).where(WorkflowRunRecord.id == seeded)
            )
        ).first()
    assert wr is not None
    assert wr.plan_json is not None
    assert wr.plan_json.get("definition_id") == "test.plan.v1"


# --- _on_job_end branches -------------------------------------------------


@pytest.mark.asyncio
async def test_branch_1_success(seeded: str) -> None:
    _stash_outcome(
        seeded, 1,
        _JobOutcome(kind="success", result={"result_path": "/tmp/out"}),
    )
    await _on_job_end({"job_id": seeded, "job_try": 1})
    rec = await _get(seeded)
    assert rec.status == TaskStatus.DONE
    assert rec.result_path == "/tmp/out"
    assert rec.completed_at is not None
    assert rec.error is None


@pytest.mark.asyncio
async def test_branch_1_enqueues_dependents(seeded: str) -> None:
    dep_id = str(uuid.uuid4())
    async with async_session_scope() as session:
        session.add(
            TaskRecord(
                id=dep_id,
                track="vulnerability",
                fn_path="tests.dep",
                fn_module="tests",
                status=TaskStatus.WAITING,
                user_id="u",
                group_id="o",
                kwargs_json="{}",
                depends_on_json=f'["{seeded}"]',
            ),
        )
        await session.commit()

    _stash_outcome(
        seeded, 1, _JobOutcome(kind="success", result={}),
    )
    await _on_job_end({"job_id": seeded, "job_try": 1})

    dep = await _get(dep_id)
    assert dep.status == TaskStatus.QUEUED


@pytest.mark.asyncio
async def test_branch_2_retry_signalled(seeded: str) -> None:
    _stash_outcome(seeded, 1, _JobOutcome(kind="retry_signalled"))
    await _on_job_end({"job_id": seeded, "job_try": 1})
    rec = await _get(seeded)
    assert rec.status == TaskStatus.RUNNING
    assert rec.completed_at is None


@pytest.mark.asyncio
async def test_branch_3_exception_under_max_tries(
    seeded: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Register a platform task keyed by the TaskRecord's fn_path so the
    # hook finds the configured max_tries via the registry.
    @platform_task(track="vulnerability", module_id="vulnerability", max_tries=3)
    async def fake_task(ctx: TaskContext, **_k: Any) -> dict[str, Any]:
        return {}

    async with async_session_scope() as session:
        rec = (
            await session.exec(select(TaskRecord).where(TaskRecord.id == seeded))
        ).first()
        assert rec is not None
        rec.fn_path = next(iter(_REGISTRY.tasks)).name
        session.add(rec)
        await session.commit()

    exc = RuntimeError("transient")
    _stash_outcome(
        seeded, 1,
        _JobOutcome(
            kind="exception", exception=exc, exception_class="RuntimeError",
        ),
    )
    with caplog.at_level("WARNING"):
        await _on_job_end({"job_id": seeded, "job_try": 1})

    rec = await _get(seeded)
    assert rec.status == TaskStatus.RUNNING
    assert rec.completed_at is None


@pytest.mark.asyncio
async def test_branch_4_exception_final_try_dead_letter(
    seeded: str,
    redis_cleanup: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import redis.asyncio as aioredis

    @platform_task(track="vulnerability", module_id="vulnerability", max_tries=3)
    async def fake_task2(ctx: TaskContext, **_k: Any) -> dict[str, Any]:
        return {}

    async with async_session_scope() as session:
        rec = (
            await session.exec(select(TaskRecord).where(TaskRecord.id == seeded))
        ).first()
        assert rec is not None
        rec.fn_path = next(iter(_REGISTRY.tasks)).name
        session.add(rec)
        await session.commit()

    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", redis_cleanup)

    exc = RuntimeError("permanent failure")
    _stash_outcome(
        seeded, 3,
        _JobOutcome(
            kind="exception", exception=exc, exception_class="RuntimeError",
        ),
    )
    await _on_job_end({"job_id": seeded, "job_try": 3})

    rec = await _get(seeded)
    assert rec.status == TaskStatus.DEAD_LETTER
    assert rec.error is not None and "permanent failure" in rec.error
    assert rec.completed_at is not None

    client = aioredis.Redis.from_url(redis_cleanup, socket_connect_timeout=2.0)
    try:
        card = await client.zcard("arq:dead-letter:vulnerability")
        assert int(card) == 1
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_branch_5_timeout_dead_letter(
    seeded: str,
    redis_cleanup: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", redis_cleanup)

    exc = TimeoutError()
    _stash_outcome(
        seeded, 1,
        _JobOutcome(
            kind="timeout", exception=exc, exception_class="TimeoutError",
        ),
    )
    await _on_job_end({"job_id": seeded, "job_try": 1})

    rec = await _get(seeded)
    assert rec.status == TaskStatus.DEAD_LETTER
    assert rec.error is not None and "code=JOB_TIMEOUT" in rec.error


@pytest.mark.asyncio
async def test_branch_6_cancelled(seeded: str) -> None:
    _stash_outcome(
        seeded, 1,
        _JobOutcome(
            kind="cancelled",
            exception=asyncio.CancelledError(),
            exception_class="CancelledError",
        ),
    )
    await _on_job_end({"job_id": seeded, "job_try": 1})

    rec = await _get(seeded)
    assert rec.status == TaskStatus.CANCELLED
    assert rec.completed_at is not None
