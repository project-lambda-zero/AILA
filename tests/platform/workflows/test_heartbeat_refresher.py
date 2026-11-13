"""The engine keeps ``taskrecord.heartbeat_at`` fresh while a handler runs (#438).

A handler that stays in one state longer than the reaper's stale-heartbeat
threshold must not look dead, and no refresher may outlive its handler. The
refresh interval is shortened to a few tens of milliseconds for the test.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from aila.platform.tasks.models import TaskRecord
from aila.platform.workflows import DurableStateMachine, StateResult, StateSpec, WorkflowDefinition
from aila.platform.workflows import engine as engine_mod
from aila.storage.database import async_session_scope
from tests.platform.workflows.conftest import toy_services_factory

_INTERVAL_S = 0.05
_OLD = datetime.now(UTC) - timedelta(hours=1)


@pytest.fixture(autouse=True)
def _fast_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _interval() -> float:
        return _INTERVAL_S

    monkeypatch.setattr(engine_mod, "_resolve_heartbeat_interval_s", _interval)


async def _seed_task(run_id: str) -> None:
    async with async_session_scope() as session:
        session.add(TaskRecord(
            id=run_id, track="default", fn_path="test.fn", fn_module="test",
            status="running", user_id="admin", group_id=run_id,
            started_at=_OLD, heartbeat_at=_OLD,
        ))
        await session.commit()


async def _heartbeat(run_id: str) -> datetime:
    async with async_session_scope() as session:
        row = await session.get(TaskRecord, run_id)
    assert row is not None and row.heartbeat_at is not None
    return row.heartbeat_at


def _single_state(handler) -> WorkflowDefinition:  # noqa: ANN001 -- handler signature is the engine's
    return WorkflowDefinition(
        definition_id="test.heartbeat.v1",
        start_state="start",
        states={"start": StateSpec(handler=handler, timeout_s=30.0)},
        services_factory=toy_services_factory,
    )


async def test_heartbeat_advances_while_the_handler_runs(workflow_run_id: str) -> None:
    await _seed_task(workflow_run_id)
    seen: list[datetime] = []

    async def long_handler(state_input: dict, services: object) -> StateResult:
        for _ in range(4):
            await asyncio.sleep(_INTERVAL_S * 3)
            seen.append(await _heartbeat(workflow_run_id))
        return StateResult(next_state="__succeeded__", output={"ok": True})

    await DurableStateMachine.execute(workflow_run_id, _single_state(long_handler), {})

    assert seen[0] > _OLD
    # Every sample taken inside the handler is newer than the previous one:
    # the refresher wrote at least once per three intervals, mid-handler.
    assert all(later > earlier for earlier, later in zip(seen, seen[1:], strict=False))


@pytest.mark.parametrize("outcome", ["returns", "raises"])
async def test_no_refresher_outlives_its_handler(workflow_run_id: str, outcome: str) -> None:
    await _seed_task(workflow_run_id)

    async def handler(state_input: dict, services: object) -> StateResult:
        await asyncio.sleep(_INTERVAL_S * 3)
        if outcome == "raises":
            raise RuntimeError("handler failed")
        return StateResult(next_state="__succeeded__", output={"ok": True})

    await DurableStateMachine.execute(workflow_run_id, _single_state(handler), {})
    after_run = await _heartbeat(workflow_run_id)

    await asyncio.sleep(_INTERVAL_S * 6)

    assert await _heartbeat(workflow_run_id) == after_run

