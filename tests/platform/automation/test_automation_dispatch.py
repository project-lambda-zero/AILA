"""#455 -- scheduled platform automation actions reach a worker that runs them.

A due schedule is submitted by the real :class:`AutomationRunner` against the
real platform action registration; the queue is the replaced boundary (a
recorder). Every submission must target a queue in the default worker set and
a function the worker registers, and the worker function must run the
action's handler.
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any

import pytest

from aila.platform.automation.maintenance import register_maintenance_actions
from aila.platform.automation.models import AutomationScheduleRecord
from aila.platform.automation.registry import AutomationRegistry
from aila.platform.automation.runner import AutomationRunner
from aila.platform.tasks.models import TaskHandle
from aila.platform.tasks.queue import qualified_task_name
from aila.platform.tasks.worker import WorkerSettings
from aila.storage.database import async_session_scope

_START_SH = Path(__file__).resolve().parents[3] / "start.sh"


def _default_worker_queues() -> set[str]:
    """Queues ``start.sh`` starts a worker for when ``WORKERS`` is unset."""
    match = re.search(r'^: "\$\{WORKERS:=([^}]*)\}"', _START_SH.read_text(encoding="utf-8"), re.MULTILINE)
    assert match is not None, "start.sh no longer declares a WORKERS default"
    return set(match.group(1).split())


class _RecordingQueue:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def submit(self, *, track: str, fn: Any, kwargs: dict[str, Any], user_id: str, team_id: str | None) -> TaskHandle:
        self.calls.append({"track": track, "fn": fn, "kwargs": kwargs, "user_id": user_id, "team_id": team_id})
        return TaskHandle(task_id=f"task-{uuid.uuid4().hex[:12]}")


def _platform_registry() -> AutomationRegistry:
    registry = AutomationRegistry()
    register_maintenance_actions(registry)
    return registry


async def _insert_due_schedule(action_id: str) -> None:
    async with async_session_scope() as session:
        session.add(AutomationScheduleRecord(
            id=str(uuid.uuid4()),
            action_id=action_id,
            target_name=f"tests-{uuid.uuid4().hex[:8]}",
            cron_expression="* * * * *",
            cron_timezone="UTC",
            action_kwargs_json="{}",
            enabled=True,
            created_by="tests",
        ))
        await session.commit()


def _worker_function(fn: Any) -> Any:
    by_name = {f.name: f for f in WorkerSettings.functions}
    name = qualified_task_name(fn)
    assert name in by_name, f"{name} is not a worker function"
    return by_name[name]


@pytest.mark.usefixtures("test_db")
async def test_every_platform_action_submits_to_a_served_worker_function() -> None:
    registry = _platform_registry()
    action_ids = {a.action_id for a in registry.list_actions()}
    for action_id in sorted(action_ids):
        await _insert_due_schedule(action_id)
    queue = _RecordingQueue()

    await AutomationRunner(registry, queue).tick()  # type: ignore[arg-type]

    served = _default_worker_queues()
    assert len(queue.calls) == len(action_ids)
    for call in queue.calls:
        assert call["track"] in served, f"{qualified_task_name(call['fn'])} submitted on unserved queue {call['track']!r}"
        _worker_function(call["fn"])
    assert {c["kwargs"]["action_id"] for c in queue.calls} == action_ids


@pytest.mark.usefixtures("test_db")
async def test_worker_function_runs_the_scheduled_handler() -> None:
    registry = _platform_registry()
    await _insert_due_schedule("platform.health_check")
    queue = _RecordingQueue()
    await AutomationRunner(registry, queue).tick()  # type: ignore[arg-type]
    (call,) = queue.calls

    result = await _worker_function(call["fn"]).coroutine({"job_id": f"job-{uuid.uuid4().hex[:12]}", "job_try": 1}, **call["kwargs"])

    assert result["action_id"] == "platform.health_check"
    assert result["result"]["dependencies"]["database"] == {"status": "healthy", "error": None}
