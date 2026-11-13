"""A full-analysis run that fails after intake leaves the project failed (#427).

Runs the real workflow engine over the full-analysis definition on the test
database. The state specs (retry policy, ``on_success`` / ``on_failure``
edges) and the ``response_emit`` / ``analysis_failed`` handlers are the
production ones; the evidence states are replaced by pass-through handlers,
one of which raises. The run's ``TaskRecord`` carries the project id in its
kwargs exactly as the task queue writes it.
"""
from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from aila.modules.forensics.contracts.status import ProjectStatus
from aila.modules.forensics.db_models import ForensicsProjectRecord
from aila.modules.forensics.workflow.definitions import FORENSICS_FULL_ANALYSIS_V1
from aila.platform.tasks.models import TaskRecord
from aila.platform.workflows import DurableStateMachine, StateResult, WorkflowDefinition
from aila.platform.workflows.types import RESERVED_FAILED, RESERVED_SUCCEEDED
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord, WorkflowStateCursor

pytestmark = pytest.mark.usefixtures("test_db")

_EVIDENCE_STATES = ("intake", "collection", "deep_analysis", "promotion", "resolution", "writeup")


class _Emitter:
    async def emit(self, stage: str, message: str, meta: dict[str, Any]) -> None:
        return None


async def _services(run_id: str) -> Any:
    return SimpleNamespace(
        run_id=run_id,
        emitter=_Emitter(),
        settings=None,
        evidence_directory="",
        integration={"id": 1, "host": "analyzer.invalid"},
    )


def _pass_through(next_state: str | None) -> Any:
    async def handler(state_input: dict[str, Any], services: Any) -> StateResult:
        assert next_state is not None
        return StateResult(next_state=next_state, output={"project_id": state_input["project_id"]})
    return handler


async def _raise(state_input: dict[str, Any], services: Any) -> StateResult:
    raise RuntimeError("synthetic state failure")


def _definition(failing: str | None, *, real_intake: bool = False) -> WorkflowDefinition:
    states = dict(FORENSICS_FULL_ANALYSIS_V1.states)
    for name in _EVIDENCE_STATES:
        if name == "intake" and real_intake:
            continue
        handler = _raise if name == failing else _pass_through(states[name].on_success)
        states[name] = replace(states[name], handler=handler)
    return replace(FORENSICS_FULL_ANALYSIS_V1, states=states, services_factory=_services)


async def _seed(status: str) -> tuple[str, str]:
    suffix = uuid4().hex[:8]
    project_id = f"proj-427-{suffix}"
    run_id = str(uuid4())
    async with async_session_scope() as session:
        session.add(ForensicsProjectRecord(
            id=project_id, name=project_id, system_id=0,
            evidence_directory="/evidence", status=status,
        ))
        session.add(TaskRecord(
            id=run_id, track="forensics", fn_path="forensics.run", fn_module="forensics",
            status="running", user_id="admin", group_id=run_id,
            kwargs_json=json.dumps({"project_id": project_id, "query": "analyze"}),
        ))
        session.add(WorkflowRunRecord(id=run_id, query_text="analyze", action_id="test", module_id="forensics"))
        await session.commit()
    return project_id, run_id


async def _project(project_id: str) -> ForensicsProjectRecord:
    async with async_session_scope() as session:
        project = await session.get(ForensicsProjectRecord, project_id)
    assert project is not None
    return project


async def _cursor_state(run_id: str) -> str:
    async with async_session_scope() as session:
        cursor = await session.get(WorkflowStateCursor, run_id)
    assert cursor is not None
    return cursor.current_state


@pytest.mark.parametrize("failing", ["collection", "deep_analysis", "promotion", "resolution", "writeup"])
async def test_later_state_failure_marks_project_failed(failing: str) -> None:
    project_id, run_id = await _seed(ProjectStatus.ANALYZING.value)

    out = await DurableStateMachine.execute(run_id, _definition(failing), {"project_id": project_id})

    project = await _project(project_id)
    assert project.status == ProjectStatus.FAILED.value
    assert project.failure_reason == f"{failing} failed: RuntimeError"
    assert out["failed_state"] == failing
    assert await _cursor_state(run_id) == RESERVED_FAILED


async def test_successful_run_still_completes() -> None:
    project_id, run_id = await _seed(ProjectStatus.ANALYZING.value)

    await DurableStateMachine.execute(run_id, _definition(None), {"project_id": project_id})

    project = await _project(project_id)
    assert project.status == ProjectStatus.COMPLETED.value
    assert project.failure_reason is None
    assert await _cursor_state(run_id) == RESERVED_SUCCEEDED


async def test_intake_failure_keeps_the_intake_reason() -> None:
    project_id, run_id = await _seed(ProjectStatus.CREATED.value)

    # No evidence directory anywhere: the real intake rejects its input,
    # marks the project failed with its own reason, and re-raises.
    await DurableStateMachine.execute(
        run_id, _definition(None, real_intake=True), {"project_id": project_id},
    )

    project = await _project(project_id)
    assert project.status == ProjectStatus.FAILED.value
    assert project.failure_reason is not None
    assert project.failure_reason.startswith("intake failed: ValidationError: ")
    assert "evidence_directory" in project.failure_reason
    assert await _cursor_state(run_id) == RESERVED_FAILED
