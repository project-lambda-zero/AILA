"""#59-3 -- _active_analysis_task_id detects an in-flight full-analysis task.

Readiness auto-enqueue must skip submitting a second run_forensics_analysis
task when one is already active for the project (double-click, or a prior
submit still in flight). This exercises the guard helper directly: it returns
the active task's id for a queued/running/waiting run_forensics_analysis task
carrying the project_id, and None otherwise (terminal status, a different
project, or a different task type that merely shares the project_id).
"""
from __future__ import annotations

import json

import pytest

from aila.modules.forensics.api_router import _active_analysis_task_id
from aila.modules.forensics.workflow.task import (
    run_forensics_analysis,
    run_forensics_investigation,
)
from aila.platform.tasks.models import TaskRecord
from aila.platform.tasks.queue import TaskQueue
from aila.platform.uow import UnitOfWork

# Seed rows with the fn_path exactly as ``TaskQueue.submit`` stores it, so the
# positive cases fail if the guard's derivation ever diverges from submit.
_SUBMIT_QUEUE = TaskQueue(config_registry=None, module_id="forensics")
_ANALYSIS_FN_PATH = _SUBMIT_QUEUE._get_fn_path(run_forensics_analysis)
_INVESTIGATION_FN_PATH = _SUBMIT_QUEUE._get_fn_path(run_forensics_investigation)


async def _seed_task(
    *,
    task_id: str,
    project_id: str,
    status: str,
    fn_path: str = _ANALYSIS_FN_PATH,
) -> None:
    async with UnitOfWork() as uow:
        uow.session.add(TaskRecord(
            id=task_id,
            track="forensics",
            fn_path=fn_path,
            fn_module="forensics",
            status=status,
            user_id="system",
            group_id="forensics_test",
            team_id="admin",
            kwargs_json=json.dumps(
                {"project_id": project_id, "mode": "full_analysis"},
            ),
        ))
        await uow.session.commit()


async def _active_task(project_id: str) -> str | None:
    async with UnitOfWork() as uow:
        return await _active_analysis_task_id(uow.session, project_id)


@pytest.mark.usefixtures("test_db")
@pytest.mark.parametrize("status", ["queued", "running", "waiting"])
async def test_active_analysis_task_detected(status: str) -> None:
    await _seed_task(task_id=f"t-{status}", project_id="proj-1", status=status)

    assert await _active_task("proj-1") == f"t-{status}"


@pytest.mark.usefixtures("test_db")
async def test_terminal_task_not_detected() -> None:
    # A DONE task must not block a fresh enqueue; a live one for the same
    # project still does (positive control on the same query).
    await _seed_task(task_id="t-done", project_id="proj-2", status="done")
    assert await _active_task("proj-2") is None

    await _seed_task(task_id="t-live", project_id="proj-2", status="running")
    assert await _active_task("proj-2") == "t-live"


@pytest.mark.usefixtures("test_db")
async def test_other_project_not_detected() -> None:
    await _seed_task(task_id="t-other", project_id="proj-A", status="running")

    assert await _active_task("proj-B") is None
    assert await _active_task("proj-A") == "t-other"


@pytest.mark.usefixtures("test_db")
async def test_different_task_type_with_same_project_not_detected() -> None:
    """An active run_forensics_investigation sharing the project_id is NOT an
    active analysis task; the fn_path filter must exclude it."""
    await _seed_task(
        task_id="t-inv",
        project_id="proj-3",
        status="running",
        fn_path=_INVESTIGATION_FN_PATH,
    )
    assert await _active_task("proj-3") is None

    await _seed_task(task_id="t-analysis", project_id="proj-3", status="running")
    assert await _active_task("proj-3") == "t-analysis"
