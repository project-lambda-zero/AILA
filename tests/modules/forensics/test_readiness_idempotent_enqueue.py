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
from aila.modules.forensics.workflow.task import run_forensics_analysis
from aila.platform.tasks.models import TaskRecord
from aila.platform.tasks.queue import TaskQueue
from aila.platform.uow import UnitOfWork

# Derive the stored fn_path the same way TaskQueue.submit does, so the seeded
# rows match whatever the guard computes even if the task module moves. The
# coupling test below anchors this to TaskQueue._get_fn_path so a future change
# to how submit stores fn_path cannot silently turn the guard into a no-op.
_ANALYSIS_FN_PATH = (
    f"{run_forensics_analysis.__module__}.{run_forensics_analysis.__qualname__}"
)
_INVESTIGATION_FN_PATH = (
    "aila.modules.forensics.workflow.task.run_forensics_investigation"
)


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


@pytest.mark.usefixtures("test_db")
async def test_active_analysis_task_detected() -> None:
    await _seed_task(task_id="t-active", project_id="proj-1", status="running")
    async with UnitOfWork() as uow:
        found = await _active_analysis_task_id(uow.session, "proj-1")
    assert found == "t-active"


@pytest.mark.usefixtures("test_db")
async def test_terminal_task_not_detected() -> None:
    # A DONE task must not block a fresh enqueue.
    await _seed_task(task_id="t-done", project_id="proj-2", status="done")
    async with UnitOfWork() as uow:
        found = await _active_analysis_task_id(uow.session, "proj-2")
    assert found is None


@pytest.mark.usefixtures("test_db")
async def test_other_project_not_detected() -> None:
    await _seed_task(task_id="t-other", project_id="proj-A", status="running")
    async with UnitOfWork() as uow:
        found = await _active_analysis_task_id(uow.session, "proj-B")
    assert found is None


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
    async with UnitOfWork() as uow:
        found = await _active_analysis_task_id(uow.session, "proj-3")
    assert found is None


def test_dedup_fn_path_matches_submit_derivation() -> None:
    """The guard filters TaskRecord.fn_path by a locally-derived dotted path.
    If that derivation ever diverges from what TaskQueue.submit actually stores,
    the query matches nothing and the dedup guard becomes a silent no-op. Anchor
    the derivation to the real submit path (_get_fn_path) rather than trusting
    the other tests, which seed rows with the same derived value (circular).

    _get_fn_path ignores config_registry/module_id (pure inspect over the
    callable), and @platform_task preserves the wrapped fn's __module__ and
    __qualname__, so the stored path equals module.__name__ + '.' + qualname.
    """
    stored = TaskQueue(
        config_registry=None, module_id="forensics",
    )._get_fn_path(run_forensics_analysis)
    assert _ANALYSIS_FN_PATH == stored
