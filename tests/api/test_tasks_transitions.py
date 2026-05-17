"""Integration tests for GET /tasks/{task_id}/transitions operator endpoint (Phase 181).

Verifies:
- 404 when task does not exist
- 200 with empty list when task exists but has no workflow transitions
- 200 with ordered transition list when transitions exist
- 401 when no auth provided

Run: pytest tests/api/test_tasks_transitions.py -v
"""
from __future__ import annotations

import pytest
import pytest_asyncio

from aila.platform.contracts._common import utc_now
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord, WorkflowStateTransition


@pytest_asyncio.fixture
async def task_with_run(test_db, admin_key_record):
    """Create a TaskRecord + WorkflowRunRecord sharing the same id."""
    rid = "test-transitions-run-001"
    async with async_session_scope() as session:
        # Parent WorkflowRunRecord required by FK on WorkflowStateTransition
        run = WorkflowRunRecord(
            id=rid,
            query_text="test scan",
            action_id="vulnerability.analyze",
            module_id="vulnerability",
        )
        session.add(run)
        # TaskRecord with same id — required by TaskRepository.get_for_user
        task = TaskRecord(
            id=rid,
            track="vulnerability",
            fn_path="aila.api.routers.scans:run_platform_handle",
            fn_module="__platform__",
            status=TaskStatus.DONE,
            user_id=admin_key_record.id,
            group_id="admin",
        )
        session.add(task)
        await session.commit()
    return rid


@pytest_asyncio.fixture
async def task_with_transitions(task_with_run):
    """Seed two WorkflowStateTransition rows for task_with_run."""
    rid = task_with_run
    async with async_session_scope() as session:
        t1 = WorkflowStateTransition(
            run_id=rid,
            seq=0,
            from_state="start",
            to_state="start",
            event="entered",
            happened_at=utc_now(),
        )
        t2 = WorkflowStateTransition(
            run_id=rid,
            seq=1,
            from_state="start",
            to_state="__succeeded__",
            event="exited:ok",
            duration_ms=123,
            happened_at=utc_now(),
        )
        session.add(t1)
        session.add(t2)
        await session.commit()
    return rid


@pytest.mark.asyncio
async def test_transitions_404_unknown_task(async_client, admin_token):
    resp = await async_client.get(
        "/tasks/does-not-exist/transitions",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_transitions_401_no_auth(async_client, task_with_run):
    resp = await async_client.get(f"/tasks/{task_with_run}/transitions")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_transitions_empty_list_for_non_workflow_task(
    async_client, admin_token, task_with_run
):
    """A task with no WorkflowStateTransition rows returns [] — not 404."""
    resp = await async_client.get(
        f"/tasks/{task_with_run}/transitions",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"] == []


@pytest.mark.asyncio
async def test_transitions_returns_ordered_rows(
    async_client, admin_token, task_with_transitions
):
    """Transitions are returned oldest-first (seq ASC) with correct fields."""
    rid = task_with_transitions
    resp = await async_client.get(
        f"/tasks/{rid}/transitions",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert len(data) == 2
    # First row: entered
    assert data[0]["seq"] == 0
    assert data[0]["event"] == "entered"
    assert data[0]["run_id"] == rid
    assert data[0]["to_state"] == "start"
    # Second row: exited:ok
    assert data[1]["seq"] == 1
    assert data[1]["event"] == "exited:ok"
    assert data[1]["to_state"] == "__succeeded__"
    assert data[1]["duration_ms"] == 123
    # input_hash / output_hash NOT in the response (omitted by TransitionView)
    assert "input_hash" not in data[0]
    assert "output_hash" not in data[0]


@pytest.mark.asyncio
async def test_transitions_task_id_echoed_in_each_row(
    async_client, admin_token, task_with_transitions
):
    """Each TransitionView.task_id equals the task_id path param."""
    rid = task_with_transitions
    resp = await async_client.get(
        f"/tasks/{rid}/transitions",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    data = resp.json()["data"]
    for row in data:
        assert row["task_id"] == rid
