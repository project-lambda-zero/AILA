"""Integration tests for admin workflow inspection endpoints (Phase 181).

Tests:
- GET /admin/workflows/runs — list runs (admin only)
- GET /admin/workflows/runs/{run_id}/transitions — list transitions
- GET /admin/workflows/runs/{run_id}/transitions/{seq} — get one transition

Run: pytest tests/api/test_admin_workflows.py -v
"""
from __future__ import annotations

import pytest
import pytest_asyncio

from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord, WorkflowStateCursor, WorkflowStateTransition


@pytest_asyncio.fixture
async def workflow_run_with_cursor(test_db):
    """Seed a WorkflowRunRecord + WorkflowStateCursor for admin inspection."""
    rid = "admin-wf-test-001"
    async with async_session_scope() as session:
        run = WorkflowRunRecord(
            id=rid,
            query_text="admin inspection test",
            action_id="test.action",
            module_id="test",
        )
        session.add(run)
        cursor = WorkflowStateCursor(
            run_id=rid,
            current_state="__succeeded__",
            state_input={"done": True},
            retries_in_state=0,
            definition_id="test.toy.v1",
            version=2,
        )
        session.add(cursor)
        await session.commit()
    return rid


@pytest_asyncio.fixture
async def workflow_run_with_transitions(workflow_run_with_cursor):
    """Seed two WorkflowStateTransition rows."""
    rid = workflow_run_with_cursor
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
            duration_ms=50,
            happened_at=utc_now(),
        )
        session.add(t1)
        session.add(t2)
        await session.commit()
    return rid


# ---- GET /admin/workflows/runs -----------------------------------------------


@pytest.mark.asyncio
async def test_list_runs_requires_admin(async_client, reader_token):
    resp = await async_client.get(
        "/admin/workflows/runs",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_runs_requires_auth(async_client, test_db):
    resp = await async_client.get("/admin/workflows/runs")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_runs_empty(async_client, admin_token, test_db):
    resp = await async_client.get(
        "/admin/workflows/runs",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"] == []


@pytest.mark.asyncio
async def test_list_runs_returns_seeded_run(
    async_client, admin_token, workflow_run_with_cursor
):
    rid = workflow_run_with_cursor
    resp = await async_client.get(
        "/admin/workflows/runs",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert len(data) >= 1
    run = next((r for r in data if r["run_id"] == rid), None)
    assert run is not None
    assert run["current_state"] == "__succeeded__"
    assert run["definition_id"] == "test.toy.v1"
    assert run["version"] == 2


@pytest.mark.asyncio
async def test_list_runs_filter_by_definition_id(
    async_client, admin_token, workflow_run_with_cursor
):
    resp = await async_client.get(
        "/admin/workflows/runs",
        params={"definition_id": "test.toy.v1"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert all(r["definition_id"] == "test.toy.v1" for r in data)


@pytest.mark.asyncio
async def test_list_runs_filter_no_match(
    async_client, admin_token, workflow_run_with_cursor
):
    resp = await async_client.get(
        "/admin/workflows/runs",
        params={"definition_id": "nonexistent.v999"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"] == []


# ---- GET /admin/workflows/runs/{run_id}/transitions --------------------------


@pytest.mark.asyncio
async def test_list_run_transitions_empty(
    async_client, admin_token, workflow_run_with_cursor
):
    """A run with no transitions returns [] — not 404."""
    rid = workflow_run_with_cursor
    resp = await async_client.get(
        f"/admin/workflows/runs/{rid}/transitions",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"] == []


@pytest.mark.asyncio
async def test_list_run_transitions_returns_ordered(
    async_client, admin_token, workflow_run_with_transitions
):
    rid = workflow_run_with_transitions
    resp = await async_client.get(
        f"/admin/workflows/runs/{rid}/transitions",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert len(data) == 2
    assert data[0]["seq"] == 0
    assert data[0]["event"] == "entered"
    assert data[1]["seq"] == 1
    assert data[1]["event"] == "exited:ok"
    assert data[1]["duration_ms"] == 50


@pytest.mark.asyncio
async def test_list_run_transitions_requires_admin(
    async_client, reader_token, workflow_run_with_transitions
):
    rid = workflow_run_with_transitions
    resp = await async_client.get(
        f"/admin/workflows/runs/{rid}/transitions",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403


# ---- GET /admin/workflows/runs/{run_id}/transitions/{seq} --------------------


@pytest.mark.asyncio
async def test_get_single_transition_ok(
    async_client, admin_token, workflow_run_with_transitions
):
    rid = workflow_run_with_transitions
    resp = await async_client.get(
        f"/admin/workflows/runs/{rid}/transitions/1",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    t = resp.json()["data"]
    assert t["seq"] == 1
    assert t["event"] == "exited:ok"
    assert t["from_state"] == "start"
    assert t["to_state"] == "__succeeded__"
    assert t["duration_ms"] == 50
    assert t["run_id"] == rid


@pytest.mark.asyncio
async def test_get_single_transition_not_found(
    async_client, admin_token, workflow_run_with_transitions
):
    rid = workflow_run_with_transitions
    resp = await async_client.get(
        f"/admin/workflows/runs/{rid}/transitions/999",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_single_transition_requires_admin(
    async_client, reader_token, workflow_run_with_transitions
):
    rid = workflow_run_with_transitions
    resp = await async_client.get(
        f"/admin/workflows/runs/{rid}/transitions/0",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403
