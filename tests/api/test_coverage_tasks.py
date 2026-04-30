"""Coverage tests for tasks.py router uncovered paths.

Targets lines 241, 249-253, 269-307, 347-358 in src/aila/api/routers/tasks.py.

- SSE endpoint 404 path (line 241)
- SSE endpoint with platform present but Redis config exception (lines 249-253)
- submit_task with mock platform that has task_queue.submit (lines 347-358)
- cancel/resume additional paths not yet covered by existing tests

Uses async_client and async_client_with_registries fixtures from conftest.
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import session_scope


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_task(
    status: str = TaskStatus.QUEUED,
    group_id: str = "admin",
    user_id: str = "user-cov-001",
    track: str = "vuln",
) -> TaskRecord:
    """Seed a TaskRecord directly into the test DB."""
    record = TaskRecord(
        track=track,
        fn_path="aila.modules.vulnerability.tasks.scan",
        fn_module="vulnerability",
        status=status,
        user_id=user_id,
        group_id=group_id,
    )
    with session_scope() as session:
        session.add(record)
        session.commit()
        session.refresh(record)
    return record


# ---------------------------------------------------------------------------
# SSE endpoint: 404 for nonexistent task (line 241)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sse_events_task_not_found(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """GET /tasks/{nonexistent}/events returns 404.

    Covers line 241 (record is None -> HTTPException).
    """
    resp = await async_client.get(
        "/tasks/nonexistent-task-id/events",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# SSE endpoint with platform present but config_registry.get raises (lines 249-253)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def async_client_with_failing_config(test_db):
    """Client where platform.runtime.config_registry.get raises an exception.

    This exercises the except block at lines 249-253 in stream_task_events.
    """
    from aila.api.app import create_app

    stub_config = MagicMock()
    stub_config.get.side_effect = RuntimeError("config unavailable")

    stub_runtime = MagicMock()
    stub_runtime.config_registry = stub_config

    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app = create_app()
    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_sse_events_redis_config_error(
    async_client_with_failing_config: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """GET /tasks/{id}/events when config_registry.get raises falls back to no-Redis SSE.

    Covers lines 249-253 (exception in config_registry.get -> redis_url stays None).
    """
    task = _seed_task(status=TaskStatus.RUNNING, group_id="admin")

    resp = await async_client_with_failing_config.get(
        f"/tasks/{task.id}/events",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    content_type = resp.headers.get("content-type", "")
    assert "text/event-stream" in content_type
    # Falls back to the no-redis informational message
    assert "Redis not configured" in resp.text or "no progress stream" in resp.text


# ---------------------------------------------------------------------------
# POST /task with mocked platform.task_queue.submit (lines 347-358)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def async_client_with_task_queue(test_db):
    """Client where platform.task_queue.submit() returns a TaskHandle.

    This exercises the submit_task success path (lines 347-358).
    """
    from aila.api.app import create_app
    from aila.platform.tasks.models import TaskHandle

    mock_handle = TaskHandle(task_id="submitted-task-001")
    stub_task_queue = MagicMock()
    stub_task_queue.submit.return_value = mock_handle

    stub_platform = MagicMock()
    stub_platform.task_queue = stub_task_queue

    test_app = create_app()
    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_submit_task_success(
    async_client_with_task_queue: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """POST /task with platform and task_queue returns 202 with run_id.

    Covers lines 347-358 (submit_task success path).
    """
    resp = await async_client_with_task_queue.post(
        "/task",
        json={"query_text": "scan all systems"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["run_id"] == "submitted-task-001"
    assert data["status"] == "submitted"


# ---------------------------------------------------------------------------
# Cancel task: covers exists check -> 404 and -> 409 paths
# The test_tasks.py already covers the basic cancel path (queued -> cancelled)
# and cancel done -> 409. Add: cancel nonexistent -> 404 (via admin who can
# see all, so the exists check in _cancel path is actually reached).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cancel_failed_task_returns_409(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """POST /tasks/{id}/cancel on FAILED task returns 409 (terminal state).

    Covers the exists=True -> 409 path in cancel_task (lines 169-172).
    """
    task = _seed_task(status=TaskStatus.FAILED, group_id="admin")

    resp = await async_client.post(
        f"/tasks/{task.id}/cancel",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 409
    assert "terminal" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_cancel_cancelled_task_returns_409(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """POST /tasks/{id}/cancel on already CANCELLED task returns 409."""
    task = _seed_task(status=TaskStatus.CANCELLED, group_id="admin")

    resp = await async_client.post(
        f"/tasks/{task.id}/cancel",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Resume task: additional edge case -- resume a done task -> 409
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resume_done_task_returns_409(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """POST /tasks/{id}/resume on DONE task returns 409 (not paused).

    Covers the exists=True -> 409 branch in resume_task (lines 208-210).
    """
    task = _seed_task(status=TaskStatus.DONE, group_id="admin")

    resp = await async_client.post(
        f"/tasks/{task.id}/resume",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 409
    assert "PAUSED" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_resume_queued_task_returns_409(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """POST /tasks/{id}/resume on QUEUED task returns 409 (not paused)."""
    task = _seed_task(status=TaskStatus.QUEUED, group_id="admin")

    resp = await async_client.post(
        f"/tasks/{task.id}/resume",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# List tasks with track/status filters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_tasks_filter_by_track(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """GET /tasks?track=vuln filters by track."""
    _seed_task(track="vuln", group_id="admin")
    _seed_task(track="platform", group_id="admin")

    resp = await async_client.get(
        "/tasks?track=vuln",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert all(t["track"] == "vuln" for t in data["tasks"])


@pytest.mark.asyncio
async def test_list_tasks_filter_by_status(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """GET /tasks?status=done filters by status."""
    _seed_task(status=TaskStatus.DONE, group_id="admin")
    _seed_task(status=TaskStatus.QUEUED, group_id="admin")

    resp = await async_client.get(
        "/tasks?status=done",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert all(t["status"] == "done" for t in data["tasks"])
