"""Integration tests for /tasks API routes (Phase 54, Plan 06).

Requirements covered:
  MOD-09 (resume PAUSED→QUEUED), MOD-12 (has_checkpoint field), MOD-13 (group_id scoping)
  INFRA-06 (result_path is Text/path not blob)
  TASK-08, TASK-09 (SSE endpoint returns text/event-stream)

Pattern: use async_client from conftest.py (ASGITransport, no TestClient),
         seed TaskRecord directly via session_scope, then call API routes.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import session_scope

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_task(
    status: TaskStatus = TaskStatus.QUEUED,
    group_id: str = "reader",
    user_id: str = "user-test-001",
    track: str = "vuln",
    result_path: str | None = None,
) -> TaskRecord:
    """Seed a TaskRecord directly into the test DB. Returns the created record."""
    # Phase 179: legacy cursor column dropped from TaskRecord.
    record = TaskRecord(
        track=track,
        fn_path="aila.modules.vulnerability.tasks.scan",
        fn_module="vulnerability",
        status=status,
        user_id=user_id,
        group_id=group_id,
        result_path=result_path,
    )
    with session_scope() as session:
        session.add(record)
        session.commit()
        session.refresh(record)
    return record


# ---------------------------------------------------------------------------
# 1. test_get_tasks_empty_returns_list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_tasks_empty_returns_list(
    async_client: AsyncClient, admin_token: str, test_db
) -> None:
    """GET /tasks returns 200 with {"tasks": [], "total": 0} when no tasks seeded."""
    response = await async_client.get(
        "/tasks",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "tasks" in data, "Response must have 'tasks' key"
    assert isinstance(data["tasks"], list)
    assert "total" in data, "Response must have 'total' key"
    assert data["total"] == 0


# ---------------------------------------------------------------------------
# 2. test_get_tasks_scoped_by_role (MOD-13 / D-22)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_tasks_scoped_by_role(
    async_client: AsyncClient,
    admin_token: str,
    reader_token: str,
    reader_key_record,
    operator_token: str,
    test_db,
) -> None:
    """Reader sees tasks with group_id=reader; operator does NOT see them (MOD-13 / D-22).

    Admin sees ALL tasks regardless of group_id.
    """
    # Seed a task belonging to the reader group
    task = _seed_task(status=TaskStatus.QUEUED, group_id="reader")

    # Admin sees it
    admin_resp = await async_client.get(
        "/tasks",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert admin_resp.status_code == 200
    admin_data = admin_resp.json()
    assert admin_data["total"] >= 1, "Admin must see all tasks"
    task_ids = [t["task_id"] for t in admin_data["tasks"]]
    assert task.id in task_ids, "Admin must see the reader task"

    # Reader sees it (group_id matches reader.role="reader")
    reader_resp = await async_client.get(
        "/tasks",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert reader_resp.status_code == 200
    reader_data = reader_resp.json()
    assert reader_data["total"] >= 1, "Reader must see tasks in their group"
    reader_task_ids = [t["task_id"] for t in reader_data["tasks"]]
    assert task.id in reader_task_ids, "Reader must see the reader-scoped task"

    # Operator does NOT see reader's task (operator.role="operator" != "reader")
    operator_resp = await async_client.get(
        "/tasks",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert operator_resp.status_code == 200
    operator_data = operator_resp.json()
    operator_task_ids = [t["task_id"] for t in operator_data["tasks"]]
    assert task.id not in operator_task_ids, (
        "Operator must NOT see tasks scoped to reader group (MOD-13)"
    )


# ---------------------------------------------------------------------------
# 3. test_get_task_by_id_not_found_returns_404
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_task_by_id_not_found_returns_404(
    async_client: AsyncClient, admin_token: str, test_db
) -> None:
    """GET /tasks/{nonexistent_id} returns 404."""
    response = await async_client.get(
        "/tasks/nonexistent-task-id-000",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# 4. test_get_task_by_id_wrong_group_returns_404
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_task_by_id_wrong_group_returns_404(
    async_client: AsyncClient, operator_token: str, operator_key_record, test_db
) -> None:
    """Operator cannot see a task whose group_id=reader; returns 404."""
    # Seed a task for reader group
    task = _seed_task(status=TaskStatus.QUEUED, group_id="reader")

    # Operator tries to access it -- should be 404 (not visible to different group)
    response = await async_client.get(
        f"/tasks/{task.id}",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# 5. test_task_response_has_result_path_and_has_checkpoint (INFRA-06, MOD-12)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_task_response_has_result_path_and_has_checkpoint(
    async_client: AsyncClient, admin_token: str, test_db
) -> None:
    """TaskResponse includes result_path (INFRA-06) and has_checkpoint (Phase 179).

    Phase 179: has_checkpoint is now always False (legacy cursor column
    dropped; cursor state is in workflow_state_cursor and will surface via
    Phase 180's wiring).
    """
    task = _seed_task(
        status=TaskStatus.DONE,
        group_id="admin",
        result_path="/reports/vuln_scan_001.json",
    )

    response = await async_client.get(
        f"/tasks/{task.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()

    # INFRA-06: result_path is a filesystem path string, not a blob
    assert "result_path" in data, "TaskResponse must include result_path (INFRA-06)"
    assert data["result_path"] == "/reports/vuln_scan_001.json"

    # Phase 179: has_checkpoint field retained for wire compatibility; always False.
    assert "has_checkpoint" in data
    assert data["has_checkpoint"] is False


# ---------------------------------------------------------------------------
# 6. test_cancel_queued_task_returns_200
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cancel_queued_task_returns_200(
    async_client: AsyncClient, admin_token: str, test_db
) -> None:
    """POST /tasks/{id}/cancel on a QUEUED task returns 200 and status=cancelled."""
    task = _seed_task(status=TaskStatus.QUEUED, group_id="admin")

    cancel_resp = await async_client.post(
        f"/tasks/{task.id}/cancel",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert cancel_resp.status_code == 200

    # Verify via GET that status is now cancelled
    get_resp = await async_client.get(
        f"/tasks/{task.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["status"] == "cancelled"


# ---------------------------------------------------------------------------
# 7. test_cancel_done_task_returns_409
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cancel_done_task_returns_409(
    async_client: AsyncClient, admin_token: str, test_db
) -> None:
    """POST /tasks/{id}/cancel on a DONE task returns 409 (already terminal)."""
    task = _seed_task(status=TaskStatus.DONE, group_id="admin")

    response = await async_client.post(
        f"/tasks/{task.id}/cancel",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 409, (
        "Cancelling a DONE task must return 409 Conflict"
    )


# ---------------------------------------------------------------------------
# 8. test_resume_paused_task_returns_200 (MOD-09)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resume_paused_task_returns_200(
    async_client: AsyncClient, admin_token: str, test_db
) -> None:
    """POST /tasks/{id}/resume on a PAUSED task returns 200; GET shows status=queued (MOD-09)."""
    task = _seed_task(status=TaskStatus.PAUSED, group_id="admin")

    resume_resp = await async_client.post(
        f"/tasks/{task.id}/resume",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resume_resp.status_code == 200, (
        f"MOD-09: resume of PAUSED task must return 200, got {resume_resp.status_code}"
    )

    # Verify status is now queued
    get_resp = await async_client.get(
        f"/tasks/{task.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["status"] == "queued", (
        "MOD-09: resumed task must have status=queued"
    )


# ---------------------------------------------------------------------------
# 9. test_resume_running_task_returns_409
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resume_running_task_returns_409(
    async_client: AsyncClient, admin_token: str, test_db
) -> None:
    """POST /tasks/{id}/resume on a RUNNING task returns 409 (only PAUSED can resume)."""
    task = _seed_task(status=TaskStatus.RUNNING, group_id="admin")

    response = await async_client.post(
        f"/tasks/{task.id}/resume",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 409, (
        "Resuming a RUNNING task must return 409 (only PAUSED → QUEUED allowed)"
    )


# ---------------------------------------------------------------------------
# 10. test_tasks_require_auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tasks_require_auth(async_client: AsyncClient, test_db) -> None:
    """GET /tasks without Bearer token returns 401."""
    response = await async_client.get("/tasks")
    assert response.status_code == 401, (
        "Unauthenticated GET /tasks must return 401"
    )


# ---------------------------------------------------------------------------
# 11. test_sse_events_endpoint_returns_streaming_response (TASK-08/09)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sse_events_endpoint_returns_streaming_response(
    async_client: AsyncClient, admin_token: str, test_db
) -> None:
    """GET /tasks/{id}/events returns content-type text/event-stream (TASK-08/09).

    When Redis is not configured, the endpoint returns a single informational
    SSE message. The response content-type must be text/event-stream regardless.
    """
    task = _seed_task(status=TaskStatus.RUNNING, group_id="admin")

    response = await async_client.get(
        f"/tasks/{task.id}/events",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200, (
        f"TASK-08: SSE endpoint must return 200, got {response.status_code}"
    )
    # The content-type must be text/event-stream (SSE)
    content_type = response.headers.get("content-type", "")
    assert "text/event-stream" in content_type, (
        f"TASK-09: content-type must be text/event-stream, got {content_type!r}"
    )


# ---------------------------------------------------------------------------
# Bonus: test_get_task_by_id_returns_full_response
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_task_by_id_returns_full_response(
    async_client: AsyncClient, admin_token: str, test_db
) -> None:
    """GET /tasks/{id} returns a full TaskResponse with all required fields."""
    task = _seed_task(status=TaskStatus.QUEUED, group_id="admin")

    response = await async_client.get(
        f"/tasks/{task.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()

    # Verify all required fields are present
    required_fields = {
        "task_id", "track", "status", "user_id", "group_id",
        "fn_path", "fn_module", "created_at", "has_checkpoint",
    }
    for field in required_fields:
        assert field in data, f"TaskResponse must include '{field}' field"

    assert data["task_id"] == task.id
    assert data["status"] == "queued"
    assert data["track"] == "vuln"
