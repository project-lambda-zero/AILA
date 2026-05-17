"""Deep review tests for tasks router (Phase 71).

Covers branches NOT tested by test_tasks.py:
  - Cross-user task isolation for cancel, resume, and SSE (FILE-08 per-user scoping)
  - Cancel edge cases: FAILED, CANCELLED, RUNNING, nonexistent
  - Resume edge cases: QUEUED, DONE, FAILED, nonexistent
  - List filtering: track, status, combined
  - SSE edge cases: nonexistent task, inaccessible task
  - Submit endpoint: platform=None (503), reader RBAC (403)
  - Response shape: cancel/resume response content, has_checkpoint=False

FILE-08: every function read, every branch tested, zero dead code.
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
    # Phase 179: legacy cursor column dropped; parameter removed.
    record = TaskRecord(
        track=track,
        fn_path="test.fn",
        fn_module="test",
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


# ===========================================================================
# Group 1: Cross-user task isolation (FILE-08 per-user scoping)
# ===========================================================================


@pytest.mark.asyncio
async def test_cross_user_cancel_returns_404(
    async_client: AsyncClient,
    reader_token: str,
    operator_token: str,
    reader_key_record,
    operator_key_record,
    test_db,
) -> None:
    """FILE-08: operator cannot cancel a task scoped to the reader group."""
    task = _seed_task(status=TaskStatus.QUEUED, group_id="reader")

    response = await async_client.post(
        f"/tasks/{task.id}/cancel",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 404, (
        "Operator must not be able to cancel a reader-scoped task (FILE-08 cross-user isolation)"
    )


@pytest.mark.asyncio
async def test_cross_user_resume_returns_404(
    async_client: AsyncClient,
    reader_token: str,
    operator_token: str,
    reader_key_record,
    operator_key_record,
    test_db,
) -> None:
    """FILE-08: operator cannot resume a task scoped to the reader group."""
    task = _seed_task(status=TaskStatus.PAUSED, group_id="reader")

    response = await async_client.post(
        f"/tasks/{task.id}/resume",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 404, (
        "Operator must not be able to resume a reader-scoped task (FILE-08 cross-user isolation)"
    )


@pytest.mark.asyncio
async def test_cross_user_sse_returns_404(
    async_client: AsyncClient,
    operator_token: str,
    operator_key_record,
    test_db,
) -> None:
    """FILE-08: operator cannot stream SSE for a task scoped to the reader group."""
    task = _seed_task(status=TaskStatus.RUNNING, group_id="reader")

    response = await async_client.get(
        f"/tasks/{task.id}/events",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 404, (
        "Operator must not be able to stream SSE for a reader-scoped task (FILE-08)"
    )


@pytest.mark.asyncio
async def test_admin_can_cancel_any_group_task(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """FILE-08: admin bypass -- admin CAN cancel a task with any group_id."""
    task = _seed_task(status=TaskStatus.QUEUED, group_id="reader")

    response = await async_client.post(
        f"/tasks/{task.id}/cancel",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200, (
        "Admin must be able to cancel tasks in any group (admin bypass)"
    )


# ===========================================================================
# Group 2: Cancel edge cases
# ===========================================================================


@pytest.mark.asyncio
async def test_cancel_failed_task_returns_409(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """Cancel FAILED task returns 409 -- FAILED is a terminal state."""
    task = _seed_task(status=TaskStatus.FAILED, group_id="admin")

    response = await async_client.post(
        f"/tasks/{task.id}/cancel",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 409, (
        "Cancelling a FAILED task must return 409 (terminal state)"
    )


@pytest.mark.asyncio
async def test_cancel_cancelled_task_returns_409(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """Cancel already-CANCELLED task returns 409 -- CANCELLED is a terminal state."""
    task = _seed_task(status=TaskStatus.CANCELLED, group_id="admin")

    response = await async_client.post(
        f"/tasks/{task.id}/cancel",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 409, (
        "Cancelling an already-CANCELLED task must return 409 (terminal state)"
    )


@pytest.mark.asyncio
async def test_cancel_running_task_returns_200(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """Cancel RUNNING task returns 200 -- RUNNING is non-terminal."""
    task = _seed_task(status=TaskStatus.RUNNING, group_id="admin")

    response = await async_client.post(
        f"/tasks/{task.id}/cancel",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200, (
        "Cancelling a RUNNING task must return 200 (non-terminal)"
    )


@pytest.mark.asyncio
async def test_cancel_nonexistent_task_returns_404(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """Cancel nonexistent task returns 404."""
    response = await async_client.post(
        "/tasks/nonexistent-task-000/cancel",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 404


# ===========================================================================
# Group 3: Resume edge cases
# ===========================================================================


@pytest.mark.asyncio
async def test_resume_queued_task_returns_409(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """Resume QUEUED task returns 409 -- only PAUSED allowed."""
    task = _seed_task(status=TaskStatus.QUEUED, group_id="admin")

    response = await async_client.post(
        f"/tasks/{task.id}/resume",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 409, (
        "Resuming a QUEUED task must return 409 (only PAUSED -> QUEUED allowed)"
    )


@pytest.mark.asyncio
async def test_resume_done_task_returns_409(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """Resume DONE task returns 409 -- terminal state."""
    task = _seed_task(status=TaskStatus.DONE, group_id="admin")

    response = await async_client.post(
        f"/tasks/{task.id}/resume",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 409, (
        "Resuming a DONE task must return 409 (terminal state)"
    )


@pytest.mark.asyncio
async def test_resume_failed_task_returns_409(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """Resume FAILED task returns 409 -- terminal state."""
    task = _seed_task(status=TaskStatus.FAILED, group_id="admin")

    response = await async_client.post(
        f"/tasks/{task.id}/resume",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 409, (
        "Resuming a FAILED task must return 409 (terminal state)"
    )


@pytest.mark.asyncio
async def test_resume_nonexistent_task_returns_404(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """Resume nonexistent task returns 404."""
    response = await async_client.post(
        "/tasks/nonexistent-task-000/resume",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 404


# ===========================================================================
# Group 4: List filtering
# ===========================================================================


@pytest.mark.asyncio
async def test_list_with_track_filter(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """FILE-08: list with track filter returns only matching tasks."""
    _seed_task(status=TaskStatus.QUEUED, group_id="admin", track="vuln")
    _seed_task(status=TaskStatus.QUEUED, group_id="admin", track="platform")

    response = await async_client.get(
        "/tasks?track=vuln",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    for task in data["tasks"]:
        assert task["track"] == "vuln", "Track filter must narrow results to matching track"


@pytest.mark.asyncio
async def test_list_with_status_filter(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """FILE-08: list with status filter returns only matching tasks."""
    _seed_task(status=TaskStatus.QUEUED, group_id="admin")
    _seed_task(status=TaskStatus.RUNNING, group_id="admin")
    _seed_task(status=TaskStatus.DONE, group_id="admin")

    response = await async_client.get(
        "/tasks?status=running",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    for task in data["tasks"]:
        assert task["status"] == "running", "Status filter must narrow results to matching status"


@pytest.mark.asyncio
async def test_list_with_track_and_status_filter(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """FILE-08: list with both track and status filter narrows correctly."""
    _seed_task(status=TaskStatus.QUEUED, group_id="admin", track="vuln")
    _seed_task(status=TaskStatus.RUNNING, group_id="admin", track="vuln")
    _seed_task(status=TaskStatus.QUEUED, group_id="admin", track="platform")

    response = await async_client.get(
        "/tasks?track=vuln&status=queued",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    for task in data["tasks"]:
        assert task["track"] == "vuln", "Combined filter must match track"
        assert task["status"] == "queued", "Combined filter must match status"


# ===========================================================================
# Group 5: SSE edge cases
# ===========================================================================


@pytest.mark.asyncio
async def test_sse_nonexistent_task_returns_404(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """FILE-08: SSE events for nonexistent task returns 404 before stream opens."""
    response = await async_client.get(
        "/tasks/nonexistent-task-000/events",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_sse_inaccessible_task_returns_404(
    async_client: AsyncClient,
    operator_token: str,
    operator_key_record,
    test_db,
) -> None:
    """FILE-08: SSE events for task in wrong group returns 404 before stream opens."""
    task = _seed_task(status=TaskStatus.RUNNING, group_id="reader")

    response = await async_client.get(
        f"/tasks/{task.id}/events",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 404, (
        "SSE must return 404 for inaccessible tasks before opening the stream"
    )


# ===========================================================================
# Group 6: Submit endpoint (POST /task)
# ===========================================================================


@pytest.mark.asyncio
async def test_submit_task_without_platform_returns_503(
    async_client: AsyncClient,
    operator_token: str,
    operator_key_record,
    test_db,
) -> None:
    """FILE-08: submit task without platform returns 503.

    async_client sets platform=None, which is the trigger for the 503 path.
    """
    response = await async_client.post(
        "/task",
        json={"query_text": "scan web01"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 503, (
        "Submit must return 503 when platform is not initialized"
    )


@pytest.mark.asyncio
async def test_submit_task_reader_gets_403(
    async_client: AsyncClient,
    reader_token: str,
    reader_key_record,
    test_db,
) -> None:
    """FILE-08: submit task requires operator+ role -- reader gets 403."""
    response = await async_client.post(
        "/task",
        json={"query_text": "scan web01"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 403, (
        "Reader must get 403 on POST /task (requires operator+ role)"
    )


# ===========================================================================
# Group 7: Response shape
# ===========================================================================


@pytest.mark.asyncio
async def test_cancel_response_contains_task_id_and_status(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """FILE-08: cancel response contains task_id and status='cancelled'."""
    task = _seed_task(status=TaskStatus.QUEUED, group_id="admin")

    response = await async_client.post(
        f"/tasks/{task.id}/cancel",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["task_id"] == task.id
    assert data["status"] == "cancelled"


@pytest.mark.asyncio
async def test_resume_response_contains_task_id_and_status(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """FILE-08: resume response contains task_id and status='queued'."""
    task = _seed_task(status=TaskStatus.PAUSED, group_id="admin")

    response = await async_client.post(
        f"/tasks/{task.id}/resume",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["task_id"] == task.id
    assert data["status"] == "queued"


@pytest.mark.asyncio
async def test_has_checkpoint_always_false_phase_179(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """Phase 179: legacy cursor column dropped; has_checkpoint is always False.

    The schema field is retained until Phase 180 wires a workflow-cursor
    lookup to surface engine cursor presence.
    """
    task = _seed_task(status=TaskStatus.QUEUED, group_id="admin")

    response = await async_client.get(
        f"/tasks/{task.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["has_checkpoint"] is False
