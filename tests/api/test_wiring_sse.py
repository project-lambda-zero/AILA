"""Wiring verification: SSE streaming endpoints (WIRE-07).

Tests prove that SSE scan and task progress endpoints return correct
content-type, emit SSE-formatted events, and handle missing tasks with 404.

Without Redis configured (platform=None in tests), both SSE endpoints
gracefully return a single informational event and close.

Endpoints under test:
  GET /scans/{run_id}/events   -- scan progress SSE stream
  GET /tasks/{task_id}/events  -- task progress SSE stream
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import session_scope

pytestmark = pytest.mark.anyio


def _seed_task_record(
    *,
    task_id: str,
    track: str = "vulnerability",
    status: str = TaskStatus.RUNNING,
    user_id: str = "test-user",
    group_id: str = "admin",
    fn_path: str = "aila.modules.vulnerability.tasks.scan",
    fn_module: str = "vulnerability",
) -> TaskRecord:
    """Insert a TaskRecord directly into the test DB."""
    record = TaskRecord(
        id=task_id,
        track=track,
        status=status,
        user_id=user_id,
        group_id=group_id,
        fn_path=fn_path,
        fn_module=fn_module,
        kwargs_json='{"query": "test"}',
    )
    with session_scope() as session:
        session.add(record)
        session.commit()
        session.refresh(record)
    return record


async def test_sse_scan_events_returns_sse_content_type(
    async_client: AsyncClient,
    admin_token: str,
    admin_key_record,
) -> None:
    """GET /scans/{run_id}/events returns text/event-stream with SSE data.

    Without Redis, the endpoint returns a single informational event
    indicating Redis is not configured and closes the stream.
    Proves: auth works, task lookup works, SSE format correct.
    """
    headers = {"Authorization": f"Bearer {admin_token}"}

    record = _seed_task_record(
        task_id="scan-sse-001",
        user_id=admin_key_record.id,
        group_id=admin_key_record.role,
    )

    resp = await async_client.get(
        f"/scans/{record.id}/events",
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert "text/event-stream" in resp.headers.get("content-type", "")
    # SSE format: lines starting with "data:"
    assert "data:" in resp.text
    # Should mention Redis not configured (graceful fallback)
    assert "Redis not configured" in resp.text


async def test_sse_task_events_returns_sse_content_type(
    async_client: AsyncClient,
    admin_token: str,
    admin_key_record,
) -> None:
    """GET /tasks/{task_id}/events returns text/event-stream with SSE data.

    Without Redis, the endpoint returns a single informational event
    and closes. Proves the task SSE endpoint is wired identically to scans.
    """
    headers = {"Authorization": f"Bearer {admin_token}"}

    record = _seed_task_record(
        task_id="task-sse-001",
        user_id=admin_key_record.id,
        group_id=admin_key_record.role,
    )

    resp = await async_client.get(
        f"/tasks/{record.id}/events",
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert "text/event-stream" in resp.headers.get("content-type", "")
    assert "data:" in resp.text
    assert "Redis not configured" in resp.text


async def test_sse_scan_events_returns_404_for_nonexistent(
    async_client: AsyncClient,
    admin_token: str,
) -> None:
    """GET /scans/nonexistent-id/events returns 404.

    Proves: auth passes, task lookup runs, and missing tasks get 404 (not 500).
    """
    headers = {"Authorization": f"Bearer {admin_token}"}

    resp = await async_client.get(
        "/scans/nonexistent-id/events",
        headers=headers,
    )
    assert resp.status_code == 404, resp.text
    assert "not found" in resp.json()["detail"].lower()
