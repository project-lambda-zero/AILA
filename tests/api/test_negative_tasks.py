"""Negative tests for tasks endpoints: 403, 404, 503 error paths.

Covers:
  GET  /tasks/{id}          - 404 not found
  POST /tasks/{id}/cancel   - 404 not found
  POST /tasks/{id}/resume   - 404 not found
  POST /task                - 403 reader forbidden, 503 no platform
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

# -- GET /tasks/{id} -----------------------------------------------------------


@pytest.mark.asyncio
async def test_get_task_not_found(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /tasks/nonexistent-uuid returns 404."""
    resp = await async_client.get(
        "/tasks/nonexistent-task-uuid",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "not found" in detail.lower()


# -- POST /tasks/{id}/cancel ---------------------------------------------------


@pytest.mark.asyncio
async def test_cancel_task_not_found(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /tasks/nonexistent/cancel returns 404."""
    resp = await async_client.post(
        "/tasks/nonexistent-task-uuid/cancel",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "not found" in detail.lower()


# -- POST /tasks/{id}/resume ---------------------------------------------------


@pytest.mark.asyncio
async def test_resume_task_not_found(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /tasks/nonexistent/resume returns 404."""
    resp = await async_client.post(
        "/tasks/nonexistent-task-uuid/resume",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "not found" in detail.lower()


# -- POST /task ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_submit_task_reader_forbidden(
    async_client: AsyncClient, reader_token: str
) -> None:
    """POST /task with reader token returns 403 (operator+ required)."""
    resp = await async_client.post(
        "/task",
        json={"query_text": "scan all"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert "operator" in detail.lower()


@pytest.mark.asyncio
async def test_submit_task_no_platform(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /task with platform=None returns 503.

    The async_client fixture sets app.state.platform = None.
    """
    resp = await async_client.post(
        "/task",
        json={"query_text": "scan all"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert "platform" in detail.lower()
