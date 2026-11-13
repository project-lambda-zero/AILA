"""Negative tests for tasks endpoints: 403, 404, 503 error paths.

Covers:
  GET  /tasks/{id}          - 404 not found
  POST /tasks/{id}/cancel   - 404 not found
  POST /tasks/{id}/resume   - 404 not found
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

