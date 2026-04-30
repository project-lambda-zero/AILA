"""Negative tests for sessions endpoints: 404, 503 error paths.

Covers:
  GET  /sessions/{id}/messages  - 404 nonexistent, 404 wrong user
  POST /sessions/{id}/messages  - 404 nonexistent, 503 no platform
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


# -- GET /sessions/{id}/messages -----------------------------------------------


@pytest.mark.asyncio
async def test_get_messages_nonexistent_session(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /sessions/fake-id/messages returns 404 for nonexistent session."""
    resp = await async_client.get(
        "/sessions/nonexistent-session-id/messages",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "not found" in detail.lower()


@pytest.mark.asyncio
async def test_get_messages_wrong_user(
    async_client: AsyncClient, admin_token: str, reader_token: str
) -> None:
    """Session created by admin is not visible to reader (user scoping -> 404)."""
    # Admin creates a session
    resp_create = await async_client.post(
        "/sessions",
        json={"title": "admin-only-session"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_create.status_code == 201
    session_id = resp_create.json()["session_id"]

    # Reader tries to read messages from admin's session -> 404
    resp = await async_client.get(
        f"/sessions/{session_id}/messages",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "not found" in detail.lower() or "another user" in detail.lower()


# -- POST /sessions/{id}/messages ----------------------------------------------


@pytest.mark.asyncio
async def test_post_message_nonexistent(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /sessions/fake-id/messages returns 404."""
    resp = await async_client.post(
        "/sessions/nonexistent-session-id/messages",
        json={"content": "hello"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "not found" in detail.lower()


@pytest.mark.asyncio
async def test_post_message_no_platform(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST message to a valid session with platform=None returns 503.

    The async_client fixture sets app.state.platform = None.
    A valid session must exist first, then the 503 fires.
    """
    # Create a session so the session exists
    resp_create = await async_client.post(
        "/sessions",
        json={"title": "platform-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_create.status_code == 201
    session_id = resp_create.json()["session_id"]

    resp = await async_client.post(
        f"/sessions/{session_id}/messages",
        json={"content": "hello"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert "platform" in detail.lower()
