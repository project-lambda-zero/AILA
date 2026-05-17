"""Wiring verification: session lifecycle round-trip (WIRE-08).

Tests prove the session create -> message -> history flow is wired
end-to-end through the real API stack. Uses async_client with a real
test DB (no mocks for persistence).

Endpoints under test:
  POST /sessions             -- create a session
  POST /sessions/{id}/messages -- send message (returns 503 with no platform)
  GET  /sessions/{id}/messages -- retrieve message history
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.anyio


async def test_session_create_message_history_roundtrip(
    async_client: AsyncClient,
    admin_token: str,
    admin_key_record,
) -> None:
    """Full round-trip: create session, attempt message (503), seed messages, read history."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Step 1: POST /sessions -- create a new session
    resp = await async_client.post(
        "/sessions",
        json={"title": "wiring test"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert "session_id" in body
    assert "user_id" in body
    assert body["title"] == "wiring test"
    assert "created_at" in body
    session_id = body["session_id"]

    # Step 2: POST /sessions/{session_id}/messages -- proves wiring reaches
    # the platform dependency. With platform=None the endpoint should:
    #   a) validate session ownership (pass -- we just created it)
    #   b) return 503 because platform is not initialized
    resp = await async_client.post(
        f"/sessions/{session_id}/messages",
        json={"content": "hello"},
        headers=headers,
    )
    assert resp.status_code == 503, f"Expected 503, got {resp.status_code}: {resp.text}"

    # Step 3: Seed messages directly via DB, then GET history
    from aila.storage.database import session_scope
    from aila.storage.db_models import SessionMessageRecord

    def _seed_messages() -> None:
        with session_scope() as db:
            db.add(SessionMessageRecord(
                session_id=session_id,
                role="user",
                content="hello",
            ))
            db.add(SessionMessageRecord(
                session_id=session_id,
                role="assistant",
                content="world",
            ))
            db.commit()

    import asyncio
    await asyncio.to_thread(_seed_messages)

    # GET /sessions/{session_id}/messages
    resp = await async_client.get(
        f"/sessions/{session_id}/messages",
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 2
    assert len(body["items"]) == 2
    roles = [item["role"] for item in body["items"]]
    assert "user" in roles
    assert "assistant" in roles
    contents = [item["content"] for item in body["items"]]
    assert "hello" in contents
    assert "world" in contents


async def test_session_returns_404_for_other_users_session(
    async_client: AsyncClient,
    admin_token: str,
    reader_token: str,
) -> None:
    """Sessions are scoped by user_id (D-25): reader cannot access admin's session."""
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    reader_headers = {"Authorization": f"Bearer {reader_token}"}

    # Create session as admin
    resp = await async_client.post(
        "/sessions",
        json={"title": "admin-only"},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    session_id = resp.json()["session_id"]

    # Reader tries to read admin's session messages -> 404
    resp = await async_client.get(
        f"/sessions/{session_id}/messages",
        headers=reader_headers,
    )
    assert resp.status_code == 404, f"Expected 404 (user scoping), got {resp.status_code}"


async def test_session_create_returns_401_without_auth(
    async_client: AsyncClient,
) -> None:
    """POST /sessions without auth header returns 401."""
    resp = await async_client.post(
        "/sessions",
        json={"title": "no-auth"},
    )
    assert resp.status_code == 401
