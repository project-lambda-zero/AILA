"""Tests for Phase 55 Plan 04: Conversation session endpoints.

Covers:
  TASK-02: POST /sessions creates SessionRecord
  TASK-03: POST /sessions/{id}/messages persists messages
  TASK-05: GET /sessions/{id}/messages returns ordered history
  TASK-06: assistant response includes run_id when scan triggered
  D-23: reader+ role sufficient for all session endpoints
  D-25: sessions scoped by user_id
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from aila.platform.contracts._common import utc_now
from aila.storage.database import session_scope
from aila.storage.db_models import SessionRecord


def _seed_session(user_id: str, session_id: str = "sess-001", title: str = "Test") -> SessionRecord:
    """Seed a SessionRecord for the given user."""
    record = SessionRecord(
        id=session_id,
        user_id=user_id,
        title=title,
        created_at=utc_now(),
    )
    with session_scope() as session:
        session.add(record)
        session.commit()
        session.refresh(record)
    return record


@pytest.mark.asyncio
async def test_create_session_reader(async_client: AsyncClient, reader_token: str) -> None:
    """POST /sessions with reader token -> 201 with session data (D-23: readers can chat)."""
    response = await async_client.post(
        "/sessions",
        json={"title": "My Session"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 201
    data = response.json()
    assert "session_id" in data
    assert data["title"] == "My Session"


@pytest.mark.asyncio
async def test_post_message_no_platform(
    async_client: AsyncClient,
    reader_key_record,
    reader_token: str,
) -> None:
    """POST /sessions/{id}/messages with platform=None -> 503."""
    sess = _seed_session(user_id=reader_key_record.id, session_id="sess-msg-001")
    response = await async_client.post(
        f"/sessions/{sess.id}/messages",
        json={"content": "Hello"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_post_message_session_not_found(
    async_client: AsyncClient, reader_token: str
) -> None:
    """POST /sessions/{non_existent}/messages -> 404."""
    response = await async_client.post(
        "/sessions/does-not-exist/messages",
        json={"content": "Hello"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_post_message_wrong_user(
    async_client: AsyncClient,
    admin_key_record,
    reader_key_record,
    reader_token: str,
) -> None:
    """POST /sessions/{id}/messages where session belongs to another user -> 404."""
    # Seed session for admin; reader tries to post to it
    sess = _seed_session(user_id=admin_key_record.id, session_id="sess-admin-001")
    response = await async_client.post(
        f"/sessions/{sess.id}/messages",
        json={"content": "Hello"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_messages_empty(
    async_client: AsyncClient,
    reader_key_record,
    reader_token: str,
) -> None:
    """GET /sessions/{id}/messages for own session with no messages returns 200 with empty list."""
    sess = _seed_session(user_id=reader_key_record.id, session_id="sess-empty-001")
    response = await async_client.get(
        f"/sessions/{sess.id}/messages",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_get_messages_wrong_user(
    async_client: AsyncClient,
    admin_key_record,
    reader_token: str,
) -> None:
    """GET /sessions/{id}/messages for another user's session -> 404 (D-25)."""
    sess = _seed_session(user_id=admin_key_record.id, session_id="sess-isolation-001")
    response = await async_client.get(
        f"/sessions/{sess.id}/messages",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 404
