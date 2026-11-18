"""Focused regression tests for bounded session-message pagination."""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine

from aila.storage.database import async_session_scope
from aila.storage.db_models import ApiKeyRecord, SessionMessageRecord, SessionRecord


async def _seed_messages(
    user_id: str,
    count: int,
    session_id: str = "sess-paginated",
) -> str:
    """Create one owned session with deterministic chronological messages."""
    base = datetime(2026, 1, 1, tzinfo=UTC)
    async with async_session_scope() as db:
        db.add(SessionRecord(
            id=session_id,
            user_id=user_id,
            title="Pagination",
            created_at=base,
        ))
        for index in range(count):
            db.add(SessionMessageRecord(
                id=f"{session_id}-message-{index:03d}",
                session_id=session_id,
                role="user" if index % 2 == 0 else "assistant",
                content=f"message-{index:03d}",
                created_at=base + timedelta(seconds=index),
            ))
        await db.commit()
    return session_id


@pytest.mark.asyncio
async def test_get_messages_counts_and_pages_in_sql(
    async_client: AsyncClient,
    admin_token: str,
    admin_key_record: ApiKeyRecord,
    _session_async_engine: AsyncEngine,
) -> None:
    """The DB materializes only the requested page, not the full history."""
    session_id = await _seed_messages(admin_key_record.id, 125)
    statements: list[str] = []

    def _capture(_conn, _cursor, statement, _params, _context, _executemany) -> None:
        statements.append(statement)

    event.listen(_session_async_engine.sync_engine, "before_cursor_execute", _capture)
    try:
        response = await async_client.get(
            f"/sessions/{session_id}/messages?page=2&page_size=50",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
    finally:
        event.remove(_session_async_engine.sync_engine, "before_cursor_execute", _capture)

    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"total", "page", "page_size", "pages", "items"}
    assert body["total"] == 125
    assert body["page"] == 2
    assert body["page_size"] == 50
    assert body["pages"] == 3
    assert [item["content"] for item in body["items"]] == [
        f"message-{index:03d}" for index in range(50, 100)
    ]
    assert set(body["items"][0]) == {
        "message_id", "role", "content", "run_id", "created_at", "actions",
    }

    message_selects = [
        " ".join(statement.lower().split())
        for statement in statements
        if re.search(r"\bfrom\s+session_message_records\b", statement, re.IGNORECASE)
    ]
    count_selects = [statement for statement in message_selects if "count(" in statement]
    page_selects = [statement for statement in message_selects if "count(" not in statement]
    assert len(count_selects) == 1, f"Expected one SQL COUNT, got: {statements}"
    assert len(page_selects) == 1, f"Expected one message page query, got: {statements}"
    page_sql = page_selects[0]
    assert "where session_message_records.session_id =" in page_sql
    assert "order by session_message_records.created_at" in page_sql
    assert re.search(r"\blimit\b", page_sql), page_sql
    assert re.search(r"\boffset\b", page_sql), page_sql


@pytest.mark.asyncio
async def test_get_messages_out_of_range_preserves_metadata(
    async_client: AsyncClient,
    admin_token: str,
    admin_key_record: ApiKeyRecord,
) -> None:
    """Backend page requests are not silently clamped to the last page."""
    session_id = await _seed_messages(admin_key_record.id, 3, "sess-out-of-range")
    response = await async_client.get(
        f"/sessions/{session_id}/messages?page=4&page_size=2",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "total": 3,
        "page": 4,
        "page_size": 2,
        "pages": 2,
        "items": [],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("query", ["page=0", "page_size=0", "page_size=251"])
async def test_get_messages_preserves_page_validation(
    async_client: AsyncClient,
    admin_token: str,
    query: str,
) -> None:
    """Existing 1-based page and 1..250 page-size validation is unchanged."""
    response = await async_client.get(
        f"/sessions/sess-validation/messages?{query}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_messages_requires_authentication(async_client: AsyncClient) -> None:
    """The router-level auth dependency still rejects anonymous reads."""
    response = await async_client.get("/sessions/sess-anonymous/messages")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_messages_preserves_not_found_and_owner_isolation(
    async_client: AsyncClient,
    admin_token: str,
    admin_key_record: ApiKeyRecord,
    reader_token: str,
) -> None:
    """Unknown and other-owned sessions retain the same 404 behavior."""
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    missing = await async_client.get("/sessions/sess-missing/messages", headers=admin_headers)
    assert missing.status_code == 404
    assert "not found" in missing.json()["detail"].lower()

    session_id = await _seed_messages(admin_key_record.id, 1, "sess-admin-private")
    other_user = await async_client.get(
        f"/sessions/{session_id}/messages",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert other_user.status_code == 404
    assert "not found" in other_user.json()["detail"].lower()
