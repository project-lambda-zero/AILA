"""Comprehensive deep-review tests for sessions router (Phase 69).

Covers behaviors NOT tested by existing suites:
  - SSE content negotiation (Accept: text/event-stream dispatches to SSE vs JSON)
  - Message persistence after SSE stream completion
  - User isolation across all three endpoints with platform present
  - Edge cases: nonexistent session on SSE path, platform=None on SSE path,
    done sentinel run_id, Accept header variations

Existing tests in test_55_04_sessions.py, test_wiring_sessions.py, and
test_negative_sessions.py cover: basic create, basic post (no-platform 503),
basic get, basic wrong-user 404, basic nonexistent 404.  This file does NOT
duplicate those.
"""
from __future__ import annotations

import json
import time
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.platform.contracts._common import utc_now
from aila.storage.database import session_scope
from aila.storage.db_models import SessionRecord

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_session(
    user_id: str,
    session_id: str = "sess-deep-001",
    title: str = "Deep Review",
) -> SessionRecord:
    """Insert a SessionRecord into the test database."""
    record = SessionRecord(
        id=session_id,
        user_id=user_id,
        title=title,
        created_at=utc_now(),
    )
    with session_scope() as db:
        db.add(record)
        db.commit()
        db.refresh(record)
    return record


def _parse_sse_events(raw_text: str) -> list[dict]:
    """Parse SSE text into a list of JSON event payloads.

    Each SSE event is prefixed with ``data: `` and separated by ``\\n\\n``.
    """
    events: list[dict] = []
    for chunk in raw_text.strip().split("\n\n"):
        for line in chunk.split("\n"):
            if line.startswith("data: "):
                payload = line[len("data: "):]
                events.append(json.loads(payload))
    return events


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def async_client_with_platform(
    test_db,
) -> AsyncGenerator[tuple[AsyncClient, MagicMock], None]:
    """Async HTTP client with a stub platform whose async handle() resolves.

    handle() is awaited by the router and returns a result carrying a summary
    and run_id; both the SSE and JSON paths consume that summary.
    """
    from aila.api.app import create_app

    stub_platform = MagicMock()

    result_obj = MagicMock()
    result_obj.summary = "test response from platform"
    result_obj.run_id = "run-test-001"

    stub_platform.handle = AsyncMock(return_value=result_obj)

    app = create_app()
    app.state.platform = stub_platform
    app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client, stub_platform


# ---------------------------------------------------------------------------
# Group 1: SSE content negotiation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sse_content_negotiation_returns_event_stream(
    async_client_with_platform: tuple[AsyncClient, MagicMock],
    admin_key_record,
    admin_token: str,
) -> None:
    """POST with Accept: text/event-stream returns SSE media type."""
    client, _platform = async_client_with_platform
    _seed_session(user_id=admin_key_record.id, session_id="sess-sse-cn-001")

    resp = await client.post(
        "/sessions/sess-sse-cn-001/messages",
        json={"content": "hello"},
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Accept": "text/event-stream",
        },
    )
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_json_content_negotiation_returns_json(
    async_client_with_platform: tuple[AsyncClient, MagicMock],
    admin_key_record,
    admin_token: str,
) -> None:
    """POST without Accept: text/event-stream returns JSON response."""
    client, _platform = async_client_with_platform
    _seed_session(user_id=admin_key_record.id, session_id="sess-json-cn-001")

    resp = await client.post(
        "/sessions/sess-json-cn-001/messages",
        json={"content": "hello"},
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Accept": "application/json",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "message_id" in data
    assert data["role"] == "assistant"
    assert "content" in data


@pytest.mark.asyncio
async def test_sse_accept_header_variations(
    async_client_with_platform: tuple[AsyncClient, MagicMock],
    admin_key_record,
    admin_token: str,
) -> None:
    """Verify Accept header dispatching: text/event-stream -> SSE, others -> JSON."""
    client, _platform = async_client_with_platform

    # SSE path
    _seed_session(user_id=admin_key_record.id, session_id="sess-var-001")
    resp_sse = await client.post(
        "/sessions/sess-var-001/messages",
        json={"content": "hello"},
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Accept": "text/event-stream",
        },
    )
    assert "text/event-stream" in resp_sse.headers.get("content-type", "")

    # JSON path (application/json)
    _seed_session(user_id=admin_key_record.id, session_id="sess-var-002")
    resp_json = await client.post(
        "/sessions/sess-var-002/messages",
        json={"content": "hello"},
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Accept": "application/json",
        },
    )
    assert resp_json.status_code == 200
    assert "message_id" in resp_json.json()

    # Missing Accept header -> JSON path
    _seed_session(user_id=admin_key_record.id, session_id="sess-var-003")
    resp_no_accept = await client.post(
        "/sessions/sess-var-003/messages",
        json={"content": "hello"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_no_accept.status_code == 200
    assert "message_id" in resp_no_accept.json()


# ---------------------------------------------------------------------------
# Group 2: Message persistence after SSE stream
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sse_persists_assistant_message(
    async_client_with_platform: tuple[AsyncClient, MagicMock],
    admin_key_record,
    admin_token: str,
) -> None:
    """After SSE stream completes, GET /messages returns both user and assistant messages."""
    client, _platform = async_client_with_platform
    _seed_session(user_id=admin_key_record.id, session_id="sess-persist-sse-001")

    # Send message via SSE
    resp = await client.post(
        "/sessions/sess-persist-sse-001/messages",
        json={"content": "What is AILA?"},
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Accept": "text/event-stream",
        },
    )
    assert resp.status_code == 200

    # Verify persistence via GET
    resp_get = await client.get(
        "/sessions/sess-persist-sse-001/messages",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_get.status_code == 200
    data = resp_get.json()
    assert data["total"] == 2
    roles = [item["role"] for item in data["items"]]
    assert "user" in roles
    assert "assistant" in roles
    contents = [item["content"] for item in data["items"]]
    assert "What is AILA?" in contents
    assert "test response from platform" in contents


@pytest.mark.asyncio
async def test_json_path_persists_both_messages(
    async_client_with_platform: tuple[AsyncClient, MagicMock],
    admin_key_record,
    admin_token: str,
) -> None:
    """JSON path: after POST, GET /messages returns user + assistant messages."""
    client, _platform = async_client_with_platform
    _seed_session(user_id=admin_key_record.id, session_id="sess-persist-json-001")

    # Send message via JSON path
    resp = await client.post(
        "/sessions/sess-persist-json-001/messages",
        json={"content": "Tell me about CVEs"},
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Accept": "application/json",
        },
    )
    assert resp.status_code == 200

    # Verify persistence via GET
    resp_get = await client.get(
        "/sessions/sess-persist-json-001/messages",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_get.status_code == 200
    data = resp_get.json()
    assert data["total"] == 2
    roles = [item["role"] for item in data["items"]]
    assert roles == ["user", "assistant"]


# ---------------------------------------------------------------------------
# Group 3: User isolation across all endpoints
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_isolation_post_message_json_cross_user(
    async_client_with_platform: tuple[AsyncClient, MagicMock],
    admin_key_record,
    reader_key_record,
    reader_token: str,
) -> None:
    """Reader cannot POST message (JSON path) to admin's session -> 404."""
    client, _platform = async_client_with_platform
    _seed_session(user_id=admin_key_record.id, session_id="sess-iso-json-001")

    resp = await client.post(
        "/sessions/sess-iso-json-001/messages",
        json={"content": "hello"},
        headers={
            "Authorization": f"Bearer {reader_token}",
            "Accept": "application/json",
        },
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_isolation_post_message_sse_cross_user(
    async_client_with_platform: tuple[AsyncClient, MagicMock],
    admin_key_record,
    reader_key_record,
    reader_token: str,
) -> None:
    """Reader cannot POST message (SSE path) to admin's session -> 404."""
    client, _platform = async_client_with_platform
    _seed_session(user_id=admin_key_record.id, session_id="sess-iso-sse-001")

    resp = await client.post(
        "/sessions/sess-iso-sse-001/messages",
        json={"content": "hello"},
        headers={
            "Authorization": f"Bearer {reader_token}",
            "Accept": "text/event-stream",
        },
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_isolation_get_messages_cross_user_after_messages_exist(
    async_client_with_platform: tuple[AsyncClient, MagicMock],
    admin_key_record,
    reader_key_record,
    admin_token: str,
    reader_token: str,
) -> None:
    """Reader cannot GET messages from admin's session even when messages exist."""
    client, _platform = async_client_with_platform
    _seed_session(user_id=admin_key_record.id, session_id="sess-iso-get-001")

    # Admin posts a message (creates messages in DB)
    await client.post(
        "/sessions/sess-iso-get-001/messages",
        json={"content": "admin message"},
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Accept": "application/json",
        },
    )

    # Reader tries to read admin's session messages -> 404
    resp = await client.get(
        "/sessions/sess-iso-get-001/messages",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_isolation_create_session_scoped_to_user(
    async_client_with_platform: tuple[AsyncClient, MagicMock],
    admin_key_record,
    reader_key_record,
    admin_token: str,
    reader_token: str,
) -> None:
    """Each user's sessions are isolated: cross-user GET returns 404, own returns 200."""
    client, _platform = async_client_with_platform

    # Admin creates session
    _seed_session(user_id=admin_key_record.id, session_id="sess-scope-admin")
    # Reader creates session
    _seed_session(user_id=reader_key_record.id, session_id="sess-scope-reader")

    # Reader cannot see admin's session
    resp_reader_to_admin = await client.get(
        "/sessions/sess-scope-admin/messages",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp_reader_to_admin.status_code == 404

    # Admin cannot see reader's session
    resp_admin_to_reader = await client.get(
        "/sessions/sess-scope-reader/messages",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_admin_to_reader.status_code == 404

    # Each can access their own
    resp_admin_own = await client.get(
        "/sessions/sess-scope-admin/messages",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_admin_own.status_code == 200

    resp_reader_own = await client.get(
        "/sessions/sess-scope-reader/messages",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp_reader_own.status_code == 200


# ---------------------------------------------------------------------------
# Group 4: Edge cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_message_sse_nonexistent_session(
    async_client_with_platform: tuple[AsyncClient, MagicMock],
    admin_token: str,
) -> None:
    """SSE path: POST to nonexistent session returns 404 (not 503)."""
    client, _platform = async_client_with_platform

    resp = await client.post(
        "/sessions/fake-nonexistent-id/messages",
        json={"content": "hello"},
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Accept": "text/event-stream",
        },
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_post_message_sse_platform_none(
    async_client: AsyncClient,
    admin_key_record,
    admin_token: str,
) -> None:
    """SSE path: POST to valid owned session with platform=None returns 503."""
    _seed_session(user_id=admin_key_record.id, session_id="sess-sse-503-001")

    resp = await async_client.post(
        "/sessions/sess-sse-503-001/messages",
        json={"content": "hello"},
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Accept": "text/event-stream",
        },
    )
    assert resp.status_code == 503
    assert "platform" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_done_sentinel_contains_run_id(
    async_client_with_platform: tuple[AsyncClient, MagicMock],
    admin_key_record,
    admin_token: str,
) -> None:
    """SSE done sentinel must contain type=done and the correct run_id."""
    client, _platform = async_client_with_platform
    _seed_session(user_id=admin_key_record.id, session_id="sess-done-rid-001")

    resp = await client.post(
        "/sessions/sess-done-rid-001/messages",
        json={"content": "hello"},
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Accept": "text/event-stream",
        },
    )
    assert resp.status_code == 200

    events = _parse_sse_events(resp.text)
    assert len(events) >= 2, f"Expected at least 2 SSE events, got {len(events)}: {events}"

    # Token events
    token_events = [e for e in events if e.get("type") == "token"]
    assert len(token_events) >= 1

    # Done sentinel
    done_events = [e for e in events if e.get("type") == "done"]
    assert len(done_events) == 1, f"Expected exactly 1 done event, got {len(done_events)}"
    assert done_events[0]["run_id"] == "run-test-001"
