"""Tests for POST /sessions/{id}/messages SSE streaming variant (TASK-04)."""
from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.api.auth import issue_jwt_token
from aila.platform.contracts._common import utc_now
from aila.storage.database import session_scope
from aila.storage.db_models import ApiKeyRecord, SessionMessageRecord, SessionRecord


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _seed_session(key: ApiKeyRecord, session_id: str = "sess-test-001") -> SessionRecord:
    """Seed a SessionRecord owned by key."""
    record = SessionRecord(
        id=session_id,
        user_id=key.id,
        title="Test session",
        created_at=utc_now(),
    )
    with session_scope() as db:
        db.add(record)
        db.commit()
        db.refresh(record)
    return record


def _make_stub_platform(tokens: list[str], run_id: str | None = None) -> MagicMock:
    """Return a stub platform whose handle() calls token_callback for each token.

    Falls back gracefully if token_callback not accepted (raises TypeError).
    """
    stub = MagicMock()

    def _fake_handle(query: str, token_callback=None, **kwargs):  # noqa: ARG001
        if token_callback is not None:
            for t in tokens:
                token_callback(t)
        result = MagicMock()
        result.summary = "".join(tokens)
        result.run_id = run_id
        return result

    stub.handle.side_effect = _fake_handle
    return stub


@pytest_asyncio.fixture
async def client_with_platform(test_db, admin_key_record):
    """AsyncClient with a stub platform that supports token_callback."""
    from aila.api.app import create_app

    stub_platform = _make_stub_platform(["Hello", " ", "world"], run_id=None)
    app = create_app()
    app.state.platform = stub_platform
    app.state.start_time = time.monotonic()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c, admin_key_record


# ─── Tests ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_chat_non_streaming_still_works(async_client, admin_key_record, admin_token):
    """POST without Accept: text/event-stream returns JSON (regression guard)."""
    _seed_session(admin_key_record, "sess-json-001")

    resp = await async_client.post(
        "/sessions/sess-json-001/messages",
        json={"content": "Hello"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    # platform=None so 503, but it must NOT be a streaming response
    assert resp.headers.get("content-type", "").startswith("application/json")


@pytest.mark.asyncio
async def test_chat_sse_missing_session_returns_404(async_client, admin_token):
    """Streaming request to unknown session returns 404 (D-25)."""
    resp = await async_client.post(
        "/sessions/does-not-exist/messages",
        json={"content": "Hi"},
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Accept": "text/event-stream",
        },
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_chat_sse_no_platform_returns_503(async_client, admin_key_record, admin_token):
    """Streaming request with platform=None returns 503 (after session check)."""
    _seed_session(admin_key_record, "sess-503-001")

    resp = await async_client.post(
        "/sessions/sess-503-001/messages",
        json={"content": "Hi"},
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Accept": "text/event-stream",
        },
    )
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_chat_sse_token_event_format(client_with_platform):
    """Streaming response emits data lines with {'token': ..., 'type': 'token'} (TASK-04)."""
    client, key = client_with_platform
    token_jwt, _ = issue_jwt_token(key)
    _seed_session(key, "sess-tok-001")

    resp = await client.post(
        "/sessions/sess-tok-001/messages",
        json={"content": "Greet me"},
        headers={
            "Authorization": f"Bearer {token_jwt}",
            "Accept": "text/event-stream",
        },
    )
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers.get("content-type", "")

    data_lines = [ln for ln in resp.text.splitlines() if ln.startswith("data:")]
    assert len(data_lines) >= 1, f"Expected SSE data lines, got: {resp.text!r}"

    token_events = []
    for line in data_lines:
        payload = json.loads(line.removeprefix("data:").strip())
        if payload.get("type") == "token":
            token_events.append(payload)

    assert len(token_events) >= 1, f"No 'token' type events found: {data_lines}"
    for ev in token_events:
        assert "token" in ev, f"Missing 'token' key in event: {ev}"


@pytest.mark.asyncio
async def test_chat_sse_done_sentinel_emitted(client_with_platform):
    """Last SSE event before close has type='done' (stream completion signal)."""
    client, key = client_with_platform
    token_jwt, _ = issue_jwt_token(key)
    _seed_session(key, "sess-done-001")

    resp = await client.post(
        "/sessions/sess-done-001/messages",
        json={"content": "Hi"},
        headers={
            "Authorization": f"Bearer {token_jwt}",
            "Accept": "text/event-stream",
        },
    )
    assert resp.status_code == 200
    data_lines = [ln for ln in resp.text.splitlines() if ln.startswith("data:")]
    assert len(data_lines) >= 1

    last_payload = json.loads(data_lines[-1].removeprefix("data:").strip())
    assert last_payload.get("type") == "done", f"Last event not 'done': {last_payload}"


@pytest.mark.asyncio
async def test_chat_sse_db_persistence_after_stream(client_with_platform):
    """After streaming completes, one assistant SessionMessageRecord is in DB (D-07)."""
    client, key = client_with_platform
    token_jwt, _ = issue_jwt_token(key)
    _seed_session(key, "sess-persist-001")

    resp = await client.post(
        "/sessions/sess-persist-001/messages",
        json={"content": "Hello world"},
        headers={
            "Authorization": f"Bearer {token_jwt}",
            "Accept": "text/event-stream",
        },
    )
    assert resp.status_code == 200

    # Wait briefly for the finally-block DB write to complete
    await asyncio.sleep(0.1)

    with session_scope() as db:
        from sqlmodel import select  # noqa: PLC0415
        msgs = list(db.exec(
            select(SessionMessageRecord)
            .where(SessionMessageRecord.session_id == "sess-persist-001")
            .where(SessionMessageRecord.role == "assistant")
        ).all())

    assert len(msgs) == 1, f"Expected 1 assistant message, found {len(msgs)}"
    assert msgs[0].content == "Hello world", f"Unexpected content: {msgs[0].content!r}"
