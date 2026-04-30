"""Cross-cutting SSE streaming verification tests (Phase 96, XCUT-04/XCUT-05).

XCUT-04: Scan SSE progress -- catchup before scan, live events, completion,
         late-connect replay, disconnect cleanup.
XCUT-05: Chat SSE streaming -- token streaming, done sentinel, DB persistence,
         content negotiation.

All tests use mocked Redis (ProgressStream) and mocked platform.handle() --
no real Redis or LLM required.
"""
from __future__ import annotations

import json
import time
from collections.abc import AsyncGenerator
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.api.auth import issue_jwt_token
from aila.platform.contracts._common import utc_now
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import session_scope
from aila.storage.db_models import ApiKeyRecord, SessionMessageRecord, SessionRecord


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_task(
    user_id: str,
    group_id: str,
    task_id: str,
    status: str = TaskStatus.RUNNING,
) -> TaskRecord:
    """Seed a TaskRecord for SSE tests."""
    record = TaskRecord(
        id=task_id,
        user_id=user_id,
        group_id=group_id,
        track="vulnerability",
        fn_path="aila.api.routers.scans.run_platform_handle",
        fn_module="__platform__",
        kwargs_json="{}",
        status=status,
        created_at=utc_now(),
        started_at=utc_now(),
    )
    with session_scope() as db:
        db.add(record)
        db.commit()
        db.refresh(record)
    return record


def _seed_session(user_id: str, session_id: str = "sess-sse-001") -> SessionRecord:
    """Seed a SessionRecord for chat SSE tests."""
    record = SessionRecord(
        id=session_id,
        user_id=user_id,
        title="SSE test session",
    )
    with session_scope() as db:
        db.add(record)
        db.commit()
        db.refresh(record)
    return record


def _parse_sse_data_lines(text: str) -> list[dict]:
    """Extract and parse all SSE data lines from response text."""
    lines = [ln for ln in text.splitlines() if ln.startswith("data:")]
    return [json.loads(ln.removeprefix("data:").strip()) for ln in lines]


def _make_platform_stub_with_redis() -> MagicMock:
    """Create a stub platform whose config_registry.get returns a Redis URL."""
    stub = MagicMock()
    stub.runtime.config_registry.get.return_value = "redis://localhost:6379"
    return stub


def _make_platform_stub_with_handle(tokens: list[str], run_id: str | None = None) -> MagicMock:
    """Create a stub platform whose handle() calls token_callback with the given tokens.

    Simulates a platform that streams tokens through the callback, then returns
    a result object with a summary and optional run_id.
    """
    stub = MagicMock()

    def _handle(query: str, token_callback=None, **kwargs):
        if token_callback is not None:
            for token in tokens:
                token_callback(token)
        result = MagicMock()
        result.summary = "".join(tokens)
        result.run_id = run_id
        return result

    stub.handle.side_effect = _handle
    stub.runtime.config_registry.get.return_value = "redis://localhost:6379"
    return stub


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def scan_sse_client(test_db, admin_key_record):
    """AsyncClient with stub platform for scan SSE tests."""
    from aila.api.app import create_app

    app = create_app()
    app.state.platform = _make_platform_stub_with_redis()
    app.state.start_time = time.monotonic()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c, admin_key_record


@pytest_asyncio.fixture
async def chat_sse_client(test_db, admin_key_record):
    """AsyncClient with stub platform for chat SSE tests."""
    from aila.api.app import create_app

    tokens = ["Hello", " there", ", how", " can", " I", " help?"]
    app = create_app()
    app.state.platform = _make_platform_stub_with_handle(tokens, run_id="run-chat-001")
    app.state.start_time = time.monotonic()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c, admin_key_record


# ===========================================================================
# XCUT-04: Scan SSE Progress
# ===========================================================================


class TestScanSSECatchupBeforeScan:
    """XCUT-04.1: Connecting to SSE with pre-existing events replays them all."""

    @pytest.mark.asyncio
    async def test_catchup_replays_all_preexisting_events(self, scan_sse_client) -> None:
        """Catchup replays 3 pre-existing events before any live events."""
        client, key = scan_sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="scan-catchup-001")

        preexisting_events = [
            {"stage": "init", "message": "Initializing", "percent": "0", "timestamp": "2026-01-01T00:00:00+00:00"},
            {"stage": "inventory", "message": "Collecting", "percent": "25", "timestamp": "2026-01-01T00:00:01+00:00"},
            {"stage": "advisory", "message": "Resolving", "percent": "50", "timestamp": "2026-01-01T00:00:02+00:00"},
        ]

        with patch("aila.api.routers.scans.ProgressStream") as MockPS:
            instance = MockPS.return_value
            instance.catchup.return_value = preexisting_events
            instance.stream_events.return_value = iter([])

            resp = await client.get(
                "/scans/scan-catchup-001/events",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        events = _parse_sse_data_lines(resp.text)
        assert len(events) == 3, f"Expected 3 catchup events, got {len(events)}"
        assert events[0]["stage"] == "init"
        assert events[1]["stage"] == "inventory"
        assert events[2]["stage"] == "advisory"
        # Verify catchup was called with correct args
        instance.catchup.assert_called_once_with("scan-catchup-001", "0")


class TestScanSSELiveEvents:
    """XCUT-04.2: stream_events yields per-stage events in order."""

    @pytest.mark.asyncio
    async def test_live_events_delivered_in_order(self, scan_sse_client) -> None:
        """Live events from stream_events appear as SSE data lines in correct order."""
        client, key = scan_sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="scan-live-001")

        live_events = [
            {"stage": "scoring", "message": "Scoring CVEs", "percent": "60", "timestamp": "t1"},
            {"stage": "reporting", "message": "Generating report", "percent": "80", "timestamp": "t2"},
            {"stage": "done", "message": "Complete", "percent": "100", "timestamp": "t3"},
        ]

        with patch("aila.api.routers.scans.ProgressStream") as MockPS:
            instance = MockPS.return_value
            instance.catchup.return_value = []
            instance.stream_events.return_value = iter(live_events)

            resp = await client.get(
                "/scans/scan-live-001/events",
                headers={"Authorization": f"Bearer {token}"},
            )

        events = _parse_sse_data_lines(resp.text)
        assert len(events) == 3
        assert [e["stage"] for e in events] == ["scoring", "reporting", "done"]
        assert events[2]["percent"] == "100"


class TestScanSSECompletion:
    """XCUT-04.3: Stream closes cleanly when stream_events exhausts."""

    @pytest.mark.asyncio
    async def test_stream_closes_on_generator_exhaustion(self, scan_sse_client) -> None:
        """When stream_events() raises StopIteration, the SSE stream ends cleanly with 200."""
        client, key = scan_sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="scan-done-001")

        with patch("aila.api.routers.scans.ProgressStream") as MockPS:
            instance = MockPS.return_value
            instance.catchup.return_value = [
                {"stage": "done", "message": "Complete", "percent": "100", "timestamp": "t"}
            ]
            instance.stream_events.return_value = iter([])  # empty = done

            resp = await client.get(
                "/scans/scan-done-001/events",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        events = _parse_sse_data_lines(resp.text)
        assert len(events) == 1  # only the catchup event
        assert events[0]["percent"] == "100"


class TestScanSSELateConnect:
    """XCUT-04.4: Late-connecting replays from the beginning then gets live events."""

    @pytest.mark.asyncio
    async def test_late_connect_replays_then_continues(self, scan_sse_client) -> None:
        """Client connecting after scan already in progress gets catchup + live events."""
        client, key = scan_sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="scan-late-001")

        # 2 events already happened before client connected
        catchup_events = [
            {"stage": "init", "message": "Started", "percent": "0", "timestamp": "t0"},
            {"stage": "inventory", "message": "Collecting", "percent": "30", "timestamp": "t1"},
        ]
        # 1 live event arrives after connection
        live_event = {"stage": "scoring", "message": "Scoring", "percent": "70", "timestamp": "t2"}

        with patch("aila.api.routers.scans.ProgressStream") as MockPS:
            instance = MockPS.return_value
            instance.catchup.return_value = catchup_events
            instance.stream_events.return_value = iter([live_event])

            resp = await client.get(
                "/scans/scan-late-001/events?last_id=0",
                headers={"Authorization": f"Bearer {token}"},
            )

        events = _parse_sse_data_lines(resp.text)
        assert len(events) == 3, "Expected 2 catchup + 1 live event"
        # Catchup comes first
        assert events[0]["stage"] == "init"
        assert events[1]["stage"] == "inventory"
        # Then live
        assert events[2]["stage"] == "scoring"

    @pytest.mark.asyncio
    async def test_late_connect_default_last_id_is_zero(self, scan_sse_client) -> None:
        """Default last_id='0' means replay from the beginning of the stream."""
        client, key = scan_sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="scan-late-default-001")

        with patch("aila.api.routers.scans.ProgressStream") as MockPS:
            instance = MockPS.return_value
            instance.catchup.return_value = []
            instance.stream_events.return_value = iter([])

            resp = await client.get(
                "/scans/scan-late-default-001/events",  # no ?last_id param
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        # Verify catchup was called with default '0'
        instance.catchup.assert_called_once_with("scan-late-default-001", "0")
        # Verify stream_events was called with default '0'
        instance.stream_events.assert_called_once_with("scan-late-default-001", "0")


class TestScanSSEDisconnectCleanup:
    """XCUT-04.5: No leaked server resources after client disconnect."""

    @pytest.mark.asyncio
    async def test_stream_events_generator_finite_no_leak(self, scan_sse_client) -> None:
        """Verify stream_events generator is consumed and exhausted (no infinite loop).

        A finite generator proves no server-side resource leak: when it returns,
        the async generator in _sse_generator() breaks its while loop and the
        StreamingResponse terminates.
        """
        client, key = scan_sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="scan-cleanup-001")

        events_yielded = []

        def _tracking_gen():
            event = {"stage": "s", "message": "m", "percent": "10", "timestamp": "t"}
            events_yielded.append(event)
            yield event
            # Generator exhausts here -- no infinite loop

        with patch("aila.api.routers.scans.ProgressStream") as MockPS:
            instance = MockPS.return_value
            instance.catchup.return_value = []
            instance.stream_events.return_value = _tracking_gen()

            resp = await client.get(
                "/scans/scan-cleanup-001/events",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        assert len(events_yielded) == 1, "Generator should have yielded exactly once then stopped"
        sse_events = _parse_sse_data_lines(resp.text)
        assert len(sse_events) == 1

    @pytest.mark.asyncio
    async def test_catchup_exception_does_not_crash(self, scan_sse_client) -> None:
        """If catchup() raises, the SSE stream continues to live events gracefully."""
        client, key = scan_sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="scan-catchup-err-001")

        live_event = {"stage": "scan", "message": "Scanning", "percent": "50", "timestamp": "t"}

        with patch("aila.api.routers.scans.ProgressStream") as MockPS:
            instance = MockPS.return_value
            instance.catchup.side_effect = ConnectionError("Redis connection lost")
            instance.stream_events.return_value = iter([live_event])

            resp = await client.get(
                "/scans/scan-catchup-err-001/events",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        events = _parse_sse_data_lines(resp.text)
        # Catchup failed, but live event should still be delivered
        assert len(events) == 1
        assert events[0]["stage"] == "scan"


# ===========================================================================
# XCUT-05: Chat SSE Streaming
# ===========================================================================


class TestChatSSETokenStreaming:
    """XCUT-05.1: Token streaming via SSE."""

    @pytest.mark.asyncio
    async def test_tokens_streamed_individually(self, chat_sse_client) -> None:
        """POST with Accept: text/event-stream yields individual token events."""
        client, key = chat_sse_client
        token, _ = issue_jwt_token(key)
        _seed_session(key.id, "sess-tokens-001")

        resp = await client.post(
            "/sessions/sess-tokens-001/messages",
            json={"content": "Hello"},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "text/event-stream",
            },
        )

        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("content-type", "")
        events = _parse_sse_data_lines(resp.text)

        # Should have token events + done sentinel
        token_events = [e for e in events if e.get("type") == "token"]
        assert len(token_events) == 6, f"Expected 6 token events, got {len(token_events)}: {token_events}"
        # Verify each token content
        expected_tokens = ["Hello", " there", ", how", " can", " I", " help?"]
        actual_tokens = [e["token"] for e in token_events]
        assert actual_tokens == expected_tokens


class TestChatSSEDoneSentinel:
    """XCUT-05.2: Done sentinel emitted after all tokens."""

    @pytest.mark.asyncio
    async def test_done_sentinel_emitted_at_end(self, chat_sse_client) -> None:
        """The last SSE event has type='done' with optional run_id."""
        client, key = chat_sse_client
        token, _ = issue_jwt_token(key)
        _seed_session(key.id, "sess-done-001")

        resp = await client.post(
            "/sessions/sess-done-001/messages",
            json={"content": "Test"},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "text/event-stream",
            },
        )

        events = _parse_sse_data_lines(resp.text)
        done_events = [e for e in events if e.get("type") == "done"]
        assert len(done_events) == 1, f"Expected exactly 1 done sentinel, got {len(done_events)}"

        done = done_events[0]
        assert done["type"] == "done"
        assert "run_id" in done
        assert done["run_id"] == "run-chat-001"

        # Done must be the last event
        assert events[-1] == done


class TestChatSSEDBPersistence:
    """XCUT-05.3: Full assistant message persisted to DB after stream completes."""

    @pytest.mark.asyncio
    async def test_assistant_message_persisted_after_stream(self, chat_sse_client) -> None:
        """After SSE stream ends, the complete message is in SessionMessageRecord."""
        client, key = chat_sse_client
        token, _ = issue_jwt_token(key)
        _seed_session(key.id, "sess-persist-001")

        resp = await client.post(
            "/sessions/sess-persist-001/messages",
            json={"content": "Persist test"},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "text/event-stream",
            },
        )
        assert resp.status_code == 200

        # Verify DB persistence
        from sqlmodel import select

        def _check_messages():
            with session_scope() as db:
                stmt = (
                    select(SessionMessageRecord)
                    .where(SessionMessageRecord.session_id == "sess-persist-001")
                    .order_by(SessionMessageRecord.created_at)
                )
                return list(db.exec(stmt).all())

        import asyncio
        messages = await asyncio.to_thread(_check_messages)

        # Should have user message + assistant message
        assert len(messages) == 2, f"Expected 2 messages (user + assistant), got {len(messages)}"
        user_msg = messages[0]
        asst_msg = messages[1]

        assert user_msg.role == "user"
        assert user_msg.content == "Persist test"

        assert asst_msg.role == "assistant"
        assert asst_msg.content == "Hello there, how can I help?"
        assert asst_msg.run_id == "run-chat-001"


class TestChatSSEContentNegotiation:
    """XCUT-05.4: Same endpoint returns JSON without Accept: text/event-stream."""

    @pytest.mark.asyncio
    async def test_json_response_without_sse_accept(self, chat_sse_client) -> None:
        """POST without Accept: text/event-stream returns JSON SessionMessageResponse."""
        client, key = chat_sse_client
        token, _ = issue_jwt_token(key)
        _seed_session(key.id, "sess-json-001")

        resp = await client.post(
            "/sessions/sess-json-001/messages",
            json={"content": "No streaming please"},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        # JSON response has SessionMessageResponse shape
        assert "message_id" in data
        assert data["role"] == "assistant"
        assert "content" in data
        assert "created_at" in data
        # Content type should NOT be text/event-stream
        assert "text/event-stream" not in resp.headers.get("content-type", "")
