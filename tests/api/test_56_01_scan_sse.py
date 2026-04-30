"""Tests for GET /scans/{run_id}/events SSE endpoint (ASYNC-03, ASYNC-04)."""
from __future__ import annotations

import json
import time
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.api.auth import issue_jwt_token
from aila.platform.contracts._common import utc_now
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import session_scope
from aila.storage.db_models import ApiKeyRecord


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _seed_task(key: ApiKeyRecord, run_id: str = "scan-test-001") -> TaskRecord:
    """Seed a TaskRecord owned by key's group."""
    record = TaskRecord(
        id=run_id,
        track="vulnerability",
        fn_path="aila.modules.vulnerability.tasks.run_scan",
        fn_module="vulnerability",
        kwargs_json="{}",
        status=TaskStatus.RUNNING,
        user_id=key.id,
        group_id=key.role,
        created_at=utc_now(),
    )
    with session_scope() as db:
        db.add(record)
        db.commit()
        db.refresh(record)
    return record


def _stub_platform_no_redis() -> MagicMock:
    """Stub platform whose config_registry.get() always returns None."""
    stub = MagicMock()
    stub.runtime.config_registry.get.return_value = None
    return stub


@pytest_asyncio.fixture
async def client_no_redis(test_db, admin_key_record):
    """AsyncClient with stub platform that reports no Redis URL."""
    from aila.api.app import create_app

    app = create_app()
    app.state.platform = _stub_platform_no_redis()
    app.state.start_time = time.monotonic()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c, admin_key_record


# ─── Tests ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_sse_404_for_unknown_run_id(async_client, admin_token):
    """Unknown run_id returns 404 before any stream is opened (ASYNC-03)."""
    resp = await async_client.get(
        "/scans/does-not-exist/events",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_scan_sse_no_redis_returns_info_event(client_no_redis):
    """When Redis is not configured, endpoint returns single SSE info event and closes."""
    client, key = client_no_redis
    token, _ = issue_jwt_token(key)
    _seed_task(key, run_id="scan-no-redis-001")

    resp = await client.get(
        "/scans/scan-no-redis-001/events",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers.get("content-type", "")
    body = resp.text
    lines = [ln for ln in body.splitlines() if ln.startswith("data:")]
    assert len(lines) >= 1
    payload = json.loads(lines[0].removeprefix("data:").strip())
    assert "Redis not configured" in payload.get("message", "")


@pytest.mark.asyncio
async def test_scan_sse_headers(client_no_redis):
    """SSE response includes Cache-Control: no-cache and X-Accel-Buffering: no."""
    client, key = client_no_redis
    token, _ = issue_jwt_token(key)
    _seed_task(key, run_id="scan-hdr-001")

    resp = await client.get(
        "/scans/scan-hdr-001/events",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.headers.get("cache-control") == "no-cache"
    assert resp.headers.get("x-accel-buffering") == "no"


@pytest.mark.asyncio
async def test_scan_sse_event_format_contract(test_db, admin_key_record):
    """Events emitted by ProgressStream contain stage, message, percent keys (ASYNC-04).

    This test verifies the event format contract without live Redis.
    Uses a mock ProgressStream whose catchup() returns pre-baked events.
    """
    from unittest.mock import patch

    from aila.api.app import create_app

    stub_platform = MagicMock()
    stub_platform.runtime.config_registry.get.return_value = "redis://localhost:6379"

    mock_events = [
        {"stage": "inventory", "message": "Collecting packages", "percent": "25", "timestamp": "2026-04-04T00:00:00+00:00"},
        {"stage": "scoring", "message": "Scoring CVEs", "percent": "75", "timestamp": "2026-04-04T00:00:01+00:00"},
    ]

    app = create_app()
    app.state.platform = stub_platform
    app.state.start_time = time.monotonic()
    _seed_task(admin_key_record, run_id="scan-fmt-001")

    with patch("aila.api.routers.scans.ProgressStream") as MockPS:  # noqa: N806
        instance = MockPS.return_value
        instance.catchup.return_value = mock_events
        # Return an empty generator so the live loop exits after catchup events
        instance.stream_events.return_value = iter([])

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            token, _ = issue_jwt_token(admin_key_record)
            resp = await c.get(
                "/scans/scan-fmt-001/events",
                headers={"Authorization": f"Bearer {token}"},
            )

    assert resp.status_code == 200
    lines = [ln for ln in resp.text.splitlines() if ln.startswith("data:")]
    assert len(lines) >= 2, f"Expected at least 2 events, got: {resp.text!r}"
    first = json.loads(lines[0].removeprefix("data:").strip())
    assert "stage" in first, f"Missing 'stage' key in event: {first}"
    assert "message" in first, f"Missing 'message' key in event: {first}"
    assert "percent" in first, f"Missing 'percent' key in event: {first}"
    assert first["stage"] == "inventory"
    assert first["percent"] == "25"


@pytest.mark.asyncio
async def test_scan_sse_403_for_wrong_group(test_db, admin_key_record, reader_token):
    """reader cannot see a scan owned by admin group (group_id isolation)."""
    from aila.api.app import create_app

    _seed_task(admin_key_record, run_id="scan-admin-001")

    app = create_app()
    app.state.platform = None
    app.state.start_time = time.monotonic()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get(
            "/scans/scan-admin-001/events",
            headers={"Authorization": f"Bearer {reader_token}"},
        )
    # reader group != admin group -> TaskRepository returns None -> 404
    assert resp.status_code == 404
