"""Deep review tests for scans router (Phase 68 Plan 01).

Covers:
  - POST /analyze 202 submission with mocked TaskQueue
  - POST /analyze 422 for empty query_text (min_length=1 enforcement)
  - POST /analyze admin allowed (admin >= operator)
  - run_platform_handle robustness: init failure, handle failure, happy path
  - GET /scans/{run_id} response shape with result_path
  - SSE catchup + live event delivery, exception handling, stream_events usage

Does NOT duplicate tests in:
  - test_55_03_scan_submit.py (503 no-platform, 403 reader, status polling)
  - test_56_01_scan_sse.py (404 unknown, no-redis info, headers, format contract, group isolation)
  - test_negative_scans.py (403 reader, 422 empty body, 503 no platform, 404 not found)
  - test_coverage_health_scans.py (status found/not-found/running, health checks)
"""
from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.api.auth import issue_jwt_token
from aila.platform.contracts._common import utc_now
from aila.platform.tasks.models import TaskHandle, TaskRecord, TaskStatus
from aila.storage.database import session_scope
from aila.storage.db_models import ApiKeyRecord

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_task(
    user_id: str,
    group_id: str = "operator",
    task_id: str = "scan-deep-001",
    status: str = TaskStatus.RUNNING,
    result_path: str | None = None,
) -> TaskRecord:
    """Seed a TaskRecord for test use."""
    record = TaskRecord(
        id=task_id,
        user_id=user_id,
        group_id=group_id,
        track="vulnerability",
        fn_path="aila.api.routers.scans.run_platform_handle",
        fn_module="__platform__",
        kwargs_json="{}",
        status=status,
        result_path=result_path,
        created_at=utc_now(),
        started_at=utc_now() if status != TaskStatus.QUEUED else None,
        completed_at=utc_now() if status == TaskStatus.DONE else None,
    )
    with session_scope() as session:
        session.add(record)
        session.commit()
        session.refresh(record)
    return record


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def client_with_taskqueue(test_db):
    """AsyncClient with a stub platform and mocked TaskQueue for 202 tests."""
    from aila.api.app import create_app

    stub_runtime = MagicMock()
    stub_runtime.config_registry = MagicMock()
    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    app = create_app()
    app.state.platform = stub_platform
    app.state.start_time = time.monotonic()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


# ---------------------------------------------------------------------------
# Group 1: POST /analyze -- 202 submission contract
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_submit_scan_202_with_taskqueue(
    client_with_taskqueue: AsyncClient,
    operator_token: str,
) -> None:
    """POST /analyze with mocked TaskQueue returns 202 with run_id and status=submitted."""
    mock_handle = TaskHandle(task_id="mock-task-001")

    with patch("aila.platform.tasks.queue.TaskQueue") as MockTQ:
        MockTQ.return_value.submit.return_value = mock_handle

        resp = await client_with_taskqueue.post(
            "/analyze",
            json={"query_text": "scan web01 for vulnerabilities", "targets": ["web01"]},
            headers={"Authorization": f"Bearer {operator_token}"},
        )

    assert resp.status_code == 202
    data = resp.json()
    assert data["run_id"] == "mock-task-001"
    assert data["status"] == "submitted"


@pytest.mark.asyncio
async def test_submit_scan_empty_query_422(
    client_with_taskqueue: AsyncClient,
    operator_token: str,
) -> None:
    """POST /analyze with empty query_text returns 422 (min_length=1)."""
    resp = await client_with_taskqueue.post(
        "/analyze",
        json={"query_text": ""},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_submit_scan_admin_allowed(
    client_with_taskqueue: AsyncClient,
    admin_token: str,
) -> None:
    """POST /analyze with admin token returns 202 (admin >= operator role)."""
    mock_handle = TaskHandle(task_id="mock-task-admin")

    with patch("aila.platform.tasks.queue.TaskQueue") as MockTQ:
        MockTQ.return_value.submit.return_value = mock_handle

        resp = await client_with_taskqueue.post(
            "/analyze",
            json={"query_text": "scan web02"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

    assert resp.status_code == 202
    data = resp.json()
    assert data["run_id"] == "mock-task-admin"
    assert data["status"] == "submitted"


# ---------------------------------------------------------------------------
# Group 2: run_platform_handle robustness
# ---------------------------------------------------------------------------


def test_run_platform_handle_init_failure() -> None:
    """run_platform_handle logs and re-raises when AILAPlatform() constructor fails."""
    from aila.api.routers.scans import run_platform_handle

    with (
        patch("aila.config.get_settings", return_value=MagicMock()),
        patch("aila.platform.runtime.AILAPlatform", side_effect=RuntimeError("init boom")),
        patch("aila.api.routers.scans._log") as mock_log,
    ):
        with pytest.raises(RuntimeError, match="init boom"):
            run_platform_handle(query="scan web01")

        mock_log.exception.assert_called_once()
        assert "platform initialization failed" in mock_log.exception.call_args[0][0]


def test_run_platform_handle_handle_failure() -> None:
    """run_platform_handle logs and re-raises when platform.handle() fails."""
    from aila.api.routers.scans import run_platform_handle

    mock_platform = MagicMock()
    mock_platform.handle.side_effect = ValueError("handle boom")

    with (
        patch("aila.config.get_settings", return_value=MagicMock()),
        patch("aila.platform.runtime.AILAPlatform", return_value=mock_platform),
        patch("aila.api.routers.scans._log") as mock_log,
    ):
        with pytest.raises(ValueError, match="handle boom"):
            run_platform_handle(query="scan web01")

        mock_log.exception.assert_called_once()
        assert "handle() failed" in mock_log.exception.call_args[0][0]


def test_run_platform_handle_happy_path() -> None:
    """run_platform_handle passes query and module_payload to platform.handle()."""
    from aila.api.routers.scans import run_platform_handle

    mock_platform = MagicMock()

    with (
        patch("aila.config.get_settings", return_value=MagicMock()),
        patch("aila.platform.runtime.AILAPlatform", return_value=mock_platform),
    ):
        run_platform_handle(
            query="scan web01",
            module_payload={"target_names": ["web01"]},
        )

    mock_platform.handle.assert_called_once_with(
        query="scan web01",
        module_payload={"target_names": ["web01"]},
    )


# ---------------------------------------------------------------------------
# Group 3: GET /scans/{run_id} response shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_status_completed_has_result_path(
    async_client: AsyncClient,
    admin_key_record: ApiKeyRecord,
    admin_token: str,
) -> None:
    """GET /scans/{run_id} for completed task returns result_path field populated."""
    task = _seed_task(
        user_id=admin_key_record.id,
        group_id="admin",
        task_id="scan-complete-001",
        status=TaskStatus.DONE,
        result_path="/tmp/result.json",
    )
    resp = await async_client.get(
        f"/scans/{task.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["result_path"] == "/tmp/result.json"


@pytest.mark.asyncio
async def test_scan_status_response_shape(
    async_client: AsyncClient,
    admin_key_record: ApiKeyRecord,
    admin_token: str,
) -> None:
    """GET /scans/{run_id} response has all expected keys: run_id, status, track, started_at, completed_at, result_path."""
    task = _seed_task(
        user_id=admin_key_record.id,
        group_id="admin",
        task_id="scan-shape-001",
        status=TaskStatus.RUNNING,
    )
    resp = await async_client.get(
        f"/scans/{task.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    expected_keys = {"run_id", "status", "track", "started_at", "completed_at", "result_path"}
    assert expected_keys.issubset(data.keys()), f"Missing keys: {expected_keys - data.keys()}"


# ---------------------------------------------------------------------------
# Group 4: SSE wiring correctness
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def client_with_redis(test_db, admin_key_record):
    """AsyncClient with a stub platform reporting a Redis URL for SSE tests."""
    from aila.api.app import create_app

    stub_platform = MagicMock()
    stub_platform.runtime.config_registry.get.return_value = "redis://localhost:6379"

    app = create_app()
    app.state.platform = stub_platform
    app.state.start_time = time.monotonic()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c, admin_key_record


@pytest.mark.asyncio
async def test_sse_delivers_catchup_then_live_events(client_with_redis) -> None:
    """SSE delivers catchup events first, then live events from stream_events()."""
    client, key = client_with_redis
    token, _ = issue_jwt_token(key)
    _seed_task(user_id=key.id, group_id="admin", task_id="scan-sse-order-001")

    catchup_events = [
        {"stage": "inventory", "message": "Collecting", "percent": "10", "timestamp": "2026-01-01T00:00:00+00:00"},
        {"stage": "advisory", "message": "Resolving", "percent": "30", "timestamp": "2026-01-01T00:00:01+00:00"},
    ]
    live_event = {"stage": "scoring", "message": "Scoring CVEs", "percent": "70", "timestamp": "2026-01-01T00:00:02+00:00"}

    with patch("aila.api.routers.scans.ProgressStream") as MockPS:
        instance = MockPS.return_value
        instance.catchup.return_value = catchup_events
        # stream_events yields one live event then stops
        instance.stream_events.return_value = iter([live_event])

        resp = await client.get(
            "/scans/scan-sse-order-001/events",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    lines = [ln for ln in resp.text.splitlines() if ln.startswith("data:")]
    assert len(lines) == 3, f"Expected 3 events (2 catchup + 1 live), got {len(lines)}: {lines}"

    # Verify order: catchup first, then live
    first = json.loads(lines[0].removeprefix("data:").strip())
    assert first["stage"] == "inventory"
    second = json.loads(lines[1].removeprefix("data:").strip())
    assert second["stage"] == "advisory"
    third = json.loads(lines[2].removeprefix("data:").strip())
    assert third["stage"] == "scoring"


@pytest.mark.asyncio
async def test_sse_stream_events_exception_closes_cleanly(client_with_redis) -> None:
    """SSE stream closes cleanly when stream_events() raises an exception."""
    client, key = client_with_redis
    token, _ = issue_jwt_token(key)
    _seed_task(user_id=key.id, group_id="admin", task_id="scan-sse-err-001")

    def _exploding_gen():
        raise ConnectionError("Redis gone")
        yield  # pragma: no cover -- make it a generator

    with patch("aila.api.routers.scans.ProgressStream") as MockPS:
        instance = MockPS.return_value
        instance.catchup.return_value = []
        instance.stream_events.return_value = _exploding_gen()

        resp = await client.get(
            "/scans/scan-sse-err-001/events",
            headers={"Authorization": f"Bearer {token}"},
        )

    # Should complete without 500 -- stream closes on exception
    assert resp.status_code == 200
    # No data events since catchup was empty and live failed immediately
    lines = [ln for ln in resp.text.splitlines() if ln.startswith("data:")]
    assert len(lines) == 0


@pytest.mark.asyncio
async def test_sse_uses_stream_events_not_xread(client_with_redis) -> None:
    """SSE generator calls stream.stream_events() and does NOT access stream._redis."""
    client, key = client_with_redis
    token, _ = issue_jwt_token(key)
    _seed_task(user_id=key.id, group_id="admin", task_id="scan-sse-api-001")

    with patch("aila.api.routers.scans.ProgressStream") as MockPS:
        instance = MockPS.return_value
        instance.catchup.return_value = []
        instance.stream_events.return_value = iter([])

        resp = await client.get(
            "/scans/scan-sse-api-001/events",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    # Verify stream_events was called (public API)
    instance.stream_events.assert_called_once()
    # Verify _redis was never accessed directly (SLF001 fix confirmed)
    # MagicMock tracks attribute access; _redis should not have been called
    assert not hasattr(instance._redis, "xread") or not instance._redis.xread.called, \
        "stream._redis.xread should not be called after SLF001 fix"
