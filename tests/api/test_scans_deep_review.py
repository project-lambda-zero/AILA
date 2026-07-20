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
from unittest.mock import AsyncMock, MagicMock, patch

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

    # scans.submit_scan awaits TaskQueue(...).submit(...) directly (no threadpool wrap).
    # AsyncMock is required so `await task_queue.submit(...)` yields the handle instead
    # of a raw MagicMock (which is not awaitable).
    with patch("aila.platform.tasks.queue.TaskQueue") as mock_tq_cls:
        mock_tq_cls.return_value.submit = AsyncMock(return_value=mock_handle)

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

    with patch("aila.platform.tasks.queue.TaskQueue") as mock_tq_cls:
        mock_tq_cls.return_value.submit = AsyncMock(return_value=mock_handle)

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
#
# The public ``run_platform_handle`` symbol re-exported by scans.py is the
# @platform_task-decorated ARQ wrapper -- it takes an ARQ ``ctx: dict`` first,
# not a bare ``query`` kwarg. The inner coroutine (the actual handler) is
# reachable through ``__wrapped__`` (functools.wraps preserves it) and calls
# ``get_worker_platform`` from ``aila.platform.tasks.entrypoints`` -- NOT
# ``AILAPlatform()`` directly. Tests below exercise the inner handler and
# the entrypoints module where ``get_worker_platform`` is bound.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_platform_handle_get_worker_platform_failure() -> None:
    """Inner run_platform_handle propagates errors from get_worker_platform()."""
    from aila.api.routers.scans import run_platform_handle
    from aila.platform.tasks.context import TaskContext

    ctx = TaskContext(task_id="task-boom-001", job_try=1, user_id="admin", team_id=None)

    with patch(
        "aila.platform.tasks.entrypoints.get_worker_platform",
        new=AsyncMock(side_effect=RuntimeError("init boom")),
    ):
        with pytest.raises(RuntimeError, match="init boom"):
            await run_platform_handle.__wrapped__(ctx, query="scan web01")


@pytest.mark.asyncio
async def test_run_platform_handle_handle_failure() -> None:
    """Inner run_platform_handle propagates errors raised by platform.handle()."""
    from aila.api.routers.scans import run_platform_handle
    from aila.platform.tasks.context import TaskContext

    ctx = TaskContext(task_id="task-boom-002", job_try=1, user_id="admin", team_id=None)

    mock_platform = MagicMock()
    mock_platform.handle = AsyncMock(side_effect=ValueError("handle boom"))

    with patch(
        "aila.platform.tasks.entrypoints.get_worker_platform",
        new=AsyncMock(return_value=mock_platform),
    ):
        with pytest.raises(ValueError, match="handle boom"):
            await run_platform_handle.__wrapped__(ctx, query="scan web01")


@pytest.mark.asyncio
async def test_run_platform_handle_happy_path() -> None:
    """Inner run_platform_handle forwards query/module_payload/options and stamps run_id from ctx."""
    from aila.api.routers.scans import run_platform_handle
    from aila.platform.tasks.context import TaskContext

    ctx = TaskContext(task_id="task-happy-001", job_try=1, user_id="admin", team_id=None)

    mock_response = MagicMock()
    mock_response.model_dump = MagicMock(return_value={"summary": "ok"})

    mock_platform = MagicMock()
    mock_platform.handle = AsyncMock(return_value=mock_response)

    with patch(
        "aila.platform.tasks.entrypoints.get_worker_platform",
        new=AsyncMock(return_value=mock_platform),
    ):
        result = await run_platform_handle.__wrapped__(
            ctx,
            query="scan web01",
            module_payload={"target_names": ["web01"]},
        )

    assert result == {"response": {"summary": "ok"}}
    # The entrypoint stamps run_id from ctx.task_id and defaults options to {}.
    mock_platform.handle.assert_called_once_with(
        query="scan web01",
        module_payload={"target_names": ["web01"]},
        module_options={},
        run_id="task-happy-001",
    )
    mock_response.model_dump.assert_called_once_with(mode="json")


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
#
# The router (scans.py) short-circuits the SSE stream through
# ``_no_redis_generator`` whenever ``pool_available()`` returns False,
# which is ALWAYS the case in the test process because the ASGITransport
# never runs the app lifespan that initialises the Redis pool. Each test
# patches ``pool_available`` to True so the real ``_sse_generator`` runs.
#
# ProgressStream.catchup is awaited and stream_events is an async generator,
# so mocks must expose an awaitable and a genuine async iterator respectively;
# a plain MagicMock return + sync ``iter([...])`` cannot satisfy either.
#
# The SSE generator emits a synthetic ``{"stage": "stream", "message":
# "Connected", ...}`` event before catchup so the frontend gets an
# immediate acknowledgement. Line-count assertions below include it.
# ---------------------------------------------------------------------------


def _async_iter(items):
    """Return a genuine async iterator over ``items`` for ``async for`` mocking."""

    async def _agen():
        for item in items:
            yield item

    return _agen()


def _async_iter_raising(exc):
    """Return an async iterator whose first ``__anext__`` raises ``exc``."""

    async def _agen():
        raise exc
        yield  # pragma: no cover -- makes _agen an async generator function

    return _agen()


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
    """SSE delivers the initial Connected event, catchup events, then live events."""
    client, key = client_with_redis
    token, _ = issue_jwt_token(key)
    _seed_task(user_id=key.id, group_id="admin", task_id="scan-sse-order-001")

    catchup_events = [
        {"stage": "inventory", "message": "Collecting", "percent": "10", "timestamp": "2026-01-01T00:00:00+00:00"},
        {"stage": "advisory", "message": "Resolving", "percent": "30", "timestamp": "2026-01-01T00:00:01+00:00"},
    ]
    live_event = {"stage": "scoring", "message": "Scoring CVEs", "percent": "70", "timestamp": "2026-01-01T00:00:02+00:00"}

    with (
        patch("aila.api.routers.scans.pool_available", return_value=True),
        patch("aila.api.routers.scans.ProgressStream") as mock_ps_cls,
    ):
        instance = mock_ps_cls.return_value
        instance.catchup = AsyncMock(return_value=catchup_events)
        instance.stream_events = MagicMock(return_value=_async_iter([live_event]))

        resp = await client.get(
            "/scans/scan-sse-order-001/events",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    lines = [ln for ln in resp.text.splitlines() if ln.startswith("data:")]
    # 1 initial Connected + 2 catchup + 1 live event.
    assert len(lines) == 4, f"Expected 4 events (Connected + 2 catchup + 1 live), got {len(lines)}: {lines}"

    connected = json.loads(lines[0].removeprefix("data:").strip())
    assert connected["stage"] == "stream"
    assert connected["message"] == "Connected"

    # Verify order: catchup first, then live
    first = json.loads(lines[1].removeprefix("data:").strip())
    assert first["stage"] == "inventory"
    second = json.loads(lines[2].removeprefix("data:").strip())
    assert second["stage"] == "advisory"
    third = json.loads(lines[3].removeprefix("data:").strip())
    assert third["stage"] == "scoring"


@pytest.mark.asyncio
async def test_sse_stream_events_exception_closes_cleanly(client_with_redis) -> None:
    """SSE stream closes cleanly when stream_events() raises an exception."""
    client, key = client_with_redis
    token, _ = issue_jwt_token(key)
    _seed_task(user_id=key.id, group_id="admin", task_id="scan-sse-err-001")

    with (
        patch("aila.api.routers.scans.pool_available", return_value=True),
        patch("aila.api.routers.scans.ProgressStream") as mock_ps_cls,
    ):
        instance = mock_ps_cls.return_value
        instance.catchup = AsyncMock(return_value=[])
        instance.stream_events = MagicMock(
            return_value=_async_iter_raising(ConnectionError("Redis gone")),
        )

        resp = await client.get(
            "/scans/scan-sse-err-001/events",
            headers={"Authorization": f"Bearer {token}"},
        )

    # Should complete without 500 -- stream closes on exception.
    assert resp.status_code == 200
    lines = [ln for ln in resp.text.splitlines() if ln.startswith("data:")]
    # Only the synthetic Connected event; catchup was empty and stream_events
    # raised immediately, so no live events reach the client.
    assert len(lines) == 1, f"Expected only the Connected event, got {len(lines)}: {lines}"
    connected = json.loads(lines[0].removeprefix("data:").strip())
    assert connected["stage"] == "stream"
    assert connected["message"] == "Connected"


@pytest.mark.asyncio
async def test_sse_uses_stream_events_not_xread(client_with_redis) -> None:
    """SSE generator calls stream.stream_events() and does NOT access stream._redis."""
    client, key = client_with_redis
    token, _ = issue_jwt_token(key)
    _seed_task(user_id=key.id, group_id="admin", task_id="scan-sse-api-001")

    with (
        patch("aila.api.routers.scans.pool_available", return_value=True),
        patch("aila.api.routers.scans.ProgressStream") as mock_ps_cls,
    ):
        instance = mock_ps_cls.return_value
        instance.catchup = AsyncMock(return_value=[])
        instance.stream_events = MagicMock(return_value=_async_iter([]))

        resp = await client.get(
            "/scans/scan-sse-api-001/events",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    # Verify stream_events was called (public API).
    instance.stream_events.assert_called_once()
    # Verify _redis was never accessed directly (SLF001 fix confirmed).
    # MagicMock tracks attribute access; _redis.xread should not have been called.
    assert not instance._redis.xread.called, \
        "stream._redis.xread should not be called after SLF001 fix"
