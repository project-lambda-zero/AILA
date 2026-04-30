"""Tests for graceful failure handling: heartbeat reaper and Redis disconnect SSE.

RACE-05: Reaper only reconciles orphan ARQ locks; does not touch TaskRecord rows.
RACE-06: Redis disconnect during SSE terminates stream gracefully (no hang, no 500).
"""
from __future__ import annotations

import time
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from aila.platform.contracts._common import utc_now
from aila.platform.tasks.constants import REAPER_HEARTBEAT_THRESHOLD_S
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.worker import reaper
from aila.storage.database import session_scope

pytestmark = pytest.mark.asyncio


async def test_race_reaper_does_not_touch_taskrecords(test_db: None) -> None:
    """Phase 179: reaper no longer marks TaskRecord rows FAILED.

    The old heartbeat-reaper + checkpoint-resume flow is deleted. The
    reaper now only reconciles orphan ``arq:in-progress:*`` Redis locks
    (covered by ``test_arq_stale_in_progress_reconciliation.py``).
    Terminal-state recovery is owned by ARQ's native max_tries +
    ``_on_job_end`` Branch-4 (DEAD_LETTER).
    """
    now = utc_now()
    stale = TaskRecord(
        id="reaper-stale-001",
        track="vulnerability",
        fn_path="test.fn",
        fn_module="test",
        status=TaskStatus.RUNNING,
        user_id="user-1",
        group_id="admin",
        heartbeat_at=now - timedelta(seconds=REAPER_HEARTBEAT_THRESHOLD_S + 3600),
        started_at=now - timedelta(seconds=300),
    )
    with session_scope() as session:
        session.add(stale)
        session.commit()

    await reaper({})

    from sqlmodel import select

    with session_scope() as session:
        rec = session.exec(
            select(TaskRecord).where(TaskRecord.id == "reaper-stale-001")
        ).one()
        # Reaper no longer modifies TaskRecord status; the row stays RUNNING.
        assert rec.status == TaskStatus.RUNNING


async def test_race_redis_disconnect_sse_graceful(
    test_db: None,
    admin_key_record: object,
    admin_token: str,
) -> None:
    """RACE-06: Redis disconnect during SSE terminates the stream gracefully.

    Approach:
    - Create a fresh app with a mock platform that returns a redis_url
    - Seed a TaskRecord so the access check passes
    - Patch ProgressStream so catchup() returns [] and _redis.xread() raises ConnectionError
    - Call GET /scans/{run_id}/events
    - Assert: 200 status, text/event-stream media type, response body terminates (no hang)
    """
    from aila.api.app import create_app

    task_id = "sse-redis-disconnect-001"

    # Seed a TaskRecord visible to admin (group_id='admin')
    task_record = TaskRecord(
        id=task_id,
        track="vulnerability",
        fn_path="test.fn",
        fn_module="test",
        status=TaskStatus.RUNNING,
        user_id=admin_key_record.id,  # type: ignore[attr-defined]
        group_id="admin",
        heartbeat_at=utc_now(),
        started_at=utc_now(),
    )
    with session_scope() as session:
        session.add(task_record)
        session.commit()

    # Build app with mock platform that provides redis_url
    test_app = create_app()
    stub_runtime = MagicMock()
    stub_runtime.config_registry.get.return_value = "redis://fake:6379"
    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime
    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    # Mock ProgressStream to simulate Redis disconnect
    mock_redis = MagicMock()
    mock_redis.xread.side_effect = ConnectionError("Redis disconnected")

    mock_stream_instance = MagicMock()
    mock_stream_instance.catchup.return_value = []
    mock_stream_instance._redis = mock_redis

    with patch(
        "aila.api.routers.scans.ProgressStream",
        return_value=mock_stream_instance,
    ):
        async with AsyncClient(
            transport=ASGITransport(app=test_app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get(
                f"/scans/{task_id}/events",
                headers={"Authorization": f"Bearer {admin_token}"},
            )

    # Assertions: stream returned 200 and terminated (not hanging)
    assert resp.status_code == 200, (
        f"Expected 200, got {resp.status_code}: {resp.text}"
    )
    assert "text/event-stream" in resp.headers.get("content-type", ""), (
        "Expected text/event-stream media type"
    )
    # The response body must be finite (generator broke on ConnectionError)
    # If it hung, the test would time out. A successful completion means
    # the generator terminated gracefully.
    assert resp.is_success, "Response should indicate success (2xx)"
