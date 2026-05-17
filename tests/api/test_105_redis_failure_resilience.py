"""Redis failure resilience stress tests -- Phase 105 (STRESS-05, STRESS-06).

STRESS-05: Redis disconnect mid-SSE -- graceful termination, no leaked tasks
STRESS-06: Redis disconnect during submit -- sync fallback completes in-process

Proves:
  1. SSE stream terminates cleanly when Redis disconnects mid-stream (scans + tasks)
  2. Catchup failure does not crash the SSE generator
  3. TaskRecord remains uncorrupted after Redis disconnect during SSE
  4. TaskQueue.submit() falls back to sync execution when Redis is unreachable
  5. Sync fallback produces identical DB state (DONE/FAILED with timestamps)
  6. Multiple consecutive sync fallbacks do not leak state
"""
from __future__ import annotations

import json
import sys
import time
import types
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlmodel import Session, SQLModel, select

from aila.api.auth import issue_jwt_token
from aila.platform.contracts._common import utc_now
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import session_scope

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_sse_data_lines(text: str) -> list[dict]:
    """Extract and parse all SSE data lines from response text."""
    lines = [ln for ln in text.splitlines() if ln.startswith("data:")]
    return [json.loads(ln.removeprefix("data:").strip()) for ln in lines]


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


def _make_platform_stub_with_redis() -> MagicMock:
    """Create a stub platform whose config_registry.get returns a Redis URL."""
    stub = MagicMock()
    stub.runtime.config_registry.get.return_value = "redis://localhost:6379"
    return stub


# ---------------------------------------------------------------------------
# DB isolation helpers (for TaskQueue tests -- same pattern as Phase 95)
# ---------------------------------------------------------------------------


def _make_test_engine(db_url: str):
    """Create a fresh SQLite engine with all SQLModel tables registered."""
    import aila.modules.vulnerability.db_models  # noqa: F401
    import aila.platform.tasks.models  # noqa: F401
    import aila.storage.db_models  # noqa: F401

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    return engine


def _inject_engine(engine, db_url: str) -> None:
    import aila.storage.database as _db_module

    with _db_module._ENGINE_LOCK:
        _db_module._ENGINES[db_url] = engine
        _db_module._INITIALIZED_URLS.add(db_url)


def _remove_engine(db_url: str) -> None:
    import aila.storage.database as _db_module

    with _db_module._ENGINE_LOCK:
        _db_module._ENGINES.pop(db_url, None)
        _db_module._INITIALIZED_URLS.discard(db_url)


@contextmanager
def _real_scope(engine):
    with Session(engine) as s:
        yield s


def _make_module_fn(module_name: str, fn_name: str = "do_work"):
    """Create a callable whose inspect.getmodule() returns a fake module."""
    m = types.ModuleType(module_name)
    fn = lambda **kwargs: "ok"  # noqa: E731
    fn.__qualname__ = fn_name
    fn.__module__ = module_name
    m.__name__ = module_name
    setattr(m, fn_name, fn)
    sys.modules[module_name] = m
    return fn, m


class MockRegistryNoRedis:
    """ConfigRegistry stub that returns no redis_url (forces sync fallback)."""

    def get(self, namespace: str, key: str) -> str | None:
        return None


class MockRegistryWithRedis:
    """ConfigRegistry stub that returns a Redis URL (triggers _arq_enqueue)."""

    def get(self, namespace: str, key: str) -> str | None:
        if key == "redis_url":
            return "redis://localhost:6379"
        return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def sse_client(test_db, admin_key_record):
    """AsyncClient with stub platform for SSE disconnect tests."""
    from aila.api.app import create_app

    app = create_app()
    app.state.platform = _make_platform_stub_with_redis()
    app.state.start_time = time.monotonic()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c, admin_key_record


# ===========================================================================
# STRESS-05: Redis disconnect mid-SSE
# ===========================================================================


class TestScanSSERedisDisconnectMidStream:
    """STRESS-05.1: Redis ConnectionError during stream_events terminates SSE gracefully."""

    async def test_redis_disconnect_mid_stream_closes_gracefully(self, sse_client) -> None:
        """stream_events raises ConnectionError after 2 events -> stream ends with 200."""
        client, key = sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="scan-redis-dc-001")

        call_count = 0

        def _disconnecting_gen():
            nonlocal call_count
            yield {"stage": "init", "message": "Starting", "percent": "0", "timestamp": "t0"}
            yield {"stage": "inventory", "message": "Collecting", "percent": "30", "timestamp": "t1"}
            raise ConnectionError("Redis connection lost")

        with patch("aila.api.routers.scans.ProgressStream") as MockPS:
            instance = MockPS.return_value
            instance.catchup.return_value = []
            instance.stream_events.return_value = _disconnecting_gen()

            resp = await client.get(
                "/scans/scan-redis-dc-001/events",
                headers={"Authorization": f"Bearer {token}"},
            )

        # Stream closes cleanly with 200 -- no 500, no crash
        assert resp.status_code == 200
        events = _parse_sse_data_lines(resp.text)
        # Only the 2 events before the disconnect should appear
        assert len(events) == 2
        assert events[0]["stage"] == "init"
        assert events[1]["stage"] == "inventory"

    async def test_redis_disconnect_during_catchup_then_stream(self, sse_client) -> None:
        """Catchup raises ConnectionError -> stream_events still delivers live events."""
        client, key = sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="scan-redis-dc-002")

        live_event = {"stage": "scoring", "message": "Scoring", "percent": "60", "timestamp": "t"}

        with patch("aila.api.routers.scans.ProgressStream") as MockPS:
            instance = MockPS.return_value
            instance.catchup.side_effect = ConnectionError("Redis unreachable during catchup")
            instance.stream_events.return_value = iter([live_event])

            resp = await client.get(
                "/scans/scan-redis-dc-002/events",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        events = _parse_sse_data_lines(resp.text)
        assert len(events) == 1
        assert events[0]["stage"] == "scoring"


class TestTaskSSERedisDisconnectMidStream:
    """STRESS-05.2: Tasks SSE endpoint handles Redis disconnect identically to scans."""

    async def test_task_sse_redis_disconnect_mid_stream(self, sse_client) -> None:
        """Tasks SSE: stream_events raises ConnectionError -> graceful termination."""
        client, key = sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="task-redis-dc-001")

        def _disconnecting_gen():
            yield {"stage": "processing", "message": "Working", "percent": "40", "timestamp": "t0"}
            raise ConnectionError("Redis connection lost")

        # tasks.py imports ProgressStream lazily inside _sse_generator, so patch at source
        with patch("aila.platform.tasks.progress.ProgressStream") as MockPS:
            instance = MockPS.return_value
            instance.catchup.return_value = []
            instance.stream_events.return_value = _disconnecting_gen()

            resp = await client.get(
                "/tasks/task-redis-dc-001/events",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        events = _parse_sse_data_lines(resp.text)
        assert len(events) == 1
        assert events[0]["stage"] == "processing"

    async def test_task_sse_catchup_failure_continues_to_stream(self, sse_client) -> None:
        """Tasks SSE: catchup raises -> stream_events still delivers."""
        client, key = sse_client
        token, _ = issue_jwt_token(key)
        _seed_task(user_id=key.id, group_id="admin", task_id="task-redis-dc-002")

        live = {"stage": "done", "message": "Complete", "percent": "100", "timestamp": "t"}

        # tasks.py imports ProgressStream lazily inside _sse_generator, so patch at source
        with patch("aila.platform.tasks.progress.ProgressStream") as MockPS:
            instance = MockPS.return_value
            instance.catchup.side_effect = ConnectionError("Redis gone")
            instance.stream_events.return_value = iter([live])

            resp = await client.get(
                "/tasks/task-redis-dc-002/events",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200
        events = _parse_sse_data_lines(resp.text)
        assert len(events) == 1
        assert events[0]["percent"] == "100"


class TestSSERedisDisconnectTaskRecordIntegrity:
    """STRESS-05.3: TaskRecord remains uncorrupted after Redis disconnect during SSE."""

    async def test_task_record_unchanged_after_sse_redis_disconnect(self, sse_client) -> None:
        """After Redis disconnect mid-SSE, the TaskRecord in DB is still RUNNING."""
        client, key = sse_client
        token, _ = issue_jwt_token(key)
        record = _seed_task(
            user_id=key.id,
            group_id="admin",
            task_id="scan-integrity-001",
            status=TaskStatus.RUNNING,
        )

        def _disconnecting_gen():
            # Must yield at least once to be a generator, but we want immediate failure
            # Use a generator that raises on first next() call
            return
            yield  # noqa: RET504 -- unreachable yield makes this a generator function

        with patch("aila.api.routers.scans.ProgressStream") as MockPS:
            instance = MockPS.return_value
            instance.catchup.side_effect = ConnectionError("Redis died immediately")
            instance.stream_events.return_value = _disconnecting_gen()

            resp = await client.get(
                "/scans/scan-integrity-001/events",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert resp.status_code == 200

        # Verify TaskRecord is still intact with original status
        import asyncio

        def _check():
            with session_scope() as db:
                rec = db.get(TaskRecord, "scan-integrity-001")
                return rec

        rec = await asyncio.to_thread(_check)
        assert rec is not None
        assert rec.status == TaskStatus.RUNNING, (
            f"TaskRecord should remain RUNNING after SSE Redis disconnect, got {rec.status}"
        )
        assert rec.started_at is not None


# ===========================================================================
# STRESS-06: Redis disconnect during submit -- sync fallback
# ===========================================================================


class TestSubmitRedisDisconnectSyncFallback:
    """STRESS-06.1: _arq_enqueue fails -> sync fallback produces DONE state."""

    def test_arq_enqueue_failure_triggers_sync_fallback_done(self, tmp_path) -> None:
        """When _arq_enqueue returns False, sync fallback runs fn and sets DONE."""
        from aila.platform.tasks.queue import TaskQueue

        db_url = f"sqlite:///{tmp_path / 'redis_dc_submit.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        execution_proof = {"called": False}

        try:
            fn, mod = _make_module_fn("aila.modules.vulnerability.tasks_dc", "scan_dc")

            def tracking_fn(**kwargs):
                execution_proof["called"] = True
                return "scan_complete"

            tracking_fn.__qualname__ = "scan_dc"
            tracking_fn.__module__ = "aila.modules.vulnerability.tasks_dc"
            setattr(mod, "scan_dc", tracking_fn)

            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)

                # Registry returns Redis URL, but _arq_enqueue will be patched to fail
                registry = MockRegistryWithRedis()
                tq = TaskQueue(config_registry=registry, module_id="vulnerability")

                with patch.object(tq, "_arq_enqueue", return_value=False):
                    handle = tq.submit(
                        track="vuln",
                        fn=tracking_fn,
                        kwargs={"target": "web01"},
                        user_id="user-stress",
                        group_id="operator",
                    )

            assert execution_proof["called"], "Sync fallback must execute fn when _arq_enqueue fails"

            with Session(engine) as s:
                rec = s.get(TaskRecord, handle.task_id)
                assert rec is not None
                assert rec.status == TaskStatus.DONE
                assert rec.completed_at is not None
                assert rec.error is None
                assert json.loads(rec.kwargs_json) == {"target": "web01"}
        finally:
            _remove_engine(db_url)
            sys.modules.pop("aila.modules.vulnerability.tasks_dc", None)

    def test_sync_fallback_failure_sets_failed_with_error(self, tmp_path) -> None:
        """Sync fallback with failing fn sets FAILED with error message."""
        from aila.platform.tasks.queue import TaskQueue

        db_url = f"sqlite:///{tmp_path / 'redis_dc_fail.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        try:
            fn, mod = _make_module_fn("aila.modules.vulnerability.tasks_fail2", "bad_fn2")

            def failing_fn(**kwargs):
                raise RuntimeError("Network timeout connecting to target")

            failing_fn.__qualname__ = "bad_fn2"
            failing_fn.__module__ = "aila.modules.vulnerability.tasks_fail2"
            setattr(mod, "bad_fn2", failing_fn)

            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)

                registry = MockRegistryNoRedis()
                tq = TaskQueue(config_registry=registry, module_id="vulnerability")
                handle = tq.submit(
                    track="vuln",
                    fn=failing_fn,
                    kwargs={},
                    user_id="user-fail",
                    group_id="operator",
                )

            with Session(engine) as s:
                rec = s.get(TaskRecord, handle.task_id)
                assert rec is not None
                assert rec.status == TaskStatus.FAILED
                assert rec.completed_at is not None
                assert rec.error is not None
                assert "Network timeout" in rec.error
        finally:
            _remove_engine(db_url)
            sys.modules.pop("aila.modules.vulnerability.tasks_fail2", None)


class TestSubmitSyncFallbackDBStateMatch:
    """STRESS-06.2: Sync fallback DB state matches expected async-path shape."""

    def test_sync_fallback_db_state_has_all_expected_fields(self, tmp_path) -> None:
        """After sync fallback: created_at, completed_at set; kwargs preserved; track correct."""
        from aila.platform.tasks.queue import TaskQueue

        db_url = f"sqlite:///{tmp_path / 'redis_dc_shape.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        try:
            fn, mod = _make_module_fn("aila.modules.vulnerability.tasks_shape", "scan_shape")

            def shape_fn(**kwargs):
                return "result"

            shape_fn.__qualname__ = "scan_shape"
            shape_fn.__module__ = "aila.modules.vulnerability.tasks_shape"
            setattr(mod, "scan_shape", shape_fn)

            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)

                registry = MockRegistryNoRedis()
                tq = TaskQueue(config_registry=registry, module_id="vulnerability")
                handle = tq.submit(
                    track="vuln",
                    fn=shape_fn,
                    kwargs={"host": "arch-vm", "port": 22},
                    user_id="user-shape",
                    group_id="admin",
                )

            with Session(engine) as s:
                rec = s.get(TaskRecord, handle.task_id)
                assert rec is not None

                # Core fields match expected async-path shape
                assert rec.track == "vuln"
                assert rec.fn_module == "vulnerability"
                assert rec.user_id == "user-shape"
                assert rec.group_id == "admin"
                assert rec.status == TaskStatus.DONE
                assert rec.created_at is not None
                assert rec.completed_at is not None
                assert rec.error is None

                # Kwargs preserved in DB
                stored_kwargs = json.loads(rec.kwargs_json)
                assert stored_kwargs == {"host": "arch-vm", "port": 22}
        finally:
            _remove_engine(db_url)
            sys.modules.pop("aila.modules.vulnerability.tasks_shape", None)


class TestSubmitMultipleConsecutiveFallbacks:
    """STRESS-06.3: Multiple consecutive submit() calls with Redis down all fallback."""

    def test_three_consecutive_submits_all_fallback_correctly(self, tmp_path) -> None:
        """3 submit() calls with no Redis: all produce DONE records, no state leaks."""
        from aila.platform.tasks.queue import TaskQueue

        db_url = f"sqlite:///{tmp_path / 'redis_dc_multi.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        try:
            fn, mod = _make_module_fn("aila.modules.vulnerability.tasks_multi", "scan_multi")

            call_log = []

            def counting_fn(**kwargs):
                call_log.append(kwargs.get("target", "unknown"))
                return "ok"

            counting_fn.__qualname__ = "scan_multi"
            counting_fn.__module__ = "aila.modules.vulnerability.tasks_multi"
            setattr(mod, "scan_multi", counting_fn)

            task_ids = []
            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)

                registry = MockRegistryNoRedis()
                tq = TaskQueue(config_registry=registry, module_id="vulnerability")

                for i, target in enumerate(["web01", "web02", "web03"]):
                    handle = tq.submit(
                        track="vuln",
                        fn=counting_fn,
                        kwargs={"target": target},
                        user_id=f"user-{i}",
                        group_id="operator",
                    )
                    task_ids.append(handle.task_id)

            # All 3 were executed via sync fallback
            assert len(call_log) == 3
            assert call_log == ["web01", "web02", "web03"]

            # All 3 task IDs are distinct
            assert len(set(task_ids)) == 3

            # All 3 TaskRecords exist with DONE status
            with Session(engine) as s:
                for tid in task_ids:
                    rec = s.get(TaskRecord, tid)
                    assert rec is not None, f"TaskRecord {tid} not found"
                    assert rec.status == TaskStatus.DONE
                    assert rec.completed_at is not None
                    assert rec.error is None

            # No orphaned records in DB beyond the 3 we created
            with Session(engine) as s:
                all_records = s.exec(select(TaskRecord)).all()
                assert len(all_records) == 3
        finally:
            _remove_engine(db_url)
            sys.modules.pop("aila.modules.vulnerability.tasks_multi", None)
