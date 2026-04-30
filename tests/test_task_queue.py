"""Tests for TaskQueue — platform task submission API (Phase 54, Plan 03).

TDD RED → GREEN: These tests verify the submit API, module boundary enforcement,
DAG cycle detection, Redis fallback, and ConfigRegistry integration.

DB isolation pattern: each test function that needs a DB creates its own
engine via create_engine(), calls SQLModel.metadata.create_all(), and
injects it into the global _ENGINES cache — matching the api/conftest.py
pattern (RESEARCH Pitfall 6: metadata collision if shared engine).
"""

from __future__ import annotations

import json
import os
import sys
import types
from collections.abc import Generator
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlmodel import SQLModel, Session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_module_fn(module_name: str, fn_name: str = "do_work"):
    """Create a callable whose inspect.getmodule() returns a fake module."""
    m = types.ModuleType(module_name)
    fn = lambda **kwargs: None  # noqa: E731
    fn.__qualname__ = fn_name
    fn.__module__ = module_name
    m.__name__ = module_name
    setattr(m, fn_name, fn)
    sys.modules[module_name] = m
    return fn, m


class MockRegistry:
    """Minimal ConfigRegistry stub. Returns None for all keys by default."""

    def __init__(self, redis_url: str | None = None) -> None:
        self._redis_url = redis_url

    def get(self, namespace: str, key: str) -> str | None:
        if namespace == "platform" and key == "redis_url":
            return self._redis_url
        return None


def _make_test_engine(db_url: str):
    """Create a test engine and register all SQLModel tables."""
    # Import platform task models to register taskrecord with SQLModel.metadata
    import aila.platform.tasks.models  # noqa: F401
    import aila.storage.db_models  # noqa: F401
    import aila.modules.vulnerability.db_models  # noqa: F401

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    return engine


def _inject_engine(engine, db_url: str):
    """Inject engine into _ENGINES cache and mark as initialized."""
    import aila.storage.database as _db_module

    with _db_module._ENGINE_LOCK:
        _db_module._ENGINES[db_url] = engine
        _db_module._INITIALIZED_URLS.add(db_url)


def _remove_engine(db_url: str):
    """Remove engine from _ENGINES cache."""
    import aila.storage.database as _db_module

    with _db_module._ENGINE_LOCK:
        _db_module._ENGINES.pop(db_url, None)
        _db_module._INITIALIZED_URLS.discard(db_url)


@contextmanager
def _real_scope(engine):
    """Context manager yielding a session from the given engine."""
    with Session(engine) as s:
        yield s


# ---------------------------------------------------------------------------
# TaskQueue import
# ---------------------------------------------------------------------------


class TestTaskQueueImport:
    """TaskQueue is importable from aila.platform.tasks."""

    def test_task_queue_importable_from_package(self) -> None:
        from aila.platform.tasks import TaskQueue

        assert TaskQueue is not None

    def test_task_queue_importable_from_module(self) -> None:
        from aila.platform.tasks.queue import TaskQueue

        assert TaskQueue is not None


# ---------------------------------------------------------------------------
# TaskQueue instantiation
# ---------------------------------------------------------------------------


class TestTaskQueueInit:
    """TaskQueue binds to a module_id and config_registry at init."""

    def test_init_stores_module_id(self) -> None:
        from aila.platform.tasks import TaskQueue

        registry = MockRegistry()
        tq = TaskQueue(config_registry=registry, module_id="vulnerability")
        assert tq._module_id == "vulnerability"

    def test_init_stores_config_registry(self) -> None:
        from aila.platform.tasks import TaskQueue

        registry = MockRegistry()
        tq = TaskQueue(config_registry=registry, module_id="vulnerability")
        assert tq._config_registry is registry


# ---------------------------------------------------------------------------
# _get_fn_path
# ---------------------------------------------------------------------------


class TestGetFnPath:
    """_get_fn_path returns the fully-qualified dotted path of a callable."""

    def test_returns_dotted_path(self) -> None:
        from aila.platform.tasks import TaskQueue

        registry = MockRegistry()
        tq = TaskQueue(config_registry=registry, module_id="vulnerability")

        fn, _mod = _make_module_fn("aila.modules.vulnerability.tasks")
        path = tq._get_fn_path(fn)
        assert path == "aila.modules.vulnerability.tasks.do_work"

    def test_raises_for_anonymous_function(self) -> None:
        from aila.platform.tasks import TaskQueue

        registry = MockRegistry()
        tq = TaskQueue(config_registry=registry, module_id="vulnerability")

        fn = lambda: None  # noqa: E731
        with patch("inspect.getmodule", return_value=None):
            with pytest.raises(ValueError, match="Cannot determine module"):
                tq._get_fn_path(fn)


# ---------------------------------------------------------------------------
# _extract_module_id
# ---------------------------------------------------------------------------


class TestExtractModuleId:
    """_extract_module_id returns the 3rd path segment for aila.modules.* paths."""

    def test_extracts_vulnerability(self) -> None:
        from aila.platform.tasks import TaskQueue

        tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
        assert tq._extract_module_id("aila.modules.vulnerability.tasks.scan") == "vulnerability"

    def test_extracts_network(self) -> None:
        from aila.platform.tasks import TaskQueue

        tq = TaskQueue(config_registry=MockRegistry(), module_id="network")
        assert tq._extract_module_id("aila.modules.network.workers.probe") == "network"

    def test_platform_tasks_return_platform_sentinel(self) -> None:
        from aila.platform.tasks import TaskQueue

        tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
        result = tq._extract_module_id("aila.platform.tasks.some_fn")
        assert result == "__platform__"


# ---------------------------------------------------------------------------
# _enforce_module_boundary
# ---------------------------------------------------------------------------


class TestEnforceModuleBoundary:
    """_enforce_module_boundary raises ValueError for cross-module functions."""

    def test_same_module_passes(self) -> None:
        from aila.platform.tasks import TaskQueue

        tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
        # Should not raise
        tq._enforce_module_boundary(
            "aila.modules.vulnerability.tasks.scan", "vulnerability"
        )

    def test_different_module_raises(self) -> None:
        from aila.platform.tasks import TaskQueue

        tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
        with pytest.raises(ValueError, match="Module boundary violation"):
            tq._enforce_module_boundary(
                "aila.modules.network.tasks.probe", "network"
            )

    def test_error_message_includes_both_modules(self) -> None:
        from aila.platform.tasks import TaskQueue

        tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
        with pytest.raises(ValueError) as exc_info:
            tq._enforce_module_boundary(
                "aila.modules.network.tasks.probe", "network"
            )
        msg = str(exc_info.value)
        assert "network" in msg
        assert "vulnerability" in msg

    def test_platform_sentinel_passes(self) -> None:
        from aila.platform.tasks import TaskQueue

        tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
        # __platform__ always passes boundary check
        tq._enforce_module_boundary("aila.platform.tasks.helper", "__platform__")


# ---------------------------------------------------------------------------
# _get_redis_url
# ---------------------------------------------------------------------------


class TestGetRedisUrl:
    """_get_redis_url reads from ConfigRegistry, not env var."""

    def test_returns_configured_url(self) -> None:
        from aila.platform.tasks import TaskQueue

        registry = MockRegistry(redis_url="redis://localhost:6379/0")
        tq = TaskQueue(config_registry=registry, module_id="vulnerability")
        assert tq._get_redis_url() == "redis://localhost:6379/0"

    def test_returns_none_when_unconfigured(self) -> None:
        from aila.platform.tasks import TaskQueue

        registry = MockRegistry(redis_url=None)
        tq = TaskQueue(config_registry=registry, module_id="vulnerability")
        assert tq._get_redis_url() is None

    def test_returns_none_when_empty_string(self) -> None:
        from aila.platform.tasks import TaskQueue

        registry = MockRegistry(redis_url="")
        tq = TaskQueue(config_registry=registry, module_id="vulnerability")
        assert tq._get_redis_url() is None

    def test_returns_none_when_registry_raises(self) -> None:
        from aila.platform.tasks import TaskQueue

        class BrokenRegistry:
            def get(self, ns, key):
                raise RuntimeError("DB unavailable")

        tq = TaskQueue(config_registry=BrokenRegistry(), module_id="vulnerability")
        # Should not propagate the exception
        assert tq._get_redis_url() is None


# ---------------------------------------------------------------------------
# _validate_dag
# ---------------------------------------------------------------------------


class TestValidateDag:
    """_validate_dag raises ValueError on circular depends_on."""

    def test_no_cycle_passes(self, tmp_path) -> None:
        """A linear chain A -> B has no cycle; adding C -> B should pass."""
        from aila.platform.tasks import TaskQueue, TaskRecord, TaskStatus

        db_url = f"sqlite:///{tmp_path / 'dag_ok.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        try:
            with Session(engine) as s:
                a = TaskRecord(
                    track="t",
                    fn_path="aila.modules.vulnerability.tasks.scan",
                    fn_module="vulnerability",
                    user_id="u",
                    group_id="g",
                    status=TaskStatus.QUEUED,
                )
                s.add(a)
                s.commit()
                s.refresh(a)
                a_id = a.id

                b = TaskRecord(
                    track="t",
                    fn_path="aila.modules.vulnerability.tasks.scan",
                    fn_module="vulnerability",
                    user_id="u",
                    group_id="g",
                    status=TaskStatus.WAITING,
                    depends_on_json=json.dumps([a_id]),
                )
                s.add(b)
                s.commit()
                s.refresh(b)
                b_id = b.id

            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)

                tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
                # C depends on B — no cycle
                tq._validate_dag("task-c", [b_id])
        finally:
            _remove_engine(db_url)

    def test_cycle_raises_value_error(self, tmp_path) -> None:
        """A depends on B and B depends on A is a cycle — must raise ValueError."""
        from aila.platform.tasks import TaskQueue, TaskRecord, TaskStatus

        db_url = f"sqlite:///{tmp_path / 'dag_cycle.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        try:
            with Session(engine) as s:
                a = TaskRecord(
                    track="t",
                    fn_path="aila.modules.vulnerability.tasks.scan",
                    fn_module="vulnerability",
                    user_id="u",
                    group_id="g",
                    status=TaskStatus.QUEUED,
                )
                s.add(a)
                s.commit()
                s.refresh(a)
                a_id = a.id

            # Fake A depending on "task-b" to set up circular potential
            with Session(engine) as s:
                task_a = s.get(TaskRecord, a_id)
                task_a.depends_on_json = json.dumps(["task-b"])
                s.add(task_a)
                s.commit()

            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)

                tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
                # task-b depends on a_id, but a_id depends on task-b → cycle
                with pytest.raises(ValueError, match="Circular dependency"):
                    tq._validate_dag("task-b", [a_id])
        finally:
            _remove_engine(db_url)


# ---------------------------------------------------------------------------
# _sync_fallback
# ---------------------------------------------------------------------------


class TestSyncFallback:
    """_sync_fallback executes fn synchronously and never raises."""

    def test_sync_fallback_calls_fn(self, tmp_path) -> None:
        from aila.platform.tasks import TaskQueue, TaskRecord, TaskStatus

        db_url = f"sqlite:///{tmp_path / 'fb.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        try:
            with Session(engine) as s:
                record = TaskRecord(
                    track="t",
                    fn_path="aila.modules.vulnerability.tasks.scan",
                    fn_module="vulnerability",
                    user_id="u",
                    group_id="g",
                    status=TaskStatus.QUEUED,
                )
                s.add(record)
                s.commit()
                s.refresh(record)
                task_id = record.id

            called_with: list[dict] = []

            def my_fn(**kwargs):
                called_with.append(kwargs)

            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)
                tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
                tq._sync_fallback(task_id, my_fn, {"x": 1})

            assert called_with == [{"x": 1}]

            with Session(engine) as s:
                updated = s.get(TaskRecord, task_id)
                assert updated.status == TaskStatus.DONE
                assert updated.completed_at is not None
        finally:
            _remove_engine(db_url)

    def test_sync_fallback_sets_failed_on_exception(self, tmp_path) -> None:
        from aila.platform.tasks import TaskQueue, TaskRecord, TaskStatus

        db_url = f"sqlite:///{tmp_path / 'fb2.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        try:
            with Session(engine) as s:
                record = TaskRecord(
                    track="t",
                    fn_path="aila.modules.vulnerability.tasks.scan",
                    fn_module="vulnerability",
                    user_id="u",
                    group_id="g",
                    status=TaskStatus.QUEUED,
                )
                s.add(record)
                s.commit()
                s.refresh(record)
                task_id = record.id

            def failing_fn(**kwargs):
                raise RuntimeError("oops")

            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)
                tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
                # Must not raise
                tq._sync_fallback(task_id, failing_fn, {})

            with Session(engine) as s:
                updated = s.get(TaskRecord, task_id)
                assert updated.status == TaskStatus.FAILED
                assert "oops" in (updated.error or "")
        finally:
            _remove_engine(db_url)

    def test_sync_fallback_never_raises(self, tmp_path) -> None:
        from aila.platform.tasks import TaskQueue, TaskRecord, TaskStatus

        db_url = f"sqlite:///{tmp_path / 'fb3.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        try:
            with Session(engine) as s:
                record = TaskRecord(
                    track="t",
                    fn_path="aila.modules.vulnerability.tasks.scan",
                    fn_module="vulnerability",
                    user_id="u",
                    group_id="g",
                    status=TaskStatus.QUEUED,
                )
                s.add(record)
                s.commit()
                s.refresh(record)
                task_id = record.id

            def catastrophic_fn(**kwargs):
                raise SystemError("total meltdown")

            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)
                tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
                # Must never propagate the exception
                tq._sync_fallback(task_id, catastrophic_fn, {})
        finally:
            _remove_engine(db_url)


# ---------------------------------------------------------------------------
# submit() — integration tests
# ---------------------------------------------------------------------------


class TestSubmit:
    """submit() creates TaskRecord and returns TaskHandle."""

    def test_submit_returns_task_handle(self, tmp_path) -> None:
        from aila.platform.tasks import TaskHandle, TaskQueue

        db_url = f"sqlite:///{tmp_path / 'submit.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        try:
            fn, _mod = _make_module_fn("aila.modules.vulnerability.tasks.submit_mod")

            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)
                tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
                handle = tq.submit(track="vuln", fn=fn, kwargs={"target": "192.168.1.1"})

            assert isinstance(handle, TaskHandle)
            assert isinstance(handle.task_id, str)
            assert len(handle.task_id) == 36  # UUID
        finally:
            _remove_engine(db_url)

    def test_submit_persists_task_record(self, tmp_path) -> None:
        from aila.platform.tasks import TaskQueue, TaskRecord

        db_url = f"sqlite:///{tmp_path / 'persist.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        try:
            fn, _mod = _make_module_fn(
                "aila.modules.vulnerability.tasks.persist_mod", "scan"
            )

            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)
                tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
                handle = tq.submit(
                    track="vuln",
                    fn=fn,
                    kwargs={"target": "10.0.0.1"},
                    user_id="user-1",
                    group_id="operator",
                )

            with Session(engine) as s:
                record = s.get(TaskRecord, handle.task_id)
                assert record is not None
                assert record.track == "vuln"
                assert record.user_id == "user-1"
                assert record.group_id == "operator"
                assert json.loads(record.kwargs_json) == {"target": "10.0.0.1"}
        finally:
            _remove_engine(db_url)

    def test_submit_with_depends_on_sets_waiting_status(self, tmp_path) -> None:
        from aila.platform.tasks import TaskQueue, TaskRecord, TaskStatus

        db_url = f"sqlite:///{tmp_path / 'deps.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        try:
            fn, _mod = _make_module_fn(
                "aila.modules.vulnerability.tasks.dep_mod", "dep_fn"
            )

            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)
                tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
                # Submit A (no deps) — sync fallback, ends up DONE
                handle_a = tq.submit(track="vuln", fn=fn, kwargs={})
                # Submit B depending on A — should be WAITING
                handle_b = tq.submit(
                    track="vuln", fn=fn, kwargs={}, depends_on=[handle_a.task_id]
                )

            with Session(engine) as s:
                record_b = s.get(TaskRecord, handle_b.task_id)
                assert record_b.status == TaskStatus.WAITING
                assert json.loads(record_b.depends_on_json) == [handle_a.task_id]
        finally:
            _remove_engine(db_url)

    def test_submit_without_depends_on_sets_queued_then_done_via_fallback(
        self, tmp_path
    ) -> None:
        from aila.platform.tasks import TaskQueue, TaskRecord, TaskStatus

        db_url = f"sqlite:///{tmp_path / 'noq.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        try:
            fn, _mod = _make_module_fn(
                "aila.modules.vulnerability.tasks.noq_mod", "noq_fn"
            )

            # No Redis configured → sync fallback; fn is a no-op so DONE
            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)
                tq = TaskQueue(
                    config_registry=MockRegistry(redis_url=None),
                    module_id="vulnerability",
                )
                handle = tq.submit(track="vuln", fn=fn, kwargs={})

            with Session(engine) as s:
                record = s.get(TaskRecord, handle.task_id)
                # Sync fallback runs fn() successfully → DONE
                assert record.status == TaskStatus.DONE
        finally:
            _remove_engine(db_url)

    def test_submit_raises_on_cross_module_fn(self, tmp_path) -> None:
        from aila.platform.tasks import TaskQueue

        db_url = f"sqlite:///{tmp_path / 'cross.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        try:
            # fn from "network" module but tq bound to "vulnerability"
            fn, _mod = _make_module_fn(
                "aila.modules.network.tasks.cross_mod", "cross_fn"
            )

            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)
                tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
                with pytest.raises(ValueError, match="Module boundary violation"):
                    tq.submit(track="vuln", fn=fn, kwargs={})
        finally:
            _remove_engine(db_url)

    def test_submit_falls_back_to_sync_when_redis_unavailable(self, tmp_path) -> None:
        """When Redis ping fails, _sync_fallback is called and task ends as DONE."""
        from aila.platform.tasks import TaskQueue, TaskRecord, TaskStatus

        db_url = f"sqlite:///{tmp_path / 'redis_down.db'}"
        engine = _make_test_engine(db_url)
        _inject_engine(engine, db_url)

        try:
            fn, _mod = _make_module_fn(
                "aila.modules.vulnerability.tasks.rdown_mod", "rdown_fn"
            )

            # Redis URL is set but will be refused (port 19999)
            registry = MockRegistry(redis_url="redis://127.0.0.1:19999/0")

            with patch("aila.platform.tasks.queue.session_scope") as mock_scope:
                mock_scope.side_effect = lambda: _real_scope(engine)
                tq = TaskQueue(config_registry=registry, module_id="vulnerability")
                handle = tq.submit(track="vuln", fn=fn, kwargs={})

            # fn is a no-op; fallback runs it → DONE
            with Session(engine) as s:
                record = s.get(TaskRecord, handle.task_id)
                assert record.status == TaskStatus.DONE
        finally:
            _remove_engine(db_url)


# ---------------------------------------------------------------------------
# Package exports
# ---------------------------------------------------------------------------


class TestPackageExports:
    """TaskQueue is exported from aila.platform.tasks."""

    def test_task_queue_in_package_all(self) -> None:
        import aila.platform.tasks as tasks_pkg

        assert "TaskQueue" in tasks_pkg.__all__

    def test_task_queue_accessible_from_package(self) -> None:
        from aila.platform.tasks import TaskQueue

        assert callable(TaskQueue)
