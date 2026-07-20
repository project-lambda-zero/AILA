"""Tests for TaskQueue -- platform task submission API (Phase 54, Plan 03).

Async migration (Phase 178/179):
  - ``TaskQueue.submit`` and ``_validate_dag`` are ``async`` and use
    ``async_session_scope`` internally against aila_test.
  - ``_sync_fallback`` and the "sync-fallback when Redis is unavailable"
    behaviour were removed (see queue.py header, D-19 revised): the
    canonical fail path is now to raise ``WorkerUnreachableError`` before
    any TaskRecord is persisted, so callers get a clean HTTP 503 and no
    orphan rows accumulate. The tests for the removed fallback path are
    dropped; a WorkerUnreachableError test covers the new contract.
  - Sync helpers (``_get_fn_path``, ``_extract_module_id``,
    ``_enforce_module_boundary``, ``_get_redis_url``) remain sync.
  - DB-touching tests depend on the shared ``test_db`` fixture. Insertion
    setup runs through ``session_scope()`` (sync psycopg); TaskQueue writes
    through ``async_session_scope`` -- both hit aila_test.
"""

from __future__ import annotations

import json
import sys
import types
from unittest.mock import AsyncMock, patch

import pytest
from sqlmodel import select

from aila.platform.exceptions import WorkerUnreachableError
from aila.storage.database import session_scope

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
    """Minimal ConfigRegistry stub. Returns None for all keys by default.

    Duck-typed sync ``.get()`` matches what ``TaskQueue._get_redis_url``
    consumes (that helper is sync and detects coroutines via
    ``hasattr(..., '__await__')`` on the return value).
    """

    def __init__(self, redis_url: str | None = None) -> None:
        self._redis_url = redis_url

    def get(self, namespace: str, key: str) -> str | None:
        if namespace == "platform" and key == "redis_url":
            return self._redis_url
        return None


def _install_fake_enqueue(tq, *, ok: bool = True) -> AsyncMock:
    """Replace ``tq._arq_enqueue_async`` with an AsyncMock that returns ``ok``.

    Returned mock lets tests assert the enqueue was awaited when needed.
    """
    fake = AsyncMock(return_value=ok)
    tq._arq_enqueue_async = fake  # type: ignore[method-assign]
    return fake


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
# _get_fn_path (sync)
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
# _extract_module_id (sync)
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
# _enforce_module_boundary (sync)
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
# _get_redis_url (sync)
# ---------------------------------------------------------------------------


class TestGetRedisUrl:
    """_get_redis_url reads from env var first, then ConfigRegistry."""

    def test_returns_configured_url(self, monkeypatch) -> None:
        from aila.platform.tasks import TaskQueue

        # Force env-var precedence off so we exercise the registry branch.
        monkeypatch.delenv("AILA_PLATFORM_REDIS_URL", raising=False)

        registry = MockRegistry(redis_url="redis://localhost:6379/0")
        tq = TaskQueue(config_registry=registry, module_id="vulnerability")
        assert tq._get_redis_url() == "redis://localhost:6379/0"

    def test_returns_none_when_unconfigured(self, monkeypatch) -> None:
        from aila.platform.tasks import TaskQueue

        monkeypatch.delenv("AILA_PLATFORM_REDIS_URL", raising=False)

        registry = MockRegistry(redis_url=None)
        tq = TaskQueue(config_registry=registry, module_id="vulnerability")
        assert tq._get_redis_url() is None

    def test_returns_none_when_empty_string(self, monkeypatch) -> None:
        from aila.platform.tasks import TaskQueue

        monkeypatch.delenv("AILA_PLATFORM_REDIS_URL", raising=False)

        registry = MockRegistry(redis_url="")
        tq = TaskQueue(config_registry=registry, module_id="vulnerability")
        assert tq._get_redis_url() is None

    def test_returns_none_when_registry_raises(self, monkeypatch) -> None:
        from aila.platform.tasks import TaskQueue

        monkeypatch.delenv("AILA_PLATFORM_REDIS_URL", raising=False)

        class BrokenRegistry:
            def get(self, ns, key):
                raise RuntimeError("DB unavailable")

        tq = TaskQueue(config_registry=BrokenRegistry(), module_id="vulnerability")
        # Should not propagate the exception
        assert tq._get_redis_url() is None

    def test_env_var_takes_precedence(self, monkeypatch) -> None:
        from aila.platform.tasks import TaskQueue

        monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", "redis://envhost:6379/1")

        registry = MockRegistry(redis_url="redis://registryhost:6379/0")
        tq = TaskQueue(config_registry=registry, module_id="vulnerability")
        assert tq._get_redis_url() == "redis://envhost:6379/1"


# ---------------------------------------------------------------------------
# _validate_dag (async)
# ---------------------------------------------------------------------------


class TestValidateDag:
    """_validate_dag raises ValueError on circular depends_on."""

    async def test_no_cycle_passes(self, test_db) -> None:
        """A linear chain A -> B has no cycle; adding C -> B should pass."""
        from aila.platform.tasks import TaskQueue, TaskRecord, TaskStatus

        with session_scope() as s:
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

        tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
        # C depends on B -- no cycle
        await tq._validate_dag("task-c", [b_id])

    async def test_cycle_raises_value_error(self, test_db) -> None:
        """A depends on B and B depends on A is a cycle -- must raise ValueError."""
        from aila.platform.tasks import TaskQueue, TaskRecord, TaskStatus

        with session_scope() as s:
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
        with session_scope() as s:
            task_a = s.exec(select(TaskRecord).where(TaskRecord.id == a_id)).first()
            task_a.depends_on_json = json.dumps(["task-b"])
            s.add(task_a)
            s.commit()

        tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
        # task-b depends on a_id, but a_id depends on task-b → cycle
        with pytest.raises(ValueError, match="Circular dependency"):
            await tq._validate_dag("task-b", [a_id])


# ---------------------------------------------------------------------------
# submit() -- integration tests
# ---------------------------------------------------------------------------


class TestSubmit:
    """submit() creates TaskRecord and returns TaskHandle."""

    async def test_submit_returns_task_handle(self, test_db) -> None:
        from aila.platform.tasks import TaskHandle, TaskQueue

        fn, _mod = _make_module_fn("aila.modules.vulnerability.tasks.submit_mod")

        tq = TaskQueue(
            config_registry=MockRegistry(redis_url="redis://127.0.0.1:6379/0"),
            module_id="vulnerability",
        )
        _install_fake_enqueue(tq, ok=True)
        handle = await tq.submit(track="vuln", fn=fn, kwargs={"target": "192.168.1.1"})

        assert isinstance(handle, TaskHandle)
        assert isinstance(handle.task_id, str)
        assert len(handle.task_id) == 36  # UUID

    async def test_submit_persists_task_record(self, test_db) -> None:
        from aila.platform.tasks import TaskQueue, TaskRecord

        fn, _mod = _make_module_fn(
            "aila.modules.vulnerability.tasks.persist_mod", "scan",
        )

        tq = TaskQueue(
            config_registry=MockRegistry(redis_url="redis://127.0.0.1:6379/0"),
            module_id="vulnerability",
        )
        _install_fake_enqueue(tq, ok=True)
        handle = await tq.submit(
            track="vuln",
            fn=fn,
            kwargs={"target": "10.0.0.1"},
            user_id="user-1",
            group_id="operator",
        )

        with session_scope() as s:
            record = s.exec(select(TaskRecord).where(TaskRecord.id == handle.task_id)).first()
            assert record is not None
            assert record.track == "vuln"
            assert record.user_id == "user-1"
            assert record.group_id == "operator"
            assert json.loads(record.kwargs_json) == {"target": "10.0.0.1"}

    async def test_submit_with_depends_on_sets_waiting_status(self, test_db) -> None:
        from aila.platform.tasks import TaskQueue, TaskRecord, TaskStatus

        fn, _mod = _make_module_fn(
            "aila.modules.vulnerability.tasks.dep_mod", "dep_fn",
        )

        tq = TaskQueue(
            config_registry=MockRegistry(redis_url="redis://127.0.0.1:6379/0"),
            module_id="vulnerability",
        )
        _install_fake_enqueue(tq, ok=True)

        # Distinct kwargs per task: the dedup hash is over {fn, kwargs} and
        # excludes depends_on, so identical kwargs would collapse B into A's
        # existing queued record and return A's id.
        handle_a = await tq.submit(track="vuln", fn=fn, kwargs={"n": 1})
        # Submit B depending on A -- WAITING, no Redis path exercised.
        handle_b = await tq.submit(
            track="vuln", fn=fn, kwargs={"n": 2}, depends_on=[handle_a.task_id],
        )

        with session_scope() as s:
            record_b = s.exec(select(TaskRecord).where(TaskRecord.id == handle_b.task_id)).first()
            assert record_b.status == TaskStatus.WAITING
            assert json.loads(record_b.depends_on_json) == [handle_a.task_id]

    async def test_submit_without_depends_on_sets_queued(self, test_db) -> None:
        """Without depends_on and with a healthy broker the row is QUEUED
        (Phase 179 removed the sync fallback that would have driven it to DONE)."""
        from aila.platform.tasks import TaskQueue, TaskRecord, TaskStatus

        fn, _mod = _make_module_fn(
            "aila.modules.vulnerability.tasks.noq_mod", "noq_fn",
        )

        tq = TaskQueue(
            config_registry=MockRegistry(redis_url="redis://127.0.0.1:6379/0"),
            module_id="vulnerability",
        )
        _install_fake_enqueue(tq, ok=True)
        handle = await tq.submit(track="vuln", fn=fn, kwargs={})

        with session_scope() as s:
            record = s.exec(select(TaskRecord).where(TaskRecord.id == handle.task_id)).first()
            assert record.status == TaskStatus.QUEUED

    async def test_submit_raises_on_cross_module_fn(self, test_db) -> None:
        from aila.platform.tasks import TaskQueue

        # fn from "network" module but tq bound to "vulnerability"
        fn, _mod = _make_module_fn(
            "aila.modules.network.tasks.cross_mod", "cross_fn",
        )

        tq = TaskQueue(config_registry=MockRegistry(), module_id="vulnerability")
        with pytest.raises(ValueError, match="Module boundary violation"):
            await tq.submit(track="vuln", fn=fn, kwargs={})

    async def test_submit_raises_worker_unreachable_when_redis_unconfigured(
        self, test_db, monkeypatch,
    ) -> None:
        """Phase 179: no sync fallback. If ``redis_url`` is missing, submit()
        raises ``WorkerUnreachableError`` BEFORE writing any TaskRecord."""
        from aila.platform.tasks import TaskQueue, TaskRecord

        # _get_redis_url() consults AILA_PLATFORM_REDIS_URL before the registry;
        # clear it so the registry's None value is the effective resolution.
        monkeypatch.delenv("AILA_PLATFORM_REDIS_URL", raising=False)

        fn, _mod = _make_module_fn(
            "aila.modules.vulnerability.tasks.rdown_mod", "rdown_fn",
        )

        tq = TaskQueue(
            config_registry=MockRegistry(redis_url=None),
            module_id="vulnerability",
        )
        with pytest.raises(WorkerUnreachableError):
            await tq.submit(track="vuln", fn=fn, kwargs={})

        # No orphan TaskRecord was persisted.
        with session_scope() as s:
            rows = s.exec(select(TaskRecord)).all()
            assert rows == []

    async def test_submit_raises_worker_unreachable_when_enqueue_fails(
        self, test_db,
    ) -> None:
        """When ARQ enqueue returns False the submitted TaskRecord is
        rolled back and ``WorkerUnreachableError`` is raised."""
        from aila.platform.tasks import TaskQueue, TaskRecord

        fn, _mod = _make_module_fn(
            "aila.modules.vulnerability.tasks.enqfail_mod", "enqfail_fn",
        )

        tq = TaskQueue(
            config_registry=MockRegistry(redis_url="redis://127.0.0.1:6379/0"),
            module_id="vulnerability",
        )
        _install_fake_enqueue(tq, ok=False)

        with pytest.raises(WorkerUnreachableError):
            await tq.submit(track="vuln", fn=fn, kwargs={})

        # The initial insert was rolled back by the submit() rollback path.
        with session_scope() as s:
            rows = s.exec(select(TaskRecord)).all()
            assert rows == []


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
