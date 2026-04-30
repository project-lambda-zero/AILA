"""Shared helpers for Phase 178 task-failsafe tests.

Tests that need Redis use db index 15 to avoid polluting the production
queue (db 0). Tests that need PostgreSQL use the shared ``test_db`` fixture
already exposed by tests/platform/conftest.py.
"""
from __future__ import annotations

import os
import socket
from contextlib import contextmanager

import pytest
from sqlalchemy import create_engine
from sqlmodel import Session, SQLModel

# Separate Redis db so the test suite never touches the production queue.
TEST_REDIS_URL_DEFAULT = "redis://127.0.0.1:6379/15"


def _redis_reachable(url: str, timeout: float = 0.5) -> bool:
    """Return True if a TCP connect to the Redis host:port succeeds."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 6379
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def redis_test_url() -> str:
    return os.environ.get("AILA_TEST_REDIS_URL", TEST_REDIS_URL_DEFAULT)


@pytest.fixture
def redis_required(redis_test_url: str) -> str:
    """Skip the test when Redis is not reachable on 127.0.0.1:6379/15."""
    if not _redis_reachable(redis_test_url):
        pytest.skip(f"Redis not reachable at {redis_test_url}; skipping test")
    return redis_test_url


@pytest.fixture
def redis_cleanup(redis_required: str):
    """Flush the test Redis database before and after the test."""
    import asyncio

    import redis.asyncio as aioredis

    async def _flush():
        client = aioredis.Redis.from_url(redis_required, socket_connect_timeout=2.0)
        try:
            await client.flushdb()
        finally:
            await client.aclose()

    asyncio.run(_flush())
    yield redis_required
    asyncio.run(_flush())


# --- SQLite DB isolation helpers (mirror tests/test_106_worker_crash_recovery.py)


def make_sqlite_engine(db_url: str):
    """Create an SQLite engine with only the TaskRecord table.

    Registering every db_model breaks under SQLite because some Postgres-only
    columns (TSVECTOR, pgvector Vector, etc.) have no SQLite compiler. The
    failsafe tests only touch taskrecord, so we create that table in
    isolation and skip the rest of the metadata.
    """
    import aila.platform.tasks.models as _tasks_models  # noqa: F401

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    # Create just the TaskRecord table — avoid SQLModel.metadata.create_all
    # which also tries to emit TSVECTOR columns on the knowledge table.
    _tasks_models.TaskRecord.__table__.create(engine, checkfirst=True)
    return engine


def inject_engine(engine, db_url: str) -> None:
    import aila.storage.database as _db_module

    with _db_module._ENGINE_LOCK:
        _db_module._ENGINES[db_url] = engine
        _db_module._INITIALIZED_URLS.add(db_url)


def remove_engine(db_url: str) -> None:
    import aila.storage.database as _db_module

    with _db_module._ENGINE_LOCK:
        _db_module._ENGINES.pop(db_url, None)
        _db_module._INITIALIZED_URLS.discard(db_url)


@contextmanager
def real_scope(engine):
    with Session(engine) as s:
        yield s


@contextmanager
def sqlite_db_env(tmp_path, name: str = "failsafe"):
    """Yield (engine, db_url) wired into both sync and async DB paths."""
    import aila.storage.database as _db_module

    db_url = f"sqlite:///{tmp_path / f'{name}.db'}"
    engine = make_sqlite_engine(db_url)
    inject_engine(engine, db_url)

    # Monkey-patch the async session to a sync-backed scope so worker code
    # that calls async_session_scope still hits the per-test engine.
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _fake_async_scope(**_kw):
        # Yield a thin shim that proxies select/execute/add/commit to the
        # sync Session. The worker only uses: .exec, .execute, .get, .add,
        # .delete, .commit, .refresh.
        with Session(engine) as s:
            yield _SyncSessionAdapter(s)

    saved = _db_module.async_session_scope
    _db_module.async_session_scope = _fake_async_scope
    # Also patch the attribute on any already-imported modules that captured
    # a direct reference.
    import aila.platform.tasks.worker as _worker
    import aila.platform.tasks.queue as _queue
    _worker.async_session_scope = _fake_async_scope
    _queue.async_session_scope = _fake_async_scope

    try:
        yield engine, db_url
    finally:
        _db_module.async_session_scope = saved
        _worker.async_session_scope = saved
        _queue.async_session_scope = saved
        remove_engine(db_url)


class _SyncSessionAdapter:
    """Adapter that exposes an async-looking interface over a sync Session.

    Only implements the subset of methods the worker / queue / reaper paths
    actually use. Any unknown attribute raises so regressions surface early.
    """

    def __init__(self, s: Session):
        self._s = s

    async def exec(self, stmt):  # noqa: A003 — mirrors SQLModel.AsyncSession API
        return self._s.exec(stmt)

    async def execute(self, stmt):
        return self._s.execute(stmt)

    async def get(self, model, pk):
        return self._s.get(model, pk)

    def add(self, instance) -> None:
        self._s.add(instance)

    async def delete(self, instance) -> None:
        self._s.delete(instance)

    async def commit(self) -> None:
        self._s.commit()

    async def refresh(self, instance) -> None:
        self._s.refresh(instance)
