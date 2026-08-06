"""Tests for thread-safe engine cache (_ENGINE_LOCK) in aila.storage.database.

Contract update
---------------
SQLite is no longer supported (D-48/D-49): the sync ``get_engine`` factory
and its ``_configure_sqlite_connection`` helper (which issued the WAL PRAGMA)
were removed with the switch to PostgreSQL + asyncpg. The async cache
``_ASYNC_ENGINES`` is now the primary path; ``get_async_engine`` reads and
mutates it under ``_ENGINE_LOCK``, and ``dispose_engine`` is async and holds
the same lock while popping the cache entry.

These tests cover the surviving invariants:
- ``_ENGINE_LOCK`` exists and is an ``RLock``.
- Both cache mutators (``get_async_engine`` and ``dispose_engine``) hold the
  lock in their sources.
- 8 threads calling ``get_async_engine`` produce exactly one engine.
- Concurrent get + dispose does not crash.

The previous WAL PRAGMA test was dropped because the SQLite plumbing it
guarded no longer exists.
"""
from __future__ import annotations

import asyncio
import inspect
import threading

_CONCURRENT_URL = "postgresql+asyncpg://x@127.0.0.1/_engine_lock_concurrent"
_DISPOSE_URL = "postgresql+asyncpg://x@127.0.0.1/_engine_lock_dispose"


class _FakeSettings:
    def __init__(self, url: str) -> None:
        self.database_url = url


def _pop_cache_entry(url: str) -> None:
    import aila.storage.database as db

    with db._ENGINE_LOCK:
        db._ASYNC_ENGINES.pop(url, None)
        db._SESSION_FACTORIES.pop(url, None)
        db._INITIALIZED_URLS.discard(url)


def test_engine_lock_exists():
    """_ENGINE_LOCK must exist at module level and be an RLock instance."""
    import aila.storage.database as db

    assert hasattr(db, "_ENGINE_LOCK"), "_ENGINE_LOCK missing from aila.storage.database"
    assert isinstance(db._ENGINE_LOCK, type(threading.RLock())), (
        "_ENGINE_LOCK must be an RLock"
    )


def test_get_async_engine_uses_lock():
    """get_async_engine() source must contain 'with _ENGINE_LOCK:'."""
    import aila.storage.database as db

    src = inspect.getsource(db.get_async_engine)
    assert "with _ENGINE_LOCK" in src, (
        "get_async_engine() is missing 'with _ENGINE_LOCK:' guard"
    )


def test_dispose_engine_uses_lock():
    """dispose_engine() source must contain 'with _ENGINE_LOCK:'."""
    import aila.storage.database as db

    src = inspect.getsource(db.dispose_engine)
    assert "with _ENGINE_LOCK" in src, (
        "dispose_engine() is missing 'with _ENGINE_LOCK:' guard"
    )


def test_concurrent_get_async_engine_single_instance():
    """8 threads calling get_async_engine simultaneously produce exactly 1 engine.

    Uses a throwaway URL that never opens a real connection: create_async_engine
    is lazy for asyncpg URLs, so no network I/O occurs even when the URL is
    unreachable.
    """
    import aila.storage.database as db

    _pop_cache_entry(_CONCURRENT_URL)
    try:
        results: list[int] = []
        errors: list[BaseException] = []
        barrier = threading.Barrier(8)

        def worker():
            try:
                barrier.wait()
                engine = db.get_async_engine(_FakeSettings(_CONCURRENT_URL))
                results.append(id(engine))
            except BaseException as exc:  # noqa: BLE001 -- surface any thread failure
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"errors during concurrent get_async_engine: {errors}"
        assert len(set(results)) == 1, (
            f"Expected 1 engine object from 8 threads, got {len(set(results))}"
        )
        assert _CONCURRENT_URL in db._ASYNC_ENGINES, (
            "Expected the throwaway URL to be present in _ASYNC_ENGINES"
        )
    finally:
        engine = db._ASYNC_ENGINES.get(_CONCURRENT_URL)
        if engine is not None:
            asyncio.run(engine.dispose())
        _pop_cache_entry(_CONCURRENT_URL)


def test_dispose_engine_thread_safe():
    """get_async_engine and dispose_engine run concurrently without crash.

    Runs 4 getter threads and 4 disposer threads on a throwaway URL. Each
    disposer invokes the async ``dispose_engine`` inside its own asyncio loop.
    The only expected outcome is a clean join with no thread-recorded errors.
    """
    import aila.storage.database as db

    _pop_cache_entry(_DISPOSE_URL)
    errors: list[BaseException] = []

    def getter():
        try:
            db.get_async_engine(_FakeSettings(_DISPOSE_URL))
        except BaseException as exc:  # noqa: BLE001 -- surface any thread failure
            errors.append(exc)

    def disposer():
        try:
            asyncio.run(db.dispose_engine(_FakeSettings(_DISPOSE_URL)))
        except BaseException as exc:  # noqa: BLE001 -- surface any thread failure
            errors.append(exc)

    threads = [threading.Thread(target=getter) for _ in range(4)]
    threads += [threading.Thread(target=disposer) for _ in range(4)]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    engine = db._ASYNC_ENGINES.get(_DISPOSE_URL)
    if engine is not None:
        asyncio.run(engine.dispose())
    _pop_cache_entry(_DISPOSE_URL)

    assert not errors, f"Thread safety errors during concurrent get/dispose: {errors}"
