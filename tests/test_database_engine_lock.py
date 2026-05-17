from __future__ import annotations

"""Tests for thread-safe engine cache (_ENGINE_LOCK) in aila.storage.database.

RED phase — these tests MUST fail before the implementation is in place.
GREEN phase — all tests pass after _ENGINE_LOCK is added and used.
"""

import inspect
import threading


def _patch_settings_to_memory(monkeypatch):
    """Redirect get_settings() to an in-memory SQLite URL so no filesystem is touched."""
    import aila.config as cfg

    class _FakeSettings:
        database_url = "sqlite:///:memory:"

    monkeypatch.setattr(cfg, "get_settings", lambda: _FakeSettings())


def _clear_engines():
    from aila.storage import database as db

    db._ENGINES.clear()


def test_engine_lock_exists():
    """_ENGINE_LOCK must exist at module level and be an RLock instance."""
    import aila.storage.database as db

    assert hasattr(db, "_ENGINE_LOCK"), "_ENGINE_LOCK missing from aila.storage.database"
    assert isinstance(db._ENGINE_LOCK, type(threading.RLock())), (
        "_ENGINE_LOCK must be an RLock"
    )


def test_get_engine_uses_lock():
    """get_engine() source must contain 'with _ENGINE_LOCK:'."""
    import aila.storage.database as db

    src = inspect.getsource(db.get_engine)
    assert "with _ENGINE_LOCK" in src, "get_engine() is missing 'with _ENGINE_LOCK:' guard"


def test_dispose_engine_uses_lock():
    """dispose_engine() source must contain 'with _ENGINE_LOCK:'."""
    import aila.storage.database as db

    src = inspect.getsource(db.dispose_engine)
    assert "with _ENGINE_LOCK" in src, "dispose_engine() is missing 'with _ENGINE_LOCK:' guard"


def test_wal_pragma_present():
    """_configure_sqlite_connection must issue PRAGMA journal_mode=WAL."""
    import aila.storage.database as db

    src = inspect.getsource(db._configure_sqlite_connection)
    assert "journal_mode=WAL" in src, "WAL PRAGMA missing from _configure_sqlite_connection"


def test_concurrent_get_engine_single_instance(monkeypatch):
    """8 threads calling get_engine() simultaneously must produce exactly 1 engine."""
    _patch_settings_to_memory(monkeypatch)
    _clear_engines()

    from aila.storage.database import _ENGINES, get_engine

    results: list[int] = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()  # all threads start at the same instant
        e = get_engine()
        results.append(id(e))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(set(results)) == 1, (
        f"Expected 1 engine object from 8 threads, got {len(set(results))}"
    )
    assert len(_ENGINES) == 1, (
        f"Expected 1 key in _ENGINES after concurrent calls, got {len(_ENGINES)}"
    )


def test_dispose_engine_thread_safe(monkeypatch):
    """dispose_engine() and get_engine() run concurrently without crash or corruption."""
    _patch_settings_to_memory(monkeypatch)
    _clear_engines()

    from aila.storage.database import dispose_engine, get_engine

    errors: list[Exception] = []

    def getter():
        try:
            get_engine()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def disposer():
        try:
            dispose_engine()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=getter) for _ in range(4)]
    threads += [threading.Thread(target=disposer) for _ in range(4)]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread safety errors during concurrent get/dispose: {errors}"
