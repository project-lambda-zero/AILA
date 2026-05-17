"""Tests for PostgreSQL async engine creation and pool configuration.

Covers: 124-01-01, DB-01, DB-05
TDD red phase -- these tests will fail until Plan 01 implements
get_async_engine() in aila.storage.database.
"""
from __future__ import annotations

__all__: list[str] = []


def test_get_async_engine_returns_async_engine(pg_url):
    """get_async_engine() returns an AsyncEngine with asyncpg dialect."""
    from aila.storage.database import get_async_engine

    engine = get_async_engine()
    assert engine is not None
    assert "asyncpg" in str(engine.url), "Engine must use asyncpg driver"


def test_engine_pool_config(pg_url):
    """Engine has correct pool configuration: pool_size=10, max_overflow=10."""
    from aila.storage.database import get_async_engine

    engine = get_async_engine()
    pool = engine.pool
    assert pool.size() == 10, f"pool_size should be 10, got {pool.size()}"
    assert pool._max_overflow == 10, "max_overflow should be 10"


def test_engine_caches_by_url(pg_url):
    """Same URL returns same engine instance (cached)."""
    from aila.storage.database import get_async_engine

    e1 = get_async_engine()
    e2 = get_async_engine()
    assert e1 is e2, "Engine should be cached by URL"


def test_no_sqlite_in_engine(pg_url):
    """Engine URL must not contain sqlite."""
    from aila.storage.database import get_async_engine

    engine = get_async_engine()
    assert "sqlite" not in str(engine.url).lower()
