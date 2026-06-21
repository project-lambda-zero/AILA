"""Shared fixtures for platform tests.

Re-exports the DB fixtures from tests/api/conftest.py so that platform tests
can use test_db, admin_key_record, etc. without duplication.

All tests run against PostgreSQL via AILA_TEST_DATABASE_URL. No SQLite.
"""
from __future__ import annotations

import os
from collections.abc import AsyncGenerator

import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel

# Test database URL -- same as tests/api/conftest.py
TEST_DB_URL: str = os.environ.get(
    "AILA_TEST_DATABASE_URL",
    "postgresql+asyncpg://postgres:admin@localhost:5432/aila_test",
)


@pytest_asyncio.fixture(scope="session")
async def _session_async_engine() -> AsyncGenerator[object, None]:
    """Session-scoped async engine: create tables once, shared across all tests."""
    import aila.modules.vulnerability.db_models  # noqa: F401
    import aila.storage.database as _db_module
    import aila.storage.db_models  # noqa: F401

    engine = create_async_engine(TEST_DB_URL, echo=False, pool_pre_ping=True)

    async with engine.begin() as conn:
        # Drop and recreate to pick up schema changes (e.g., new team_id columns)
        await conn.run_sync(SQLModel.metadata.drop_all)
        await conn.run_sync(SQLModel.metadata.create_all)

    with _db_module._ENGINE_LOCK:
        _db_module._ASYNC_ENGINES[TEST_DB_URL] = engine
        _db_module._INITIALIZED_URLS.add(TEST_DB_URL)

    yield engine

    with _db_module._ENGINE_LOCK:
        _db_module._ASYNC_ENGINES.pop(TEST_DB_URL, None)
        _db_module._INITIALIZED_URLS.discard(TEST_DB_URL)
        _db_module._SESSION_FACTORIES.pop(TEST_DB_URL, None)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def test_db(_session_async_engine) -> AsyncGenerator[None, None]:
    """Function-scoped fixture: per-test DB isolation via TRUNCATE."""
    import aila.storage.database as _db_module
    from aila.config import _build_settings

    old_db_url = os.environ.get("AILA_DATABASE_URL")
    os.environ["AILA_DATABASE_URL"] = TEST_DB_URL
    _build_settings.cache_clear()

    engine = _session_async_engine

    with _db_module._ENGINE_LOCK:
        _db_module._ASYNC_ENGINES[TEST_DB_URL] = engine
        _db_module._INITIALIZED_URLS.add(TEST_DB_URL)

    yield

    async with engine.begin() as conn:
        for table in reversed(SQLModel.metadata.sorted_tables):
            try:
                await conn.execute(table.delete())
            except Exception:  # noqa: BLE001
                pass

    if old_db_url is None:
        os.environ.pop("AILA_DATABASE_URL", None)
    else:
        os.environ["AILA_DATABASE_URL"] = old_db_url

    _build_settings.cache_clear()
