"""Shared test fixtures for the sbd_nfr module tests.

Uses real PostgreSQL (AILA_TEST_DATABASE_URL). No SQLite, no aiosqlite.

Each test gets a clean DB via per-test deletion of all sbd_nfr_* table rows.
The session-scoped engine creates all tables once per test run.
The function-scoped test_db fixture sets AILA_DATABASE_URL so ServiceFactory,
async_session_scope, and UnitOfWork all resolve to the test database.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel

# Test database URL — read from env var, default to local PostgreSQL test DB
TEST_DB_URL: str = os.environ.get(
    "AILA_TEST_DATABASE_URL",
    "postgresql+asyncpg://postgres:admin@localhost:5432/aila_test",
)


@pytest_asyncio.fixture(scope="session")
async def _sbd_engine() -> AsyncGenerator[object, None]:
    """Session-scoped async engine: create tables once, shared across all tests.

    Imports all model modules so SQLModel.metadata is complete.
    Drops and recreates all tables to pick up any schema changes.
    """
    import aila.modules.sbd_nfr.db_models  # noqa: F401
    import aila.modules.vulnerability.db_models  # noqa: F401
    import aila.storage.database as _db_module
    import aila.storage.db_models  # noqa: F401

    engine = create_async_engine(TEST_DB_URL, echo=False, pool_pre_ping=True)

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
        await conn.run_sync(SQLModel.metadata.create_all)

    # Register in module-level caches for the duration of the test session
    with _db_module._ENGINE_LOCK:
        _db_module._ASYNC_ENGINES[TEST_DB_URL] = engine
        _db_module._INITIALIZED_URLS.add(TEST_DB_URL)

    yield engine

    # Clean up caches and dispose
    with _db_module._ENGINE_LOCK:
        _db_module._ASYNC_ENGINES.pop(TEST_DB_URL, None)
        _db_module._INITIALIZED_URLS.discard(TEST_DB_URL)
        _db_module._SESSION_FACTORIES.pop(TEST_DB_URL, None)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def test_db(_sbd_engine) -> AsyncGenerator[None, None]:
    """Function-scoped fixture: point AILA_DATABASE_URL at the test DB.

    Overrides AILA_DATABASE_URL so get_settings(), ServiceFactory,
    UnitOfWork, and async_session_scope all resolve to the test database.
    On teardown, deletes all rows from all sbd_nfr_* tables (plus platform
    tables) for per-test isolation.
    """
    import aila.storage.database as _db_module
    from aila.config import _build_settings

    old_db_url = os.environ.get("AILA_DATABASE_URL")
    os.environ["AILA_DATABASE_URL"] = TEST_DB_URL

    _build_settings.cache_clear()

    engine = _sbd_engine

    # Ensure caches point to our session engine (idempotent)
    with _db_module._ENGINE_LOCK:
        _db_module._ASYNC_ENGINES[TEST_DB_URL] = engine
        _db_module._INITIALIZED_URLS.add(TEST_DB_URL)

    yield

    # Teardown: delete all rows for per-test isolation
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


@pytest_asyncio.fixture(scope="function")
async def async_db_session(test_db) -> AsyncGenerator[object, None]:
    """Function-scoped real PostgreSQL session for direct DB seeding.

    Opens a session via async_session_scope() so seed helpers can call
    db.add() / db.flush() / db.commit() / db.exec() on the test database.
    The test_db fixture handles teardown (row deletion after each test).
    """
    from aila.storage.database import async_session_scope

    async with async_session_scope() as session:
        yield session


# ---------------------------------------------------------------------------
# Path and JSON loading fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def seed_data_dir() -> Path:
    """Return the path to the seed JSON data directory."""
    return (
        Path(__file__).resolve().parents[3]
        / "src"
        / "aila"
        / "modules"
        / "sbd_nfr"
        / "data"
    )


@pytest.fixture
def load_seed_json(seed_data_dir: Path):
    """Factory fixture: load a seed JSON file by name."""

    def _load(filename: str) -> object:
        path = seed_data_dir / filename
        return json.loads(path.read_text(encoding="utf-8"))

    return _load
