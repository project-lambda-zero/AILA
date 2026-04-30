"""PostgreSQL fixture for Phase 124 database foundation tests.

Connects to the local PostgreSQL instance. Uses a dedicated test database
(aila_test) to avoid polluting the development database. Creates the test
database if it doesn't exist. Enables pgvector extension.

Uses a session-scoped event loop so all async tests in tests/storage/
share one loop — prevents asyncpg "Event loop is closed" errors on
Windows ProactorEventLoop where function-scoped loops cause teardown
races with the connection pool.

Scoped to this directory only via pytest_collection_modifyitems hook.
E2E tests and other test directories keep function-scoped loops.
"""
from __future__ import annotations

import asyncio
import os
import subprocess

import pytest

__all__ = ["pg_url", "pg_engine", "pg_session"]


# Connection defaults for local PostgreSQL
PG_HOST = os.environ.get("AILA_TEST_PG_HOST", "localhost")
PG_PORT = os.environ.get("AILA_TEST_PG_PORT", "5432")
PG_USER = os.environ.get("AILA_TEST_PG_USER", "postgres")
PG_PASSWORD = os.environ.get("AILA_TEST_PG_PASSWORD", "admin")
PG_TEST_DB = os.environ.get("AILA_TEST_PG_DB", "aila_test")

PSQL_BIN = r"C:\Program Files\PostgreSQL\18\bin\psql"


def _run_psql(db: str, sql: str) -> subprocess.CompletedProcess:
    """Run a SQL command via psql against the local PostgreSQL."""
    env = {**os.environ, "PGPASSWORD": PG_PASSWORD}
    return subprocess.run(
        [PSQL_BIN, "-U", PG_USER, "-h", PG_HOST, "-p", PG_PORT, "-d", db, "-c", sql],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )


def _ensure_test_db() -> None:
    """Create the test database and enable pgvector if they don't exist."""
    # Check if test DB exists
    result = _run_psql(
        "postgres",
        f"SELECT 1 FROM pg_database WHERE datname = '{PG_TEST_DB}';",
    )
    if PG_TEST_DB not in (result.stdout or ""):
        # Doesn't exist — but CREATE DATABASE can't run in a transaction
        _run_psql("postgres", f"CREATE DATABASE {PG_TEST_DB};")

    # Enable pgvector extension
    _run_psql(PG_TEST_DB, "CREATE EXTENSION IF NOT EXISTS vector;")


@pytest.fixture(scope="session")
def pg_url():
    """Return the async database URL for the test PostgreSQL.

    Creates the test database and enables pgvector if needed.
    Sets AILA_DATABASE_URL so the application code uses the test DB.
    Disposes the engine at session end so asyncpg closes connections
    cleanly before the event loop shuts down (Windows ProactorEventLoop
    teardown race fix).
    """
    # Use explicit URL if provided
    explicit_url = os.environ.get("AILA_TEST_DATABASE_URL")
    if explicit_url:
        os.environ["AILA_DATABASE_URL"] = explicit_url
        yield explicit_url
        _dispose_engines_sync()
        return

    # Otherwise use local PostgreSQL
    _ensure_test_db()

    url = (
        f"postgresql+asyncpg://{PG_USER}:{PG_PASSWORD}"
        f"@{PG_HOST}:{PG_PORT}/{PG_TEST_DB}"
    )
    os.environ["AILA_DATABASE_URL"] = url
    yield url

    # Dispose engines before pytest closes the event loop — prevents
    # asyncpg "Event loop is closed" errors on Windows ProactorEventLoop
    _dispose_engines_sync()


def _dispose_engines_sync() -> None:
    """Dispose all cached async engines synchronously.

    Runs asyncpg connection cleanup while the event loop is still alive.
    Must be called from a sync context (fixture teardown).
    """
    try:
        from aila.storage.database import dispose_engine
        loop = asyncio.new_event_loop()
        loop.run_until_complete(dispose_engine())
        loop.close()
    except Exception:
        pass  # Best-effort cleanup — don't fail teardown


@pytest.fixture
def pg_engine(pg_url):
    """Return an async engine pointed at the test PostgreSQL."""
    from aila.storage.database import get_async_engine

    return get_async_engine()


@pytest.fixture
async def pg_session(pg_url):
    """Yield an AsyncSession from async_session_scope."""
    from aila.storage.database import async_session_scope

    async with async_session_scope() as session:
        yield session
