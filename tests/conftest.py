"""Project-wide pytest fixtures and test-only database shims.

Many legacy unit tests build an in-memory SQLite engine and call
``SQLModel.metadata.create_all`` against the whole metadata. That metadata
contains Postgres-only constructs (JSONB and TSVECTOR columns, and a STORED
generated column computed by ``to_tsvector``) that SQLite cannot render or
execute, so a single incompatible type aborts create_all for every table and
every SQLite-based test fails at setup.

These shims keep production models pure (Postgres still gets JSONB/TSVECTOR and
the real generated column) while letting the shared metadata create_all on a
SQLite test engine:

- ``@compiles(JSONB, "sqlite")`` -> ``JSON`` and ``@compiles(TSVECTOR, "sqlite")``
  -> ``TEXT`` so the column types render on SQLite.
- a ``connect`` shim registers a passthrough ``to_tsvector`` so the knowledge
  table's generated column evaluates on SQLite instead of raising
  ``no such function``.

None of this touches the PostgreSQL path used by the Alembic-driven ``test_db``
fixture.
"""
from __future__ import annotations

import os
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from sqlalchemy import event
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.ext.compiler import compiles
from sqlmodel import SQLModel


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type, _compiler, **_kw) -> str:
    return "JSON"


@compiles(TSVECTOR, "sqlite")
def _compile_tsvector_sqlite(_type, _compiler, **_kw) -> str:
    return "TEXT"


@event.listens_for(Engine, "connect")
def _register_sqlite_pg_shims(dbapi_connection, _record) -> None:
    """Register Postgres-only functions used in generated columns on SQLite.

    Only SQLite DBAPI connections expose ``create_function``; Postgres drivers
    do not, so this is a no-op there.
    """
    create_function = getattr(dbapi_connection, "create_function", None)
    if create_function is None:
        return
    # search_vector is Computed as to_tsvector('english', content); a passthrough
    # keeps SQLite create_all and inserts working (FTS itself is Postgres-only).
    create_function("to_tsvector", 2, lambda _config, text: text or "", deterministic=True)


# ---------------------------------------------------------------------------
# PostgreSQL test database (shared across root-level test files)
#
# Mirrors tests/api/conftest.py::test_db: a session-scoped async engine against
# aila_test with drop_all/create_all, and a function-scoped fixture that points
# AILA's engine caches at the test DB and truncates all tables on teardown for
# per-test isolation. SQLite is no longer supported (D-48/D-49).
# ---------------------------------------------------------------------------

TEST_DB_URL: str = os.environ.get(
    "AILA_TEST_DATABASE_URL",
    "postgresql+asyncpg://postgres:admin@localhost:5432/aila_test",
)


@pytest_asyncio.fixture(scope="session")
async def _root_session_async_engine() -> AsyncGenerator[object, None]:
    """Session-scoped async engine: create the full schema once against aila_test."""
    import aila.modules.vr.db_models  # noqa: F401
    import aila.modules.vulnerability.db_models  # noqa: F401
    # RFC-12 retrieval graph -- edge table lives in the retrieval
    # slice module. Importing it here keeps the session engine's
    # drop_all/create_all aware of the FK to knowledgeentryrecord
    # regardless of which test file triggers the fixture.
    import aila.platform.services.knowledge_graph  # noqa: F401
    import aila.storage.database as _db_module
    import aila.storage.db_models  # noqa: F401

    engine = create_async_engine(TEST_DB_URL, echo=False, pool_pre_ping=True)

    async with engine.begin() as conn:
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
async def test_db(_root_session_async_engine) -> AsyncGenerator[None, None]:
    """Point AILA engine caches at aila_test; truncate all tables on teardown."""
    import aila.storage.database as _db_module
    from aila.config import _build_settings

    old_db_url = os.environ.get("AILA_DATABASE_URL")
    os.environ["AILA_DATABASE_URL"] = TEST_DB_URL

    _build_settings.cache_clear()

    engine = _root_session_async_engine

    with _db_module._ENGINE_LOCK:
        _db_module._ASYNC_ENGINES[TEST_DB_URL] = engine
        _db_module._INITIALIZED_URLS.add(TEST_DB_URL)

    yield

    async with engine.begin() as conn:
        for table in reversed(SQLModel.metadata.sorted_tables):
            try:
                await conn.execute(table.delete())
            except Exception:  # noqa: BLE001 -- table may be absent in this schema state
                pass

    if old_db_url is None:
        os.environ.pop("AILA_DATABASE_URL", None)
    else:
        os.environ["AILA_DATABASE_URL"] = old_db_url

    _build_settings.cache_clear()
