"""PostgreSQL async engine factory, session management, and schema bootstrap.

Async-first database infrastructure using asyncpg as the primary driver.
A module-level engine cache (_ASYNC_ENGINES) keyed by URL avoids creating
multiple connection pools to the same database.  All check-and-set operations
on the cache are guarded by _ENGINE_LOCK (RLock for re-entrant callers such
as test teardown).

Connection pool defaults: pool_size=10, max_overflow=10, pool_timeout=30,
pool_recycle=1800, pool_pre_ping=True.

Platform tables (storage/db_models.py) are always created via SQLModel.metadata.
Module-owned tables are registered with SchemaRegistry and created only when
a SchemaRegistry is passed to init_db().
"""

from __future__ import annotations

import asyncio
import subprocess
import threading
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from sqlalchemy import create_engine as _create_sync_engine
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker as _sync_sessionmaker
from sqlmodel import Session, SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from ..config import get_settings
from ..platform.exceptions import UpstreamError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from .registry import SchemaRegistry

_ASYNC_ENGINES: dict[str, object] = {}
# _ENGINES is a sync engine cache used by SQLite test fixtures via session_scope().
# Production code always uses _ASYNC_ENGINES via async_session_scope().
_ENGINES: dict[str, object] = {}
_ENGINE_LOCK = threading.RLock()
_INITIALIZED_URLS: set[str] = set()
_SESSION_FACTORIES: dict[str, async_sessionmaker] = {}
_SYNC_SESSION_FACTORIES: dict[str, _sync_sessionmaker] = {}  # type: ignore[type-arg]


class DatabaseSettings(Protocol):
    """Structural protocol satisfied by Settings and any test-doubles.

    Only database_url is required so callers can pass lightweight objects
    that carry just the URL without constructing a full Settings instance.
    """

    database_url: str


def get_async_engine(settings: DatabaseSettings | None = None):
    """Return a cached async SQLAlchemy engine for the configured database URL.

    Engines are cached by URL in the module-level _ASYNC_ENGINES dict.  The
    first call for a given URL creates the engine with asyncpg connection
    pooling.  Subsequent calls return the cached engine.

    The check-and-set is guarded by _ENGINE_LOCK so concurrent threads do not
    race to create duplicate engines for the same URL.

    Args:
        settings: Optional settings object providing database_url.  Falls back
            to get_settings() when None.

    Returns:
        An async SQLAlchemy engine for the configured URL.
    """
    active_settings = settings or get_settings()
    url = active_settings.database_url
    with _ENGINE_LOCK:
        engine = _ASYNC_ENGINES.get(url)
        if engine is None:
            # asyncpg attempts SSL by default; disable for local dev PostgreSQL
            # that doesn't have SSL configured. Production should use SSL.
            _connect_args: dict[str, object] = {}
            if "localhost" in url or "127.0.0.1" in url:
                _connect_args["ssl"] = False
            engine = create_async_engine(
                url,
                echo=False,
                pool_size=10,
                max_overflow=10,
                pool_timeout=30,
                pool_recycle=1800,
                pool_pre_ping=True,
                connect_args=_connect_args,
            )
            _ASYNC_ENGINES[url] = engine
    return engine


@asynccontextmanager
async def async_session_scope(
    settings: DatabaseSettings | None = None,
    team_context: object | None = None,
) -> AsyncIterator[AsyncSession]:
    """Async context manager that yields an AsyncSession bound to a pooled engine.

    Session factories are cached per URL alongside the engine.  The session
    uses expire_on_commit=False so detached instances remain usable after
    commit.

    The team scope do_orm_execute listener is registered (idempotently) on
    first call so that all sessions are covered by team-scoped filtering.

    Args:
        settings: Optional settings object.  Falls back to get_settings().
        team_context: Optional TeamContext (typed as object to avoid circular
            imports).  When provided, set on session.info["team_context"] so
            the do_orm_execute listener and StorageService._stamp_team_id
            can read it.

    Yields:
        An open AsyncSession.
    """
    # Lazy import to avoid circular: database -> platform.services -> storage -> database
    from ..platform.services.team_scope import register_team_scope_listener

    register_team_scope_listener()
    engine = get_async_engine(settings)
    url = (settings or get_settings()).database_url
    with _ENGINE_LOCK:
        factory = _SESSION_FACTORIES.get(url)
        if factory is None:
            factory = async_sessionmaker(
                engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )
            _SESSION_FACTORIES[url] = factory
    async with factory() as session:
        if team_context is not None:
            session.info["team_context"] = team_context
        yield session


async def init_db(
    settings: DatabaseSettings | None = None,
    schema_registry: SchemaRegistry | None = None,
) -> None:
    """Bootstrap the database schema, registering all platform and module tables.

    Fast-path: if the database URL is already in _INITIALIZED_URLS, this
    function returns immediately without touching the DB.

    Schema creation:
    1. If schema_registry is provided, calls registry.create_all_with_connection()
       inside an async connection's run_sync.
    2. Otherwise falls back to SQLModel.metadata.create_all for platform-only
       tables (storage/db_models.py).

    Args:
        settings: Optional settings object.  Falls back to get_settings().
        schema_registry: Optional SchemaRegistry populated by module
            register_tools() calls.  Pass None for platform-only init.
    """
    active_settings = settings or get_settings()
    database_url = active_settings.database_url
    if database_url in _INITIALIZED_URLS:
        return
    engine = get_async_engine(active_settings)
    async with engine.begin() as conn:
        if schema_registry is not None:
            await conn.run_sync(
                lambda sync_conn: schema_registry.create_all_with_connection(sync_conn)
            )
        else:
            await conn.run_sync(SQLModel.metadata.create_all)
    with _ENGINE_LOCK:
        _INITIALIZED_URLS.add(database_url)


async def dispose_engine(settings: DatabaseSettings | None = None) -> None:
    """Remove the cached engine for the given URL and close its connection pool.

    Removes the entry from _ASYNC_ENGINES, _INITIALIZED_URLS, and
    _SESSION_FACTORIES so the next call to get_async_engine() or init_db()
    starts fresh.  Both _ASYNC_ENGINES and _INITIALIZED_URLS mutations are
    protected by _ENGINE_LOCK (fixes CONC-01).

    Args:
        settings: Optional settings object.  Falls back to get_settings().
    """
    active_settings = settings or get_settings()
    url = active_settings.database_url
    with _ENGINE_LOCK:
        engine = _ASYNC_ENGINES.pop(url, None)
        _INITIALIZED_URLS.discard(url)  # INSIDE lock -- fixes CONC-01
        _SESSION_FACTORIES.pop(url, None)
    if engine is not None:
        await engine.dispose()


async def backup_database(
    settings: DatabaseSettings | None = None,
    destination: str | Path | None = None,
) -> Path:
    """Create a point-in-time backup of the PostgreSQL database using pg_dump.

    Generates a compressed custom-format dump.  A timestamped filename is
    created in backups/ when destination is None.

    Args:
        settings: Optional settings object.  Falls back to get_settings().
        destination: Explicit path for the backup file.  When None, a
            timestamped file is created under backups/.

    Returns:
        Path to the created backup file.

    Raises:
        UpstreamError: If pg_dump fails.
    """
    active_settings = settings or get_settings()
    url = active_settings.database_url
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    dest = Path(destination) if destination else Path(f"backups/aila-{timestamp}.dump")
    dest.parent.mkdir(parents=True, exist_ok=True)
    # pg_dump requires a libpq-compatible URL (no +asyncpg driver prefix).
    pg_url = url.replace("+asyncpg", "")
    result = await asyncio.to_thread(
        subprocess.run,
        ["pg_dump", "--format=custom", f"--file={dest}", pg_url],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise UpstreamError(f"pg_dump failed: {result.stderr}")
    return dest


@contextmanager
def session_scope(settings: DatabaseSettings | None = None):  # type: ignore[return]
    """Sync context manager yielding a SQLModel Session bound to the sync engine.

    Used exclusively by SQLite test fixtures (conftest.py) for seeding test data.
    Production code always uses async_session_scope().

    The sync engine is keyed on the DB URL in _ENGINES (mirroring the async
    engine cache in _ASYNC_ENGINES).  If no sync engine is cached for the URL,
    one is created from the current database_url setting.

    Args:
        settings: Optional settings object.  Falls back to get_settings().

    Yields:
        An open SQLModel Session.
    """
    active_settings = settings or get_settings()
    url = active_settings.database_url
    # Sync engine cannot use an async driver. The app normalizes database
    # URLs to ``postgresql+asyncpg://`` (see config.py) for async_session_scope;
    # the sync helper must strip ``+asyncpg`` back to a sync-capable driver
    # (psycopg via the bare ``postgresql://`` scheme, which SQLAlchemy
    # resolves to psycopg2 / psycopg on Python 3.11+).
    sync_url = url
    if sync_url.startswith("postgresql+asyncpg://"):
        # Rewrite to psycopg v3 (sync). psycopg2 is not a project dep.
        sync_url = "postgresql+psycopg://" + sync_url[len("postgresql+asyncpg://"):]
    elif sync_url.startswith("postgresql://"):
        sync_url = "postgresql+psycopg://" + sync_url[len("postgresql://"):]
    with _ENGINE_LOCK:
        engine = _ENGINES.get(sync_url)
        if engine is None:
            # ``check_same_thread`` is a SQLite-only kwarg. Asyncpg /
            # psycopg drivers reject unknown connect_args with a
            # ``TypeError: connect() got an unexpected keyword argument``
            # (observed on test_db runs against Postgres). Gate by URL
            # scheme so Postgres URLs get a clean connect_args={}.
            connect_args: dict[str, Any] = {}
            if sync_url.startswith(("sqlite://", "sqlite+")):
                connect_args["check_same_thread"] = False
            engine = _create_sync_engine(sync_url, connect_args=connect_args)
            _ENGINES[sync_url] = engine
        factory = _SYNC_SESSION_FACTORIES.get(url)
        if factory is None:
            factory = _sync_sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
            _SYNC_SESSION_FACTORIES[url] = factory
    with factory() as session:
        yield session
