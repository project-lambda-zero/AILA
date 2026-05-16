"""Shared fixtures for AILA API tests.

Key design decisions:
- Uses httpx.AsyncClient with ASGITransport, NOT TestClient (RESEARCH Pitfall 7/9:
  TestClient hangs on SSE endpoints and deadlocks on async routes).
- Each test gets isolated data via per-test truncation of all tables.
- create_app() is called fresh per test (not the module-level `app`).
- JWT tokens are created directly using auth helpers to avoid bootstrap complexity.
- All tests run against PostgreSQL via AILA_TEST_DATABASE_URL env var (D-48/D-49).
  Zero SQLite references -- PostgreSQL handles TSVECTOR and pgvector natively.
- Session-scoped async engine is created once and shared across all tests.
  Per-test isolation is via async TRUNCATE on teardown.
"""
from __future__ import annotations

import os
from collections.abc import AsyncGenerator, Generator
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel

from aila.api.auth import generate_api_key, hash_api_key, issue_jwt_token
from aila.storage.db_models import ApiKeyRecord

# Test database URL -- read from env var, default to local PostgreSQL test DB
TEST_DB_URL: str = os.environ.get(
    "AILA_TEST_DATABASE_URL",
    "postgresql+asyncpg://postgres:admin@localhost:5432/aila_test",
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@pytest_asyncio.fixture(scope="session")
async def _session_async_engine() -> AsyncGenerator[object, None]:
    """Session-scoped async engine: create tables once, shared across all tests.

    Imports ALL model modules so SQLModel.metadata is complete including
    TSVECTOR and pgvector columns (both supported natively by PostgreSQL).
    """
    # Import all model modules to populate SQLModel.metadata
    import aila.storage.db_models  # noqa: F401
    import aila.modules.vulnerability.db_models  # noqa: F401
    import aila.modules.sbd_nfr.db_models  # noqa: F401
    import aila.modules.vr.db_models  # noqa: F401

    import aila.storage.database as _db_module

    engine = create_async_engine(TEST_DB_URL, echo=False, pool_pre_ping=True)

    # Drop and recreate all tables to pick up schema changes (e.g., new team_id columns)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
        await conn.run_sync(SQLModel.metadata.create_all)

    # Register in module-level caches for the duration of the session
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
async def test_db(_session_async_engine) -> AsyncGenerator[None, None]:
    """Function-scoped fixture: set up AILA engine caches for one test.

    Overrides AILA_DATABASE_URL to TEST_DB_URL, ensures the session engine
    is registered in AILA's caches. On teardown, truncates ALL tables to
    isolate each test from the next.

    Per D-48/D-49: all tests run against PostgreSQL. No SQLite.
    All tables including TSVECTOR and pgvector are supported natively.
    """
    import aila.storage.database as _db_module
    from aila.config import _build_settings

    # Override environment so get_settings() resolves to test DB
    old_db_url = os.environ.get("AILA_DATABASE_URL")
    os.environ["AILA_DATABASE_URL"] = TEST_DB_URL

    # Clear settings cache to pick up new AILA_DATABASE_URL
    _build_settings.cache_clear()

    engine = _session_async_engine

    # Ensure caches point to our session engine (idempotent)
    with _db_module._ENGINE_LOCK:
        _db_module._ASYNC_ENGINES[TEST_DB_URL] = engine
        _db_module._INITIALIZED_URLS.add(TEST_DB_URL)

    yield

    # Teardown: truncate ALL tables for per-test isolation
    async with engine.begin() as conn:
        for table in reversed(SQLModel.metadata.sorted_tables):
            try:
                await conn.execute(table.delete())
            except Exception:  # noqa: BLE001
                pass  # Table may not exist in this schema state

    # Restore DB URL env var and clear settings cache
    if old_db_url is None:
        os.environ.pop("AILA_DATABASE_URL", None)
    else:
        os.environ["AILA_DATABASE_URL"] = old_db_url

    _build_settings.cache_clear()



@pytest.fixture(autouse=True)
def _disable_slowapi_limiter() -> Generator[None, None, None]:
    """Disable slowapi rate limiting for the duration of every test.

    The route sweep test exercises every endpoint with a single admin
    user identity, blowing the per-endpoint quotas within seconds. With
    a single in-memory bucket shared by all admin-token tests, the
    fastest fix is to skip rate limiting entirely in the test
    process — production behaviour is verified separately by the auth
    test suite which exercises the limiter directly.
    """
    from aila.api.limiter import limiter
    was_enabled = limiter.enabled
    limiter.enabled = False
    limiter.reset()
    try:
        yield
    finally:
        limiter.enabled = was_enabled
        limiter.reset()

@pytest_asyncio.fixture(scope="function")
async def admin_key_record(test_db) -> ApiKeyRecord:
    """Create an admin ApiKeyRecord in the test DB and return it."""
    from aila.storage.database import async_session_scope

    raw_key = generate_api_key()
    record = ApiKeyRecord(
        hashed_key=hash_api_key(raw_key),
        key_prefix=raw_key[:12],
        role="admin",
        label="test-admin",
        created_by="test-fixture",
        created_at=_utc_now(),
    )
    async with async_session_scope() as session:
        session.add(record)
        await session.commit()
        await session.refresh(record)
    # Stash raw_key on the record object for fixtures that need it
    record._raw_key = raw_key  # type: ignore[attr-defined]
    return record


@pytest_asyncio.fixture(scope="function")
async def reader_key_record(test_db, admin_key_record) -> ApiKeyRecord:
    """Create a reader ApiKeyRecord in the test DB and return it."""
    from aila.storage.database import async_session_scope

    raw_key = generate_api_key()
    record = ApiKeyRecord(
        hashed_key=hash_api_key(raw_key),
        key_prefix=raw_key[:12],
        role="reader",
        label="test-reader",
        created_by=admin_key_record.id,
        created_at=_utc_now(),
    )
    async with async_session_scope() as session:
        session.add(record)
        await session.commit()
        await session.refresh(record)
    record._raw_key = raw_key  # type: ignore[attr-defined]
    return record


@pytest.fixture(scope="function")
def admin_token(admin_key_record) -> str:
    """Return a valid admin JWT Bearer token string."""
    token, _ = issue_jwt_token(admin_key_record)
    return token


@pytest.fixture(scope="function")
def reader_token(reader_key_record) -> str:
    """Return a valid reader JWT Bearer token string."""
    token, _ = issue_jwt_token(reader_key_record)
    return token


@pytest_asyncio.fixture(scope="function")
async def async_client(test_db) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client backed by the AILA FastAPI app with isolated DB.

    Uses ASGITransport -- NOT TestClient (RESEARCH Pitfall 7: TestClient
    deadlocks on SSE and async routes).

    The app is created fresh per test via create_app() so the test DB engine is
    already in the _ASYNC_ENGINES cache (injected by test_db) when requests arrive.

    ASGITransport does not trigger ASGI lifespan events, so app.state is
    initialized directly here. This avoids two problems:
    1. AILAPlatform construction fails in tests (no LLM configured).
    2. The lifespan bootstrap logic runs against the production DB (not test DB).

    app.state.platform is set to None -- health/status endpoints handle None
    gracefully; analysis endpoints (not yet tested here) will surface 503.
    app.state.start_time is set so GET /status returns a valid uptime value.
    """
    import time

    from aila.api.app import create_app

    test_app = create_app()
    # Initialize app.state so endpoints don't crash on missing attributes.
    # platform=None is handled gracefully by health and auth endpoints.
    test_app.state.platform = None
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client


# ─── Phase 53 Plan 05: Seed fixtures and operator token ──────────────────────


@pytest_asyncio.fixture(scope="function")
async def operator_key_record(test_db, admin_key_record) -> ApiKeyRecord:
    """Create an operator ApiKeyRecord in the test DB."""
    from aila.storage.database import async_session_scope

    raw_key = generate_api_key()
    record = ApiKeyRecord(
        hashed_key=hash_api_key(raw_key),
        key_prefix=raw_key[:12],
        role="operator",
        label="test-operator",
        created_by=admin_key_record.id,
        created_at=_utc_now(),
    )
    async with async_session_scope() as session:
        session.add(record)
        await session.commit()
        await session.refresh(record)
    record._raw_key = raw_key  # type: ignore[attr-defined]
    return record


@pytest.fixture(scope="function")
def operator_token(operator_key_record) -> str:
    """Return a valid operator JWT Bearer token string."""
    token, _ = issue_jwt_token(operator_key_record)
    return token


@pytest_asyncio.fixture(scope="function")
async def seeded_run(test_db):
    """Seed one completed vulnerability WorkflowRunRecord."""
    from aila.platform.contracts._common import utc_now
    from aila.storage.database import async_session_scope
    from aila.storage.db_models import WorkflowRunRecord

    record = WorkflowRunRecord(
        id="run-test-001",
        query_text="scan web01 for vulnerabilities",
        action_id="vulnerability.analyze",
        module_id="vulnerability",
        status="completed",
        route_json='{"target": "web01"}',
        created_at=utc_now(),
        completed_at=utc_now(),
    )
    async with async_session_scope() as session:
        session.add(record)
        await session.commit()
        await session.refresh(record)
    return record


@pytest_asyncio.fixture(scope="function")
async def seeded_audit_events(test_db, seeded_run):
    """Seed three AuditEventRecord rows with different stages."""
    from aila.platform.contracts._common import utc_now
    from aila.storage.database import async_session_scope
    from aila.storage.db_models import AuditEventRecord

    records = [
        AuditEventRecord(
            run_id=seeded_run.id,
            stage="ssh",
            action="connect",
            status="completed",
            target="web01",
            user_id="system",
            details_json='{"host": "web01"}',
            created_at=utc_now(),
        ),
        AuditEventRecord(
            run_id=seeded_run.id,
            stage="scan",
            action="inventory",
            status="completed",
            target="web01",
            user_id="system",
            details_json='{"packages": 42}',
            created_at=utc_now(),
        ),
        AuditEventRecord(
            run_id=seeded_run.id,
            stage="report",
            action="persist",
            status="completed",
            target="fleet",
            user_id="system",
            details_json="{}",
            created_at=utc_now(),
        ),
    ]
    async with async_session_scope() as session:
        for r in records:
            session.add(r)
        await session.commit()
    return records


@pytest_asyncio.fixture(scope="function")
async def seeded_config_entry(test_db):
    """Seed one ConfigEntryRecord for vulnerability namespace."""
    from aila.platform.contracts._common import utc_now
    from aila.storage.database import async_session_scope
    from aila.storage.db_models import ConfigEntryRecord

    record = ConfigEntryRecord(
        namespace="vulnerability",
        key="max_cves",
        value="500",
        value_type="int",
        updated_at=utc_now(),
    )
    async with async_session_scope() as session:
        session.add(record)
        await session.commit()
        await session.refresh(record)
    return record


@pytest_asyncio.fixture(scope="function")
async def seeded_system(test_db):
    """Seed one ManagedSystemRecord (web01)."""
    from aila.platform.contracts._common import utc_now
    from aila.storage.database import async_session_scope
    from aila.storage.db_models import ManagedSystemRecord

    record = ManagedSystemRecord(
        name="web01",
        host="192.168.1.100",
        username="admin",
        port=22,
        distro="ubuntu",
        description="Test web server",
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    async with async_session_scope() as session:
        session.add(record)
        await session.commit()
        await session.refresh(record)
    return record


@pytest_asyncio.fixture(scope="function")
async def seeded_findings(test_db, seeded_system):
    """Seed three LatestFindingRecord rows with different criticality levels.

    Note: LatestFindingRecord uses 'criticality' (not 'severity') and
    'package_name' (not 'package'). There is no 'kev' or 'run_id' field.
    nvd_url is required (not nullable).
    """
    try:
        from aila.modules.vulnerability.db_models import LatestFindingRecord
    except ImportError:
        pytest.skip("LatestFindingRecord not available in test environment")
        return []

    from aila.platform.contracts._common import utc_now
    from aila.storage.database import async_session_scope

    records = [
        LatestFindingRecord(
            system_id=seeded_system.id,
            system_name=seeded_system.name,
            host=seeded_system.host,
            cve_id="CVE-2023-0001",
            package_name="openssl",
            criticality="CRITICAL",
            score=9.5,
            nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2023-0001",
            last_scanned_at=utc_now(),
            created_at=utc_now(),
        ),
        LatestFindingRecord(
            system_id=seeded_system.id,
            system_name=seeded_system.name,
            host=seeded_system.host,
            cve_id="CVE-2023-0002",
            package_name="libssl",
            criticality="HIGH",
            score=7.2,
            nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2023-0002",
            last_scanned_at=utc_now(),
            created_at=utc_now(),
        ),
        LatestFindingRecord(
            system_id=seeded_system.id,
            system_name=seeded_system.name,
            host=seeded_system.host,
            cve_id="CVE-2023-0003",
            package_name="curl",
            criticality="MEDIUM",
            score=4.5,
            nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2023-0003",
            last_scanned_at=utc_now(),
            created_at=utc_now(),
        ),
    ]
    async with async_session_scope() as session:
        for r in records:
            session.add(r)
        await session.commit()
        for r in records:
            await session.refresh(r)
    return records


@pytest_asyncio.fixture(scope="function")
async def async_client_with_registries(test_db) -> AsyncGenerator[AsyncClient, None]:
    """Async client with a stub platform that has runtime.config_registry and runtime.tool_registry.

    Use this fixture for tests that call endpoints requiring the platform
    (GET /config PUT, GET /tools, POST /tools/{key}).

    The deps.py functions check platform.runtime.config_registry and
    platform.runtime.tool_registry -- so the stub must expose a 'runtime'
    attribute with those nested attributes.
    """
    import time

    from aila.api.app import create_app
    from aila.platform.runtime.tools import ToolRegistry
    from aila.storage.registry import ConfigRegistry

    # Build real registry instances (empty but functional)
    config_registry = ConfigRegistry()
    tool_registry = ToolRegistry()

    # Stub runtime with the two registry attributes deps.py checks
    stub_runtime = MagicMock()
    stub_runtime.config_registry = config_registry
    stub_runtime.tool_registry = tool_registry

    # Stub platform with stub_runtime
    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app = create_app()
    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client
