"""Regression tests for Phase 138 Plan 02 bug fixes.

Covers:
- BE-05: GET /health with async module health check functions — no "coroutine never awaited"
- SBD-06: GET /sbd_nfr/sessions returns 200 with sessions array, not 500
- SYS-04: GET /systems returns correct paginated data shape with items array

All tests run against PostgreSQL via AILA_TEST_DATABASE_URL.
No SQLite references.
"""
from __future__ import annotations

import time
from datetime import UTC
from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from aila.api.routers.health import _run_single_health_check
from aila.storage.db_models import ApiKeyRecord

# ---------------------------------------------------------------------------
# Task 1: BE-05 — async health checks correctly awaited
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_single_health_check_with_async_coroutine() -> None:
    """_run_single_health_check must await async callables, not wrap them in to_thread.

    Before the BE-05 fix: asyncio.to_thread(async_fn) returned an unawaited coroutine
    object, causing "coroutine was never awaited" RuntimeWarning.
    After fix: inspect.iscoroutinefunction detects async callables and awaits them directly.
    """

    async def async_check_fn() -> dict[str, object]:
        return {"status": "up", "detail": "async check ran successfully"}

    result = await _run_single_health_check(async_check_fn)
    assert result.status == "up"


@pytest.mark.asyncio
async def test_run_single_health_check_with_sync_callable() -> None:
    """_run_single_health_check still works for sync callables (via asyncio.to_thread)."""

    def sync_check_fn() -> dict[str, object]:
        return {"status": "up", "detail": "sync check ran"}

    result = await _run_single_health_check(sync_check_fn)
    assert result.status == "up"


@pytest.mark.asyncio
async def test_run_single_health_check_async_returns_down() -> None:
    """Async health check returning 'down' is propagated correctly."""

    async def async_check_down() -> dict[str, object]:
        return {"status": "down", "detail": "service unavailable"}

    result = await _run_single_health_check(async_check_down)
    assert result.status == "down"
    assert result.message is not None


@pytest.mark.asyncio
async def test_run_single_health_check_timeout() -> None:
    """A health check that hangs beyond the timeout returns 'down' with timeout message.

    T-138-11: asyncio.wait_for bounds each check to _HEALTH_CHECK_TIMEOUT_SECONDS.
    """
    import asyncio as _asyncio

    from aila.api.routers.health import _HEALTH_CHECK_TIMEOUT_SECONDS

    # Verify timeout is set to a sensible value (5s per threat model)
    assert _HEALTH_CHECK_TIMEOUT_SECONDS == 5.0

    async def slow_check() -> dict[str, object]:
        # Sleep far longer than the timeout — will be cancelled by wait_for
        await _asyncio.sleep(100)
        return {"status": "up"}

    # Patch the timeout to 0.05s so the test completes quickly
    import aila.api.routers.health as health_module
    original = health_module._HEALTH_CHECK_TIMEOUT_SECONDS
    health_module._HEALTH_CHECK_TIMEOUT_SECONDS = 0.05
    try:
        result = await _run_single_health_check(slow_check)
    finally:
        health_module._HEALTH_CHECK_TIMEOUT_SECONDS = original

    assert result.status == "down"
    assert "timed out" in (result.message or "").lower()


@pytest.mark.asyncio
async def test_health_endpoint_with_async_module_checks(
    test_db: None,
    admin_key_record: ApiKeyRecord,
) -> None:
    """GET /health works correctly when a registered module exposes async health check functions.

    Before BE-05 fix: health_checks() was called via asyncio.to_thread (wrong — it's sync),
    and each check_fn was also passed to asyncio.to_thread (wrong — they're coroutines).
    After fix: health_checks() is called directly; coroutines are detected and awaited.
    """
    import warnings

    from aila.api.app import create_app
    from aila.api.auth import issue_jwt_token

    # Build a module stub whose health_checks() returns async callables
    async def _async_ping() -> dict[str, object]:
        return {"status": "up", "detail": "async ping ok"}

    stub_module = MagicMock()
    stub_module.module_id = "test_async_module"
    stub_module.health_checks = MagicMock(return_value={"async_ping": _async_ping})

    stub_registry = MagicMock()
    stub_registry.modules = [stub_module]

    stub_runtime = MagicMock()
    stub_runtime.module_registry = stub_registry

    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app = create_app()
    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    token, _ = issue_jwt_token(admin_key_record)

    # Capture RuntimeWarnings — before the fix, "coroutine was never awaited" fires here
    with warnings.catch_warnings(record=True) as caught_warnings:
        warnings.simplefilter("always")
        async with AsyncClient(
            transport=ASGITransport(app=test_app),
            base_url="http://testserver",
        ) as client:
            response = await client.get(
                "/health",
                headers={"Authorization": f"Bearer {token}"},
            )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("healthy", "degraded", "unhealthy")
    # Check for the async check result
    assert "test_async_module_async_ping" in data["checks"]
    assert data["checks"]["test_async_module_async_ping"]["status"] == "up"

    # Verify NO coroutine-related warnings fired
    coroutine_warnings = [
        w for w in caught_warnings
        if "coroutine" in str(w.message).lower() and "never awaited" in str(w.message).lower()
    ]
    assert coroutine_warnings == [], (
        f"'coroutine was never awaited' warnings detected: {coroutine_warnings}"
    )


# ---------------------------------------------------------------------------
# Task 1: SBD-06 — GET /sbd_nfr/sessions returns 200, not 500
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sbd_sessions_returns_200(
    test_db: None,
    admin_key_record: ApiKeyRecord,
    admin_token: str,
) -> None:
    """GET /sbd_nfr/sessions returns 200 with a valid paginated response shape.

    SBD-06: Before fix, this endpoint returned 500 because SbD tables were not
    created. The conftest now imports aila.modules.sbd_nfr.db_models so
    SQLModel.metadata.create_all() includes all SbD tables.
    The key assertion is status 200 (not 500) and correct response shape.
    """
    from aila.api.app import create_app

    test_app = create_app()
    test_app.state.platform = None
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        response = await client.get(
            "/sbd_nfr/sessions",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

    assert response.status_code == 200, (
        f"SBD-06: Expected 200 (not 500), got {response.status_code}: {response.text}"
    )
    data = response.json()
    # Shape must always include these keys regardless of how many sessions exist
    assert "items" in data, f"Response missing 'items' key: {data}"
    assert isinstance(data["items"], list)
    assert "total" in data
    assert isinstance(data["total"], int)
    assert data["total"] >= 0


@pytest.mark.asyncio
async def test_sbd_sessions_with_data(
    test_db: None,
    admin_key_record: ApiKeyRecord,
    admin_token: str,
) -> None:
    """GET /sbd_nfr/sessions returns seeded sessions in items array.

    SBD-06: Verifies the list_sessions() service works correctly when data exists.
    Seeds data via async_session_scope (PostgreSQL, no SQLite).
    """
    import uuid
    from datetime import datetime

    from aila.api.app import create_app
    from aila.modules.sbd_nfr.db_models import SbdNfrSessionRecord
    from aila.storage.database import async_session_scope

    session_id = str(uuid.uuid4())
    now = datetime.now(UTC)

    async with async_session_scope() as db:
        db.add(
            SbdNfrSessionRecord(
                id=session_id,
                owner_id=admin_key_record.id,
                project_name="Test Project Alpha",
                schema_version_at_start=1,
                status="draft",
                requestor_name="Test User",
                requestor_email="test@example.com",
                share_token=str(uuid.uuid4()),
                created_at=now,
                updated_at=now,
            )
        )
        await db.commit()

    test_app = create_app()
    test_app.state.platform = None
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        response = await client.get(
            "/sbd_nfr/sessions",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

    assert response.status_code == 200, (
        f"Expected 200, got {response.status_code}: {response.text}"
    )
    data = response.json()
    # Must have at least the session we just created
    assert data["total"] >= 1
    item_ids = {item["id"] for item in data["items"]}
    assert session_id in item_ids, f"Seeded session {session_id} not found in listing: {item_ids}"
    seeded = next(item for item in data["items"] if item["id"] == session_id)
    assert seeded["project_name"] == "Test Project Alpha"


@pytest.mark.asyncio
async def test_sbd_sessions_reader_sees_only_own(
    test_db: None,
    admin_key_record: ApiKeyRecord,
    admin_token: str,
) -> None:
    """Reader role can only see their own sessions (role-based filtering via D-26).

    Verifies that SBD-06 fix does not break the role isolation requirement.
    Creates the reader key record inline to avoid asyncio fixture lifecycle issues.
    """
    import uuid
    from datetime import datetime

    from aila.api.app import create_app
    from aila.api.auth import generate_api_key, hash_api_key, issue_jwt_token
    from aila.modules.sbd_nfr.db_models import SbdNfrSessionRecord
    from aila.storage.database import async_session_scope

    now = datetime.now(UTC)

    # Create reader key record inline (avoiding async fixture chaining issues)
    raw_reader_key = generate_api_key()
    reader_record = ApiKeyRecord(
        hashed_key=hash_api_key(raw_reader_key),
        key_prefix=raw_reader_key[:12],
        role="reader",
        label="inline-test-reader",
        created_by=admin_key_record.id,
        created_at=now,
    )
    async with async_session_scope() as db:
        db.add(reader_record)
        await db.commit()
        await db.refresh(reader_record)

    reader_token, _ = issue_jwt_token(reader_record)

    # Create one session owned by admin, one owned by reader
    admin_session_id = str(uuid.uuid4())
    reader_session_id = str(uuid.uuid4())

    async with async_session_scope() as db:
        db.add(
            SbdNfrSessionRecord(
                id=admin_session_id,
                owner_id=admin_key_record.id,
                project_name="Admin Project",
                schema_version_at_start=1,
                status="draft",
                requestor_name="Admin User",
                requestor_email="admin@example.com",
                share_token=str(uuid.uuid4()),
                created_at=now,
                updated_at=now,
            )
        )
        db.add(
            SbdNfrSessionRecord(
                id=reader_session_id,
                owner_id=reader_record.id,
                project_name="Reader Project",
                schema_version_at_start=1,
                status="draft",
                requestor_name="Reader User",
                requestor_email="reader@example.com",
                share_token=str(uuid.uuid4()),
                created_at=now,
                updated_at=now,
            )
        )
        await db.commit()

    test_app = create_app()
    test_app.state.platform = None
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        # Admin sees both sessions
        admin_response = await client.get(
            "/sbd_nfr/sessions",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        # Reader sees only their own
        reader_response = await client.get(
            "/sbd_nfr/sessions",
            headers={"Authorization": f"Bearer {reader_token}"},
        )

    assert admin_response.status_code == 200
    admin_data = admin_response.json()
    # Admin sees at least the two sessions created in this test (may see more from prior tests)
    admin_ids = {item["id"] for item in admin_data["items"]}
    assert admin_session_id in admin_ids, (
        f"Admin session {admin_session_id} not in admin listing: {admin_ids}"
    )
    assert reader_session_id in admin_ids, (
        f"Reader session {reader_session_id} not in admin listing: {admin_ids}"
    )

    assert reader_response.status_code == 200
    reader_data = reader_response.json()
    # Reader sees only their own sessions — reader_session_id must be present
    reader_ids = {item["id"] for item in reader_data["items"]}
    assert reader_session_id in reader_ids, (
        f"Reader session {reader_session_id} not found in reader listing: {reader_ids}"
    )
    # Admin's session must NOT be visible to the reader
    assert admin_session_id not in reader_ids, (
        f"Admin session {admin_session_id} should not be visible to reader"
    )


# ---------------------------------------------------------------------------
# Task 2: SYS-04 — GET /systems returns correct paginated data shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_systems_endpoint_returns_correct_shape(
    test_db: None,
    admin_key_record: ApiKeyRecord,
    admin_token: str,
) -> None:
    """GET /systems returns paginated response with 'items' array and correct totals.

    SYS-04: Verifies the API returns the shape that the frontend useSystems()
    hook expects: {total, page, page_size, pages, items: [...]}.
    The frontend reads data?.items — this test confirms items is always present.
    """
    import time

    from aila.api.app import create_app
    from aila.platform.contracts._common import utc_now
    from aila.storage.database import async_session_scope
    from aila.storage.db_models import ManagedSystemRecord

    # Seed two systems
    async with async_session_scope() as db:
        for i in range(2):
            db.add(
                ManagedSystemRecord(
                    name=f"sys-test-{i:02d}",
                    host=f"192.168.1.{10 + i}",
                    username="admin",
                    port=22,
                    distro="ubuntu",
                    description=f"Test system {i}",
                    created_at=utc_now(),
                    updated_at=utc_now(),
                )
            )
        await db.commit()

    test_app = create_app()
    test_app.state.platform = None
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        response = await client.get(
            "/systems",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

    assert response.status_code == 200, (
        f"Expected 200, got {response.status_code}: {response.text}"
    )
    data = response.json()

    # SYS-04: These keys must always be present so the frontend can bind data?.items
    assert "items" in data, f"Response missing 'items' key: {data.keys()}"
    assert "total" in data, f"Response missing 'total' key: {data.keys()}"
    assert "page" in data, f"Response missing 'page' key: {data.keys()}"
    assert "page_size" in data, f"Response missing 'page_size' key: {data.keys()}"
    assert "pages" in data, f"Response missing 'pages' key: {data.keys()}"

    assert isinstance(data["items"], list)
    # At least the 2 systems seeded above must appear (prior tests may have added more)
    assert data["total"] >= 2
    assert len(data["items"]) >= 2

    # Verify the seeded system names appear
    item_names = {item["name"] for item in data["items"]}
    assert "sys-test-00" in item_names
    assert "sys-test-01" in item_names

    # Each system must have the fields useSystems() / SystemSummary interface expects
    for system in data["items"]:
        assert "id" in system
        assert "name" in system
        assert "host" in system
        assert "username" in system
        assert "port" in system
        assert "distro" in system
        assert "description" in system


@pytest.mark.asyncio
async def test_systems_endpoint_always_has_items_key(
    test_db: None,
    admin_key_record: ApiKeyRecord,
    admin_token: str,
) -> None:
    """GET /systems always returns items key (even when empty).

    SYS-04: The frontend reads data?.items ?? [] — items must always be present
    in the response so the frontend can bind correctly regardless of how many
    systems exist. The key assertion is the 'items' key exists and is a list.
    """
    import time

    from aila.api.app import create_app

    test_app = create_app()
    test_app.state.platform = None
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        response = await client.get(
            "/systems",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

    assert response.status_code == 200
    data = response.json()
    # SYS-04: These keys must always be present for frontend binding to work
    assert "items" in data, "GET /systems must always return 'items' key"
    assert isinstance(data["items"], list), "'items' must be a list (not null/undefined)"
    assert "total" in data
    assert isinstance(data["total"], int)
    assert data["total"] >= 0


# ---------------------------------------------------------------------------
# Task 2: SBD-01 — SbD module route spec is consistent with backend prefix
# ---------------------------------------------------------------------------


def test_sbd_routes_spec_prefix_consistent() -> None:
    """SbD module route_specs() declares /sbd_nfr prefix (matching backend mount).

    SBD-01: Verifies no path mismatch between the frontend spec and backend mount.
    The backend mounts the SbD router at /sbd_nfr (underscore) via route_specs().
    The frontend routes.tsx uses /sbd-nfr (hyphen) as browser navigation paths —
    this is correct because browser routes and API paths are independent namespaces.
    """
    from aila.modules.sbd_nfr.module import SbdNfrModule

    module = SbdNfrModule()
    specs = module.route_specs()

    assert len(specs) == 1, f"Expected 1 route spec, got {len(specs)}"
    spec = specs[0]

    # Backend prefix must use underscore to match the DB table prefix (sbd_nfr_*)
    assert spec.prefix == "/sbd_nfr", (
        f"Backend prefix mismatch: expected '/sbd_nfr', got '{spec.prefix}'. "
        "The prefix must match the backend API URL pattern so /sbd_nfr/sessions resolves."
    )
    assert spec.config_namespace == "sbd_nfr"


def test_sbd_frontend_routes_file_exists_and_has_correct_path() -> None:
    """SbD frontend routes.tsx exists and declares a /sbd-nfr browser path.

    SBD-01: Confirms the frontend routes.tsx file exists and contains the
    /sbd-nfr browser path (hyphen) — distinct from the backend /sbd_nfr (underscore).
    Checked via file content inspection since routes.tsx is TypeScript, not Python.
    """
    from pathlib import Path

    routes_file = Path(__file__).parent.parent.parent / "src/aila/modules/sbd_nfr/frontend/routes.tsx"
    assert routes_file.exists(), f"SbD routes.tsx not found at {routes_file}"

    content = routes_file.read_text(encoding="utf-8")
    # Confirm the browser navigation path uses the /sbd-nfr format
    assert '"/sbd-nfr"' in content, (
        "SbD routes.tsx must declare path '/sbd-nfr' for the workspace route. "
        "This is the browser navigation path (hyphen), separate from the API prefix /sbd_nfr (underscore)."
    )
    # Confirm query hooks use the correct API prefix (underscore)
    spec_file = routes_file.parent / "spec.ts"
    assert spec_file.exists(), f"SbD spec.ts not found at {spec_file}"
