"""Regression tests for Phase 138 Plan 02 bug fixes.

Covers:
- BE-05: GET /health with async module health check functions — no "coroutine never awaited"
- SYS-04: GET /systems returns correct paginated data shape with items array

All tests run against PostgreSQL via AILA_TEST_DATABASE_URL.
No SQLite references.
"""
from __future__ import annotations

import time
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
