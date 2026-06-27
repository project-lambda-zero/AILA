"""Tests for GET /health and GET /status endpoints.

Covers: HEALTH-01, HEALTH-02, FILE-04
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.platform.modules.protocol import ModuleHealthResult

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_stub_module(
    module_id: str,
    health_checks_return: dict[str, object] | None = None,
    health_checks_raises: BaseException | None = None,
    *,
    no_health_checks: bool = False,
) -> MagicMock:
    """Create a MagicMock module with controllable health_checks behavior."""
    mod = MagicMock()
    mod.module_id = module_id
    if no_health_checks:
        del mod.health_checks
    elif health_checks_raises is not None:
        mod.health_checks.side_effect = health_checks_raises
    elif health_checks_return is not None:
        mod.health_checks.return_value = health_checks_return
    else:
        mod.health_checks.return_value = {}
    return mod


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture(scope="function")
async def async_client_with_modules(test_db):
    """Async client with a stub platform whose module_registry has configurable modules."""
    from aila.api.app import create_app

    test_app = create_app()

    # Build a stub platform with module_registry
    stub_registry = MagicMock()
    stub_registry.modules = []  # Empty by default; tests inject modules

    stub_runtime = MagicMock()
    stub_runtime.module_registry = stub_registry

    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        # Expose the registry for test manipulation
        client._stub_registry = stub_registry  # type: ignore[attr-defined]
        yield client


# ─── Existing tests ──────────────────────────────────────────────────────────


async def test_health_returns_200(async_client):
    """GET /health returns 200 with status and checks fields (HEALTH-01)."""
    response = await async_client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert "status" in body
    assert "checks" in body


async def test_health_database_check_present(async_client):
    """GET /health response contains a 'database' key in checks (HEALTH-01)."""
    response = await async_client.get("/health")
    assert response.status_code == 200
    checks = response.json()["checks"]
    assert "database" in checks, f"'database' key missing from checks: {list(checks.keys())}"
    db_check = checks["database"]
    assert "status" in db_check
    assert db_check["status"] in ("up", "degraded", "down")


async def test_health_top_level_status_valid(async_client):
    """GET /health top-level status is one of healthy/degraded/unhealthy (D-15)."""
    response = await async_client.get("/health")
    assert response.status_code == 200
    status = response.json()["status"]
    assert status in ("healthy", "degraded", "unhealthy"), f"Unexpected status: {status!r}"


async def test_health_no_auth_required(async_client):
    """GET /health requires no Authorization header (public endpoint)."""
    # No Authorization header -- must NOT return 401 or 403
    response = await async_client.get("/health")
    assert response.status_code not in (401, 403), (
        f"GET /health should be public but returned {response.status_code}"
    )


async def test_status_returns_200(async_client):
    """GET /status returns 200 with version and uptime_seconds (HEALTH-02)."""
    response = await async_client.get("/status")
    assert response.status_code == 200
    body = response.json()
    assert "version" in body
    assert "uptime_seconds" in body
    assert isinstance(body["version"], str)
    assert len(body["version"]) > 0
    assert isinstance(body["uptime_seconds"], int)
    assert body["uptime_seconds"] >= 0


async def test_status_no_auth_required(async_client):
    """GET /status requires no Authorization header (public endpoint)."""
    response = await async_client.get("/status")
    assert response.status_code not in (401, 403), (
        f"GET /status should be public but returned {response.status_code}"
    )


# ─── FILE-04: Health aggregation, degradation, and exception handling ────────


async def test_health_aggregation_all_up(async_client_with_modules):
    """All module checks up + database up -> top-level status == 'healthy' (FILE-04)."""
    stub_mod = _make_stub_module(
        "testmod",
        health_checks_return={"ping": lambda: ModuleHealthResult(status="up")},
    )
    async_client_with_modules._stub_registry.modules = [stub_mod]

    response = await async_client_with_modules.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert "testmod_ping" in body["checks"]
    assert body["checks"]["testmod_ping"]["status"] == "up"


async def test_health_aggregation_degraded(async_client_with_modules):
    """One degraded check, none down -> top-level status == 'degraded' (FILE-04)."""
    stub_mod = _make_stub_module(
        "testmod",
        health_checks_return={
            "svc": lambda: ModuleHealthResult(status="degraded", message="slow"),
        },
    )
    async_client_with_modules._stub_registry.modules = [stub_mod]

    response = await async_client_with_modules.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["testmod_svc"]["status"] == "degraded"
    assert body["checks"]["testmod_svc"]["message"] == "slow"


async def test_health_aggregation_module_down_db_up(async_client_with_modules):
    """Module check down + DB up -> top-level status == 'degraded' (XCUT-08).

    DB is the critical dependency. Module-level failures degrade the platform
    but do not make it unhealthy. Only DB down produces unhealthy.
    """
    stub_mod = _make_stub_module(
        "testmod",
        health_checks_return={
            "db": lambda: ModuleHealthResult(status="down", message="connection refused"),
        },
    )
    async_client_with_modules._stub_registry.modules = [stub_mod]

    response = await async_client_with_modules.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["testmod_db"]["status"] == "down"
    assert "connection refused" in body["checks"]["testmod_db"]["message"]


async def test_health_module_health_checks_raises(async_client_with_modules):
    """Module.health_checks() raises -> '{module_id}_health' entry with status=down (FILE-04)."""
    stub_mod = _make_stub_module(
        "broken",
        health_checks_raises=RuntimeError("module broke"),
    )
    async_client_with_modules._stub_registry.modules = [stub_mod]

    response = await async_client_with_modules.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert "broken_health" in body["checks"]
    check = body["checks"]["broken_health"]
    assert check["status"] == "down"
    assert "module broke" in check["message"]


async def test_health_check_callable_raises(async_client_with_modules):
    """Individual check callable raises -> entry with status=down and error message (FILE-04)."""
    def _exploding_check():
        raise ConnectionError("socket timeout")

    stub_mod = _make_stub_module(
        "netmod",
        health_checks_return={"ssh": _exploding_check},
    )
    async_client_with_modules._stub_registry.modules = [stub_mod]

    response = await async_client_with_modules.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert "netmod_ssh" in body["checks"]
    check = body["checks"]["netmod_ssh"]
    assert check["status"] == "down"
    assert "socket timeout" in check["message"]


async def test_health_check_not_callable(async_client_with_modules):
    """Non-callable health check value -> entry with status=down (FILE-04)."""
    stub_mod = _make_stub_module(
        "badmod",
        health_checks_return={"bad": "not a function"},
    )
    async_client_with_modules._stub_registry.modules = [stub_mod]

    response = await async_client_with_modules.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert "badmod_bad" in body["checks"]
    check = body["checks"]["badmod_bad"]
    assert check["status"] == "down"
    assert check["message"] == "Health check is not callable"


async def test_health_check_latency_preserved(async_client_with_modules):
    """Check returning ModuleHealthResult with latency_ms -> latency_ms in response (FILE-04)."""
    stub_mod = _make_stub_module(
        "latmod",
        health_checks_return={
            "api": lambda: ModuleHealthResult(status="up", latency_ms=42.5),
        },
    )
    async_client_with_modules._stub_registry.modules = [stub_mod]

    response = await async_client_with_modules.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert "latmod_api" in body["checks"]
    check = body["checks"]["latmod_api"]
    assert check["status"] == "up"
    assert check["latency_ms"] == 42.5


async def test_health_platform_none(async_client):
    """Platform=None -> 200, has database check, no module checks, no 500 (FILE-04)."""
    response = await async_client.get("/health")
    assert response.status_code == 200
    body = response.json()
    # Database check always present
    assert "database" in body["checks"]
    # No module checks when platform is None
    non_db_checks = {k: v for k, v in body["checks"].items() if k != "database"}
    assert len(non_db_checks) == 0, f"Unexpected module checks with None platform: {non_db_checks}"
    # Top-level status is valid
    assert body["status"] in ("healthy", "degraded", "unhealthy")
