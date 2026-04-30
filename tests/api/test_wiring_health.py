"""Wiring verification: health check state reflection (WIRE-10).

Tests prove the health endpoint aggregates check results correctly:
- healthy when all checks are up
- unhealthy when any check is down
- degraded for partial failures (non-up, non-down states)

Also verifies /status returns version and uptime.

Endpoints under test:
  GET /health  -- aggregated health status (public, no auth)
  GET /status  -- version + uptime (public, no auth)
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from aila.api.schemas.health import HealthCheckResult

pytestmark = pytest.mark.anyio


async def test_health_returns_healthy_with_good_db(
    async_client: AsyncClient,
) -> None:
    """GET /health returns healthy status when DB is responsive.

    The test DB is a real SQLite database -- SELECT 1 succeeds.
    With platform=None, module health checks are skipped (AttributeError caught).
    Result: database=up, no module checks, top status=healthy.
    """
    resp = await async_client.get("/health")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "healthy"
    assert "database" in body["checks"]
    assert body["checks"]["database"]["status"] == "up"
    # Latency should be a positive number (real DB query)
    assert body["checks"]["database"]["latency_ms"] is not None
    assert body["checks"]["database"]["latency_ms"] >= 0


async def test_health_returns_unhealthy_when_db_down(
    async_client: AsyncClient,
) -> None:
    """GET /health returns unhealthy when _check_database reports down.

    Uses unittest.mock.patch to simulate DB failure. This tests the health
    endpoint's AGGREGATION wiring, not the DB check itself (which is verified
    by the healthy test above using a real DB).
    """
    mock_result = HealthCheckResult(status="down", message="simulated DB failure")

    with patch("aila.api.routers.health._check_database", return_value=mock_result):
        resp = await async_client.get("/health")

    assert resp.status_code == 200, resp.text  # D-15: never 503
    body = resp.json()
    assert body["status"] == "unhealthy"
    assert body["checks"]["database"]["status"] == "down"
    assert "simulated DB failure" in body["checks"]["database"]["message"]


async def test_health_degraded_when_redis_down(
    async_client: AsyncClient,
) -> None:
    """GET /health returns degraded when a module check has non-up/non-down status.

    Aggregation logic: all up -> healthy, any down -> unhealthy, else -> degraded.
    With DB=up and a module check returning status='degraded', top status is 'degraded'.
    """
    mock_module_checks = {
        "redis_cache": HealthCheckResult(status="degraded", message="Redis unreachable"),
    }

    with patch(
        "aila.api.routers.health._collect_module_health_checks",
        new_callable=AsyncMock,
        return_value=mock_module_checks,
    ):
        resp = await async_client.get("/health")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    # DB is up (real), module check is degraded -> top status = degraded
    assert body["status"] == "degraded"
    assert body["checks"]["database"]["status"] == "up"
    assert body["checks"]["redis_cache"]["status"] == "degraded"


async def test_health_degraded_when_module_check_down(
    async_client: AsyncClient,
) -> None:
    """GET /health returns degraded when a non-critical module check is down.

    With DB=up and a module check returning status='down', top status is 'degraded'
    (only DB down -> unhealthy per Phase 98 health aggregation fix).
    """
    mock_module_checks = {
        "vulnerability_llm": HealthCheckResult(status="down", message="LLM provider unreachable"),
    }

    with patch(
        "aila.api.routers.health._collect_module_health_checks",
        new_callable=AsyncMock,
        return_value=mock_module_checks,
    ):
        resp = await async_client.get("/health")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["checks"]["database"]["status"] == "up"
    assert body["checks"]["vulnerability_llm"]["status"] == "down"


async def test_status_returns_version_and_uptime(
    async_client: AsyncClient,
) -> None:
    """GET /status returns version (string) and uptime_seconds (int >= 0).

    Public endpoint, no auth required. Version comes from importlib.metadata,
    uptime from app.state.start_time (set by the async_client fixture).
    """
    resp = await async_client.get("/status")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "version" in body
    assert isinstance(body["version"], str)
    assert len(body["version"]) > 0
    assert "uptime_seconds" in body
    assert isinstance(body["uptime_seconds"], int)
    assert body["uptime_seconds"] >= 0
