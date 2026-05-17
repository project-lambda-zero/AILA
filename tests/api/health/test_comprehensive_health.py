"""Tests for GET /health/comprehensive (Phase 176d).

Covers:
- admin auth gate
- happy path with mocked probes
- independent subsystem failures do not take down the batch
- overall aggregation: healthy / degraded / unhealthy
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio

from aila.api.routers.health import _aggregate_overall_status
from aila.api.schemas.comprehensive_health import SubsystemHealth

# Only async tests need the mark; sync aggregator tests set it per-function.


# ---------------------------------------------------------------------------
# Unit tests on the aggregator (no HTTP needed)
# ---------------------------------------------------------------------------


def _sh(name: str, status: str) -> SubsystemHealth:
    return SubsystemHealth(
        name=name,
        status=status,  # type: ignore[arg-type]
        last_checked_at=datetime.now(tz=UTC),
    )


def test_aggregate_all_healthy_returns_healthy():
    out = _aggregate_overall_status([_sh("a", "healthy"), _sh("b", "running")])
    assert out == "healthy"


def test_aggregate_any_unreachable_returns_unhealthy():
    out = _aggregate_overall_status([
        _sh("a", "healthy"),
        _sh("b", "unreachable"),
        _sh("c", "degraded"),
    ])
    assert out == "unhealthy"


def test_aggregate_degraded_without_unhealthy_returns_degraded():
    out = _aggregate_overall_status([
        _sh("a", "healthy"),
        _sh("b", "stale"),
        _sh("c", "rate_limited"),
    ])
    assert out == "degraded"


def test_aggregate_timed_out_is_degraded():
    out = _aggregate_overall_status([_sh("a", "timed_out")])
    assert out == "degraded"


def test_aggregate_offline_is_unhealthy():
    out = _aggregate_overall_status([_sh("a", "offline")])
    assert out == "unhealthy"


def test_aggregate_explicit_unhealthy_status_bubbles_up():
    """Phase 178: probes can now return status='unhealthy' directly
    (frozen worker). The aggregator must treat it the same as
    unreachable/offline/error."""
    out = _aggregate_overall_status([
        _sh("a", "healthy"),
        _sh("b", "unhealthy"),
    ])
    assert out == "unhealthy"


# ---------------------------------------------------------------------------
# HTTP path with mocked probes
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def mock_all_probes_healthy(monkeypatch):
    """Replace every probe with a SubsystemHealth('healthy') stub."""
    from aila.platform.services import health_probes as hp

    ts = datetime.now(tz=UTC)

    async def _ok(*args: Any, **kwargs: Any) -> SubsystemHealth:
        return SubsystemHealth(
            name="stub",
            status="healthy",
            last_checked_at=ts,
            message="stub ok",
        )

    monkeypatch.setattr(hp, "probe_redis", _ok)
    monkeypatch.setattr(hp, "probe_omniroute", _ok)
    monkeypatch.setattr(hp, "probe_arch_security", _ok)
    monkeypatch.setattr(hp, "probe_nvd", _ok)
    monkeypatch.setattr(hp, "probe_ssh_reachability", _ok)
    monkeypatch.setattr(hp, "probe_arq_worker", _ok)
    monkeypatch.setattr(hp, "probe_modules", _ok)
    return ts


@pytest.mark.asyncio
async def test_comprehensive_requires_admin_role(
    async_client, reader_token
):
    """Reader tokens are rejected with 403 (admin gate)."""
    response = await async_client.get(
        "/health/comprehensive",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 403, response.text


@pytest.mark.asyncio
async def test_comprehensive_requires_auth(async_client):
    """Missing Authorization header returns 401."""
    response = await async_client.get("/health/comprehensive")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_comprehensive_happy_path(
    async_client, admin_token, mock_all_probes_healthy
):
    """All probes healthy -> overall healthy, 7 subsystems present."""
    response = await async_client.get(
        "/health/comprehensive",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert "data" in body
    data = body["data"]
    assert data["overall_status"] == "healthy"
    assert len(data["subsystems"]) == 7
    for sub in data["subsystems"]:
        assert sub["status"] == "healthy"
        assert sub["name"] == "stub"


@pytest.mark.asyncio
async def test_comprehensive_single_probe_unreachable_degrades_whole(
    async_client, admin_token, monkeypatch
):
    """One unreachable probe -> overall unhealthy, others still report."""
    from aila.platform.services import health_probes as hp

    ts = datetime.now(tz=UTC)

    async def _ok(*args: Any, **kwargs: Any) -> SubsystemHealth:
        return SubsystemHealth(name="healthy-stub", status="healthy", last_checked_at=ts)

    async def _bad(*args: Any, **kwargs: Any) -> SubsystemHealth:
        return SubsystemHealth(
            name="redis",
            status="unreachable",
            last_checked_at=ts,
            message="connection refused",
        )

    monkeypatch.setattr(hp, "probe_redis", _bad)
    monkeypatch.setattr(hp, "probe_omniroute", _ok)
    monkeypatch.setattr(hp, "probe_arch_security", _ok)
    monkeypatch.setattr(hp, "probe_nvd", _ok)
    monkeypatch.setattr(hp, "probe_ssh_reachability", _ok)
    monkeypatch.setattr(hp, "probe_arq_worker", _ok)
    monkeypatch.setattr(hp, "probe_modules", _ok)

    response = await async_client.get(
        "/health/comprehensive",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["overall_status"] == "unhealthy"
    assert any(s["name"] == "redis" and s["status"] == "unreachable" for s in data["subsystems"])


@pytest.mark.asyncio
async def test_comprehensive_probe_exception_does_not_crash_handler(
    async_client, admin_token, monkeypatch
):
    """A raising probe is captured and converted to a SubsystemHealth(error)."""
    from aila.platform.services import health_probes as hp

    ts = datetime.now(tz=UTC)

    async def _ok(*args: Any, **kwargs: Any) -> SubsystemHealth:
        return SubsystemHealth(name="ok-stub", status="healthy", last_checked_at=ts)

    async def _raises(*args: Any, **kwargs: Any) -> SubsystemHealth:
        raise RuntimeError("boom")

    monkeypatch.setattr(hp, "probe_redis", _ok)
    monkeypatch.setattr(hp, "probe_omniroute", _raises)
    monkeypatch.setattr(hp, "probe_arch_security", _ok)
    monkeypatch.setattr(hp, "probe_nvd", _ok)
    monkeypatch.setattr(hp, "probe_ssh_reachability", _ok)
    monkeypatch.setattr(hp, "probe_arq_worker", _ok)
    monkeypatch.setattr(hp, "probe_modules", _ok)

    response = await async_client.get(
        "/health/comprehensive",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()["data"]
    # One subsystem must be error-class.
    errors = [s for s in data["subsystems"] if s["status"] == "error"]
    assert len(errors) == 1
    # Overall downgraded to unhealthy due to 'error' status.
    assert data["overall_status"] == "unhealthy"


# ---------------------------------------------------------------------------
# Phase 178 additions: worker probe surfaces queue depth + dead-letter count;
# a frozen worker (heartbeat > 60s) reports as 'unhealthy' not 'stale'.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_comprehensive_exposes_worker_queue_details(
    async_client, admin_token, monkeypatch
):
    """probe_arq_worker emits queue_depth / in_progress / dead_letter_count."""
    from aila.platform.services import health_probes as hp

    ts = datetime.now(tz=UTC)

    async def _ok(*args: Any, **kwargs: Any) -> SubsystemHealth:
        return SubsystemHealth(name="stub", status="healthy", last_checked_at=ts)

    async def _worker(*args: Any, **kwargs: Any) -> SubsystemHealth:
        return SubsystemHealth(
            name="arq_worker",
            status="running",
            last_checked_at=ts,
            message="1 worker active",
            details={
                "worker_count": 1,
                "queue_depth": 7,
                "in_progress_count": 1,
                "dead_letter_count": 2,
                "last_heartbeat_age_s": 4.0,
            },
        )

    for name in ("probe_redis", "probe_omniroute", "probe_arch_security",
                 "probe_nvd", "probe_ssh_reachability", "probe_modules"):
        monkeypatch.setattr(hp, name, _ok)
    monkeypatch.setattr(hp, "probe_arq_worker", _worker)

    response = await async_client.get(
        "/health/comprehensive",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()["data"]
    worker = next(s for s in data["subsystems"] if s["name"] == "arq_worker")
    assert worker["details"]["queue_depth"] == 7
    assert worker["details"]["in_progress_count"] == 1
    assert worker["details"]["dead_letter_count"] == 2


@pytest.mark.asyncio
async def test_comprehensive_frozen_worker_is_unhealthy(
    async_client, admin_token, monkeypatch
):
    """Stale heartbeat (>60s) -> worker probe returns 'unhealthy', overall unhealthy."""
    from aila.platform.services import health_probes as hp

    ts = datetime.now(tz=UTC)

    async def _ok(*args: Any, **kwargs: Any) -> SubsystemHealth:
        return SubsystemHealth(name="stub", status="healthy", last_checked_at=ts)

    async def _frozen(*args: Any, **kwargs: Any) -> SubsystemHealth:
        return SubsystemHealth(
            name="arq_worker",
            status="unhealthy",
            last_checked_at=ts,
            message="Worker heartbeat is 180s old -- worker is frozen",
            details={
                "worker_count": 1,
                "queue_depth": 4,
                "in_progress_count": 1,
                "dead_letter_count": 0,
                "last_heartbeat_age_s": 180.0,
            },
        )

    for name in ("probe_redis", "probe_omniroute", "probe_arch_security",
                 "probe_nvd", "probe_ssh_reachability", "probe_modules"):
        monkeypatch.setattr(hp, name, _ok)
    monkeypatch.setattr(hp, "probe_arq_worker", _frozen)

    response = await async_client.get(
        "/health/comprehensive",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["overall_status"] == "unhealthy"
    worker = next(s for s in data["subsystems"] if s["name"] == "arq_worker")
    assert worker["status"] == "unhealthy"
    assert worker["details"]["last_heartbeat_age_s"] == 180.0
