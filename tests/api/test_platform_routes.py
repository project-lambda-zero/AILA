"""Tests for platform-owned read-only API routes (Phase 53).

Tests organized by module boundary per D-22/D-23:
- test_platform_routes.py: audit, config, systems, tools routes
- test_vulnerability_routes.py: vulnerability module routes

All tests use real DB seeds (no mocks for DB queries).
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient


# ─── Audit Tests ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_audit_events_requires_auth(async_client: AsyncClient) -> None:
    """Unauthenticated request to /audit/events returns 401."""
    response = await async_client.get("/audit/events")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_audit_events_empty(async_client: AsyncClient, test_db, admin_token: str) -> None:
    """GET /audit/events returns 200 with empty items when no audit events seeded."""
    response = await async_client.get(
        "/audit/events",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_audit_events_returns_seeded_rows(
    async_client: AsyncClient,
    admin_token: str,
    seeded_audit_events,
) -> None:
    """GET /audit/events returns all seeded audit events."""
    response = await async_client.get(
        "/audit/events",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3


@pytest.mark.asyncio
async def test_audit_events_filter_by_stage(
    async_client: AsyncClient,
    admin_token: str,
    seeded_audit_events,
) -> None:
    """GET /audit/events?stage=ssh returns only ssh-stage events."""
    response = await async_client.get(
        "/audit/events?stage=ssh",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["stage"] == "ssh"


@pytest.mark.asyncio
async def test_audit_events_comma_or(
    async_client: AsyncClient,
    admin_token: str,
    seeded_audit_events,
) -> None:
    """GET /audit/events?stage=ssh,scan returns events from both stages (comma-OR)."""
    response = await async_client.get(
        "/audit/events?stage=ssh%2Cscan",  # comma URL-encoded
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    returned_stages = {item["stage"] for item in data["items"]}
    assert returned_stages == {"ssh", "scan"}


@pytest.mark.asyncio
async def test_audit_run_events(
    async_client: AsyncClient,
    admin_token: str,
    seeded_audit_events,
    seeded_run,
) -> None:
    """GET /audit/events/{run_id} returns all events for that run."""
    response = await async_client.get(
        f"/audit/events/{seeded_run.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    for item in data["items"]:
        assert item["run_id"] == seeded_run.id


# ─── Config Tests ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_config_list_requires_auth(async_client: AsyncClient, test_db) -> None:
    """GET /config without token returns 401."""
    response = await async_client.get("/config")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_config_list_returns_seeded(
    async_client: AsyncClient,
    admin_token: str,
    seeded_config_entry,
) -> None:
    """GET /config returns seeded config entry (queries DB directly, no platform needed)."""
    response = await async_client.get(
        "/config",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    keys = [item["key"] for item in data["items"]]
    assert "max_cves" in keys


@pytest.mark.asyncio
async def test_config_put_requires_admin(
    async_client: AsyncClient,
    reader_token: str,
    seeded_config_entry,
) -> None:
    """PUT /config/{ns}/{key} with reader token returns 403."""
    response = await async_client.put(
        "/config/vulnerability/max_cves",
        json={"value": "1000"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_config_put_with_admin_503_without_platform(
    async_client: AsyncClient,
    admin_token: str,
    seeded_config_entry,
) -> None:
    """PUT /config/{ns}/{key} with admin token returns 503 when platform is None.

    The PUT path calls get_config_registry(request) which raises 503 when
    app.state.platform is None (async_client fixture sets platform=None).
    Auth check (admin required) passes first, then registry lookup fails.
    """
    response = await async_client.put(
        "/config/vulnerability/max_cves",
        json={"value": "1000"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    # 503 because platform=None; role check (admin) passes before registry access
    assert response.status_code == 503


# ─── Systems Tests ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_systems_list(
    async_client: AsyncClient,
    admin_token: str,
    seeded_system,
) -> None:
    """GET /systems returns paginated list including seeded system."""
    response = await async_client.get(
        "/systems",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["name"] == "web01"


@pytest.mark.asyncio
async def test_system_detail(
    async_client: AsyncClient,
    admin_token: str,
    seeded_system,
) -> None:
    """GET /systems/{id} returns SystemDetailResponse with module_summaries."""
    response = await async_client.get(
        f"/systems/{seeded_system.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == seeded_system.id
    assert data["name"] == "web01"
    assert "module_summaries" in data
    assert isinstance(data["module_summaries"], dict)


@pytest.mark.asyncio
async def test_system_not_found(async_client: AsyncClient, admin_token: str, test_db) -> None:
    """GET /systems/99999 returns 404."""
    response = await async_client.get(
        "/systems/99999",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_system_scans(
    async_client: AsyncClient,
    admin_token: str,
    seeded_system,
    seeded_run,
) -> None:
    """GET /systems/{id}/scans returns paginated scan history."""
    response = await async_client.get(
        f"/systems/{seeded_system.id}/scans",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "total" in data


@pytest.mark.asyncio
async def test_system_findings(
    async_client: AsyncClient,
    admin_token: str,
    seeded_system,
) -> None:
    """GET /systems/{id}/findings returns paginated findings response."""
    response = await async_client.get(
        f"/systems/{seeded_system.id}/findings",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data


# ─── Tools Tests ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tools_list_returns_503_without_platform(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """GET /tools returns 503 when platform is None (no tool registry)."""
    response = await async_client.get(
        "/tools",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    # Platform is None in async_client — 503 is correct behavior
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_tools_invoke_requires_operator(
    async_client: AsyncClient,
    reader_token: str,
    test_db,
) -> None:
    """POST /tools/{key} with reader token returns 403."""
    response = await async_client.post(
        "/tools/some.tool",
        json={"kwargs": {}},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_tools_list_with_registries(
    async_client_with_registries: AsyncClient,
    admin_key_record,
    test_db,
) -> None:
    """GET /tools returns 200 empty list when platform has a real (empty) tool registry."""
    from aila.api.auth import issue_jwt_token

    token, _ = issue_jwt_token(admin_key_record)
    response = await async_client_with_registries.get(
        "/tools",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)
