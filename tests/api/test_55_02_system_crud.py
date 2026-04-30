"""Tests for Phase 55 Plan 02: System CRUD (POST/PUT/DELETE /systems).

Covers API-06: register/update/delete systems via mutation endpoints.
Tests RBAC (operator required, D-07), 409 on duplicate name (D-08),
404 for missing systems, and 204 on successful delete.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_system_operator(async_client: AsyncClient, operator_token: str) -> None:
    """POST /systems with operator token creates system, returns 201."""
    response = await async_client.post(
        "/systems",
        json={"name": "test-host", "host": "10.0.0.1"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "test-host"
    assert data["host"] == "10.0.0.1"
    assert "id" in data


@pytest.mark.asyncio
async def test_create_system_reader_forbidden(async_client: AsyncClient, reader_token: str) -> None:
    """POST /systems with reader token returns 403."""
    response = await async_client.post(
        "/systems",
        json={"name": "test-host", "host": "10.0.0.1"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_create_system_duplicate_name(
    async_client: AsyncClient, operator_token: str, seeded_system
) -> None:
    """POST /systems with duplicate name returns 409 Conflict (D-08)."""
    response = await async_client.post(
        "/systems",
        json={"name": seeded_system.name, "host": "10.0.0.99"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_update_system_operator(
    async_client: AsyncClient, operator_token: str, seeded_system
) -> None:
    """PUT /systems/{id} with operator token updates fields, returns 200."""
    response = await async_client.put(
        f"/systems/{seeded_system.id}",
        json={"description": "Updated description"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 200
    assert response.json()["description"] == "Updated description"


@pytest.mark.asyncio
async def test_update_system_not_found(async_client: AsyncClient, operator_token: str) -> None:
    """PUT /systems/{non_existent_id} returns 404."""
    response = await async_client.put(
        "/systems/99999",
        json={"description": "x"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_delete_system_operator(
    async_client: AsyncClient, operator_token: str, seeded_system
) -> None:
    """DELETE /systems/{id} with operator token returns 204."""
    response = await async_client.delete(
        f"/systems/{seeded_system.id}",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 204


@pytest.mark.asyncio
async def test_delete_system_reader_forbidden(
    async_client: AsyncClient, reader_token: str, seeded_system
) -> None:
    """DELETE /systems/{id} with reader token returns 403 (D-07)."""
    response = await async_client.delete(
        f"/systems/{seeded_system.id}",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_delete_system_not_found(async_client: AsyncClient, operator_token: str) -> None:
    """DELETE /systems/{non_existent_id} returns 404."""
    response = await async_client.delete(
        "/systems/99999",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 404
