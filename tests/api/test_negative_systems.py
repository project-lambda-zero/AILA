"""Negative tests for systems endpoints: 403, 404, 409, 422 error paths.

Covers:
  GET  /systems/{id}      - 404 not found
  GET  /systems/{id}/scans - 404 not found
  POST /systems           - 403 reader, 409 duplicate name, 422 bad input
  PUT  /systems/{id}      - 403 reader, 404 not found, 409 name conflict
  DELETE /systems/{id}    - 403 reader, 404 not found
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


# -- GET /systems/{id} ---------------------------------------------------------


@pytest.mark.asyncio
async def test_get_system_not_found(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems/99999 returns 404 with structured detail."""
    resp = await async_client.get(
        "/systems/99999",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "not found" in detail.lower()


# -- GET /systems/{id}/scans ---------------------------------------------------


@pytest.mark.asyncio
async def test_get_system_scans_not_found(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems/99999/scans returns 404 when system does not exist."""
    resp = await async_client.get(
        "/systems/99999/scans",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "not found" in detail.lower()


# -- POST /systems -------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_system_reader_forbidden(
    async_client: AsyncClient, reader_token: str
) -> None:
    """POST /systems with reader token returns 403 (operator+ required)."""
    resp = await async_client.post(
        "/systems",
        json={"name": "neg-test", "host": "10.0.0.1"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert "operator" in detail.lower()


@pytest.mark.asyncio
async def test_create_system_duplicate_name(
    async_client: AsyncClient, admin_token: str, seeded_system
) -> None:
    """POST /systems with duplicate name returns 409 Conflict."""
    resp = await async_client.post(
        "/systems",
        json={"name": seeded_system.name, "host": "10.0.0.99"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert "already exists" in detail.lower()


@pytest.mark.asyncio
async def test_create_system_missing_fields(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /systems with empty body returns 422 (Pydantic validation)."""
    resp = await async_client.post(
        "/systems",
        json={},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


# -- PUT /systems/{id} ---------------------------------------------------------


@pytest.mark.asyncio
async def test_update_system_not_found(
    async_client: AsyncClient, admin_token: str
) -> None:
    """PUT /systems/99999 returns 404 when system does not exist."""
    resp = await async_client.put(
        "/systems/99999",
        json={"name": "updated-name"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "not found" in detail.lower()


@pytest.mark.asyncio
async def test_update_system_name_conflict(
    async_client: AsyncClient, admin_token: str, seeded_system
) -> None:
    """PUT /systems/{id} with conflicting name returns 409."""
    # Create a second system first
    resp_create = await async_client.post(
        "/systems",
        json={"name": "second-system", "host": "10.0.0.2"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_create.status_code == 201
    second_id = resp_create.json()["id"]

    # Try to rename second system to the seeded_system's name
    resp = await async_client.put(
        f"/systems/{second_id}",
        json={"name": seeded_system.name},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert "already exists" in detail.lower()


@pytest.mark.asyncio
async def test_update_system_reader_forbidden(
    async_client: AsyncClient, reader_token: str
) -> None:
    """PUT /systems/{id} with reader token returns 403."""
    resp = await async_client.put(
        "/systems/1",
        json={"name": "hacked"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403


# -- DELETE /systems/{id} ------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_system_not_found(
    async_client: AsyncClient, admin_token: str
) -> None:
    """DELETE /systems/99999 returns 404."""
    resp = await async_client.delete(
        "/systems/99999",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "not found" in detail.lower()


@pytest.mark.asyncio
async def test_delete_system_reader_forbidden(
    async_client: AsyncClient, reader_token: str
) -> None:
    """DELETE /systems/{id} with reader token returns 403."""
    resp = await async_client.delete(
        "/systems/1",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403
