"""Negative tests for auth endpoints: 401, 403, 409, 422 error paths.

Covers:
  POST /auth/token      - 401 bad key, 422 missing body
  POST /auth/refresh    - 401 bad refresh token
  POST /auth/keys       - 403 non-admin, 422 invalid role
  GET  /auth/keys       - 403 non-admin
  DELETE /auth/keys/{id} - 404 not found, 409 already revoked, 403 non-admin
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


# -- POST /auth/token ----------------------------------------------------------


@pytest.mark.asyncio
async def test_login_bad_key(async_client: AsyncClient) -> None:
    """POST /auth/token with an invalid API key returns 401."""
    resp = await async_client.post("/auth/token", json={"api_key": "garbage-key-value-not-real"})
    assert resp.status_code == 401
    detail = resp.json()["detail"]
    assert "Invalid API key" in detail


@pytest.mark.asyncio
async def test_login_empty_body(async_client: AsyncClient) -> None:
    """POST /auth/token with no body returns 422 (Pydantic validation)."""
    resp = await async_client.post("/auth/token", json={})
    assert resp.status_code == 422


# -- POST /auth/refresh --------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_bad_token(async_client: AsyncClient) -> None:
    """POST /auth/refresh with garbage refresh token returns 401."""
    resp = await async_client.post("/auth/refresh", json={"refresh_token": "not.a.valid.jwt"})
    assert resp.status_code == 401
    detail = resp.json()["detail"]
    assert "JWT" in detail or "token" in detail.lower()


# -- POST /auth/keys -----------------------------------------------------------


@pytest.mark.asyncio
async def test_create_key_non_admin(
    async_client: AsyncClient, reader_token: str
) -> None:
    """POST /auth/keys with reader token returns 403 (admin only)."""
    resp = await async_client.post(
        "/auth/keys",
        json={"role": "reader", "label": "neg-test"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert "admin" in detail.lower()


@pytest.mark.asyncio
async def test_create_key_invalid_role(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /auth/keys with role='superadmin' returns 422 (invalid role).

    Schema-level Literal['admin', 'operator', 'reader'] validation fires
    before the router, producing Pydantic's standard 422 response shape.
    """
    resp = await async_client.post(
        "/auth/keys",
        json={"role": "superadmin", "label": "neg-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422
    body = resp.json()
    # Phase 80: custom validation handler reshapes 422 into ErrorResponse envelope
    assert isinstance(body["detail"], str)
    assert body["code"] == "VALIDATION_ERROR"
    assert isinstance(body["errors"], list)
    assert any(err["loc"] == ["body", "role"] for err in body["errors"])


# -- GET /auth/keys ------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_keys_non_admin(
    async_client: AsyncClient, reader_token: str
) -> None:
    """GET /auth/keys with reader token returns 403 (admin only)."""
    resp = await async_client.get(
        "/auth/keys",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert "admin" in detail.lower()


# -- DELETE /auth/keys/{id} ----------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_key_not_found(
    async_client: AsyncClient, admin_token: str
) -> None:
    """DELETE /auth/keys/nonexistent-uuid returns 404."""
    resp = await async_client.delete(
        "/auth/keys/nonexistent-uuid-value",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "not found" in detail.lower()


@pytest.mark.asyncio
async def test_revoke_key_already_revoked(
    async_client: AsyncClient, admin_token: str, reader_key_record
) -> None:
    """Revoking an already-revoked key returns 409 Conflict."""
    key_id = reader_key_record.id

    # First revoke succeeds
    resp1 = await async_client.delete(
        f"/auth/keys/{key_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp1.status_code == 200

    # Second revoke returns 409
    resp2 = await async_client.delete(
        f"/auth/keys/{key_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp2.status_code == 409
    detail = resp2.json()["detail"]
    assert "already revoked" in detail.lower()


@pytest.mark.asyncio
async def test_revoke_key_non_admin(
    async_client: AsyncClient, reader_token: str
) -> None:
    """DELETE /auth/keys/{id} with reader token returns 403."""
    resp = await async_client.delete(
        "/auth/keys/any-key-id",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403
