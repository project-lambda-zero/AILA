"""Tests for multi-provider OIDC admin endpoints (Phase 177).

Covers:
    - CRUD happy path (create microsoft/google/generic, update, delete)
    - Admin-only enforcement (non-admin token hits 403)
    - Validation errors for type-specific required fields
    - Public /providers/public endpoint exposes only id/name/type
    - client_secret never returned in any response

Data is created directly via the admin API; secrets are stored via the
SecretStore (SecretRecord ciphertext blobs).
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

# ---------------------------------------------------------------------------
# Admin-only enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_providers_requires_admin(
    async_client: AsyncClient, reader_token: str
) -> None:
    resp = await async_client.get(
        "/auth/oidc/providers",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_provider_requires_admin(
    async_client: AsyncClient, operator_token: str
) -> None:
    resp = await async_client.post(
        "/auth/oidc/providers",
        headers={"Authorization": f"Bearer {operator_token}"},
        json={
            "provider_name": "microsoft",
            "provider_type": "microsoft",
            "tenant_id": "tenant-1",
            "client_id": "client-id",
            "client_secret": "super-secret",
        },
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# CRUD happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_microsoft_provider_happy_path(
    async_client: AsyncClient, admin_token: str
) -> None:
    resp = await async_client.post(
        "/auth/oidc/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "provider_name": "ms-primary",
            "provider_type": "microsoft",
            "display_name": "Azure AD",
            "tenant_id": "0000-aaaa",
            "client_id": "azure-client",
            "client_secret": "hidden-secret",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["data"]["provider_type"] == "microsoft"
    assert body["data"]["provider_name"] == "ms-primary"
    assert body["data"]["tenant_id"] == "0000-aaaa"
    assert body["data"]["client_id"] == "azure-client"
    # T-138-08: secret never returned
    assert "client_secret" not in body["data"]
    assert "hidden-secret" not in resp.text


@pytest.mark.asyncio
async def test_create_google_provider_without_tenant(
    async_client: AsyncClient, admin_token: str
) -> None:
    resp = await async_client.post(
        "/auth/oidc/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "provider_name": "google-primary",
            "provider_type": "google",
            "client_id": "google-client",
            "client_secret": "google-secret",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["data"]["provider_type"] == "google"
    assert body["data"]["tenant_id"] is None
    assert body["data"]["issuer_url"] is None


@pytest.mark.asyncio
async def test_create_generic_provider_with_issuer(
    async_client: AsyncClient, admin_token: str
) -> None:
    resp = await async_client.post(
        "/auth/oidc/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "provider_name": "keycloak",
            "provider_type": "generic",
            "issuer_url": "https://idp.example.com/realms/main",
            "client_id": "kc-client",
            "client_secret": "kc-secret",
            "scopes": ["openid", "email", "profile", "groups"],
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["data"]["provider_type"] == "generic"
    assert body["data"]["issuer_url"] == "https://idp.example.com/realms/main"
    assert "groups" in body["data"]["scopes"]


@pytest.mark.asyncio
async def test_create_generic_rejects_missing_issuer(
    async_client: AsyncClient, admin_token: str
) -> None:
    resp = await async_client.post(
        "/auth/oidc/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "provider_name": "bad-generic",
            "provider_type": "generic",
            "client_id": "x",
            "client_secret": "y",
        },
    )
    assert resp.status_code == 422
    assert "issuer_url" in resp.text


@pytest.mark.asyncio
async def test_create_microsoft_rejects_missing_tenant(
    async_client: AsyncClient, admin_token: str
) -> None:
    resp = await async_client.post(
        "/auth/oidc/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "provider_name": "ms-bad",
            "provider_type": "microsoft",
            "client_id": "x",
            "client_secret": "y",
        },
    )
    assert resp.status_code == 422
    assert "tenant_id" in resp.text


@pytest.mark.asyncio
async def test_update_and_delete_provider(
    async_client: AsyncClient, admin_token: str
) -> None:
    create_resp = await async_client.post(
        "/auth/oidc/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "provider_name": "to-update",
            "provider_type": "google",
            "client_id": "c1",
            "client_secret": "s1",
        },
    )
    assert create_resp.status_code == 201
    provider_id = create_resp.json()["data"]["id"]

    update_resp = await async_client.put(
        f"/auth/oidc/providers/{provider_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "display_name": "Renamed",
            "is_enabled": False,
        },
    )
    assert update_resp.status_code == 200, update_resp.text
    assert update_resp.json()["data"]["display_name"] == "Renamed"
    assert update_resp.json()["data"]["is_enabled"] is False

    delete_resp = await async_client.delete(
        f"/auth/oidc/providers/{provider_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert delete_resp.status_code == 200
    assert delete_resp.json()["data"]["deleted"] == provider_id


@pytest.mark.asyncio
async def test_list_providers_returns_created(
    async_client: AsyncClient, admin_token: str
) -> None:
    # Two providers, different types
    for payload in (
        {
            "provider_name": "ms-x",
            "provider_type": "microsoft",
            "tenant_id": "t1",
            "client_id": "ms-x-cid",
            "client_secret": "ms-x-secret",
        },
        {
            "provider_name": "g-x",
            "provider_type": "google",
            "client_id": "g-x-cid",
            "client_secret": "g-x-secret",
        },
    ):
        r = await async_client.post(
            "/auth/oidc/providers",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=payload,
        )
        assert r.status_code == 201

    list_resp = await async_client.get(
        "/auth/oidc/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert list_resp.status_code == 200
    data = list_resp.json()["data"]
    names = {p["provider_name"] for p in data}
    assert {"ms-x", "g-x"} <= names
    # Double-check no secret leakage
    assert "ms-x-secret" not in list_resp.text
    assert "g-x-secret" not in list_resp.text


# ---------------------------------------------------------------------------
# Public provider listing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_public_providers_only_shows_enabled(
    async_client: AsyncClient, admin_token: str
) -> None:
    # Enabled google provider
    await async_client.post(
        "/auth/oidc/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "provider_name": "g-public",
            "provider_type": "google",
            "display_name": "Sign in with Google",
            "client_id": "cid",
            "client_secret": "sec",
            "is_enabled": True,
        },
    )
    # Disabled microsoft provider
    await async_client.post(
        "/auth/oidc/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "provider_name": "ms-hidden",
            "provider_type": "microsoft",
            "tenant_id": "t",
            "client_id": "cid2",
            "client_secret": "sec2",
            "is_enabled": False,
        },
    )

    # No auth -- public endpoint
    resp = await async_client.get("/auth/oidc/providers/public")
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    names = {p["name"] for p in data}
    assert "Sign in with Google" in names
    assert "ms-hidden" not in names
    # Public response must NOT leak client_id / secret / issuer
    assert "cid" not in resp.text
    assert "sec" not in resp.text


@pytest.mark.asyncio
async def test_public_providers_no_auth_required(async_client: AsyncClient) -> None:
    """Must return 200 even without any credentials."""
    resp = await async_client.get("/auth/oidc/providers/public")
    assert resp.status_code == 200
    assert resp.json()["data"] == []
