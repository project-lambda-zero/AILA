"""Token blacklist round-trip verification for the AILA API (WIRE-05).

Proves that token revocation works end-to-end: create a key, get a JWT,
use the JWT successfully, revoke the key, then verify the same JWT is
rejected (401) and that new tokens cannot be obtained for a revoked key.

Full cycle: create -> JWT -> use -> revoke -> JWT rejected (401).
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_token_blacklist_revoke_returns_401(
    async_client: AsyncClient,
    admin_token: str,
) -> None:
    """Full round-trip: create key -> get JWT -> use JWT -> revoke key -> JWT 401.

    Steps:
    1. Admin creates a new reader API key via POST /auth/keys.
    2. Exchange the raw key for a JWT via POST /auth/token.
    3. Use the JWT to GET /systems (any authenticated endpoint) -- expect 200.
    4. Admin revokes the key via DELETE /auth/keys/{key_id} -- expect 200.
    5. Use the same JWT to GET /systems again -- expect 401 (blacklisted).
    """
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Step 1: Create a new reader API key
    create_resp = await async_client.post(
        "/auth/keys",
        json={"role": "reader", "label": "blacklist-test"},
        headers=admin_headers,
    )
    assert create_resp.status_code == 201, f"Expected 201, got {create_resp.status_code}: {create_resp.text}"
    key_data = create_resp.json()
    raw_key = key_data["raw_key"]
    key_id = key_data["key_id"]

    # Step 2: Exchange raw key for JWT
    token_resp = await async_client.post(
        "/auth/token",
        json={"api_key": raw_key},
    )
    assert token_resp.status_code == 200, f"Expected 200, got {token_resp.status_code}: {token_resp.text}"
    access_token = token_resp.json()["access_token"]
    reader_headers = {"Authorization": f"Bearer {access_token}"}

    # Step 3: Use the JWT on an authenticated endpoint -- should succeed
    systems_resp = await async_client.get("/systems", headers=reader_headers)
    assert systems_resp.status_code == 200, (
        f"JWT should work before revocation, got {systems_resp.status_code}: {systems_resp.text}"
    )

    # Step 4: Revoke the key via admin
    revoke_resp = await async_client.delete(
        f"/auth/keys/{key_id}",
        headers=admin_headers,
    )
    assert revoke_resp.status_code == 200, f"Expected 200, got {revoke_resp.status_code}: {revoke_resp.text}"
    assert revoke_resp.json()["revoked"] is True

    # Step 5: Same JWT should now be rejected (blacklist check in _decode_and_blacklist_check)
    blocked_resp = await async_client.get("/systems", headers=reader_headers)
    assert blocked_resp.status_code == 401, (
        f"JWT should be rejected after revocation (401), got {blocked_resp.status_code}: {blocked_resp.text}"
    )


@pytest.mark.asyncio
async def test_revoked_key_cannot_get_new_token(
    async_client: AsyncClient,
    admin_token: str,
) -> None:
    """After revoking a key, POST /auth/token with that key returns 401.

    The token endpoint filters by revoked_at IS NULL in its lookup query,
    so a revoked key will not match any candidate row, resulting in 401.
    """
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a new reader API key
    create_resp = await async_client.post(
        "/auth/keys",
        json={"role": "reader", "label": "revoked-token-test"},
        headers=admin_headers,
    )
    assert create_resp.status_code == 201
    key_data = create_resp.json()
    raw_key = key_data["raw_key"]
    key_id = key_data["key_id"]

    # Verify the key works for token exchange before revocation
    pre_resp = await async_client.post("/auth/token", json={"api_key": raw_key})
    assert pre_resp.status_code == 200, (
        f"Key should work before revocation, got {pre_resp.status_code}: {pre_resp.text}"
    )

    # Revoke the key
    revoke_resp = await async_client.delete(f"/auth/keys/{key_id}", headers=admin_headers)
    assert revoke_resp.status_code == 200

    # Try to get a new token with the revoked key -- should fail
    post_revoke_resp = await async_client.post("/auth/token", json={"api_key": raw_key})
    assert post_revoke_resp.status_code == 401, (
        f"Revoked key should not get a new token (401), got {post_revoke_resp.status_code}: {post_revoke_resp.text}"
    )
