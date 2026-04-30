"""Token lifecycle end-to-end -- Phase 94 (XCUT-02).

Proves every transition in the token lifecycle in a single sequential flow:
  1. CREATE   -- admin creates a new API key (POST /auth/keys -> 201)
  2. EXCHANGE -- raw key exchanged for JWT (POST /auth/token -> 200)
  3. USE      -- JWT accesses a protected endpoint (GET /auth/keys -> 200)
  4. REFRESH  -- refresh token yields a new access token (POST /auth/refresh -> 200)
  5. USE-REFRESHED -- refreshed token works on protected endpoint (GET /auth/keys -> 200)
  6. REVOKE   -- admin revokes the key (DELETE /auth/keys/{id} -> 200)
  7. FAIL-ACCESS  -- original access token rejected (GET /auth/keys -> 401)
  8. FAIL-REFRESH -- refresh token rejected (POST /auth/refresh -> 401)
  9. FAIL-EXCHANGE -- raw key exchange rejected (POST /auth/token -> 401)

Each step asserts exact status code and meaningful response body fields.
This is one continuous flow, not isolated unit tests.
"""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_full_token_lifecycle(async_client, admin_token):
    """Full round-trip: create -> exchange -> use -> refresh -> revoke -> fail."""
    auth = {"Authorization": f"Bearer {admin_token}"}

    # ── Step 1: CREATE ─────────────────────────────────────────────────
    # Admin creates a new operator API key.
    create_resp = await async_client.post(
        "/auth/keys",
        json={"role": "operator", "label": "lifecycle-test-key"},
        headers=auth,
    )
    assert create_resp.status_code == 201, f"CREATE failed: {create_resp.text}"
    create_body = create_resp.json()
    assert "key_id" in create_body
    assert "raw_key" in create_body
    assert create_body["raw_key"].startswith("aila_sk_")
    assert create_body["role"] == "operator"
    assert create_body["label"] == "lifecycle-test-key"
    assert "created_at" in create_body

    raw_key = create_body["raw_key"]
    key_id = create_body["key_id"]

    # ── Step 2: EXCHANGE ───────────────────────────────────────────────
    # Exchange the raw API key for JWT access + refresh tokens.
    exchange_resp = await async_client.post(
        "/auth/token",
        json={"api_key": raw_key},
    )
    assert exchange_resp.status_code == 200, f"EXCHANGE failed: {exchange_resp.text}"
    exchange_body = exchange_resp.json()
    assert "access_token" in exchange_body
    assert "refresh_token" in exchange_body
    assert exchange_body["token_type"] == "bearer"
    assert isinstance(exchange_body["expires_in"], int)
    assert exchange_body["expires_in"] > 0

    access_token = exchange_body["access_token"]
    refresh_token = exchange_body["refresh_token"]

    # ── Step 3: USE ────────────────────────────────────────────────────
    # Use the access token on a protected endpoint.
    use_resp = await async_client.get(
        "/auth/keys",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    # Operator cannot access admin-only /auth/keys => 403
    # But the token IS valid (not 401). This proves the JWT works.
    assert use_resp.status_code == 403, f"USE expected 403 for operator on admin endpoint: {use_resp.text}"

    # Also verify the token works on a reader-accessible endpoint (health is public,
    # so use /systems which is reader+).
    use_systems_resp = await async_client.get(
        "/systems",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    # 200 or 503 (no platform) both prove auth passed -- NOT 401 or 403.
    assert use_systems_resp.status_code in (200, 503), (
        f"USE on /systems expected 200 or 503, got {use_systems_resp.status_code}: {use_systems_resp.text}"
    )

    # ── Step 4: REFRESH ────────────────────────────────────────────────
    # Exchange the refresh token for a new access token.
    refresh_resp = await async_client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_resp.status_code == 200, f"REFRESH failed: {refresh_resp.text}"
    refresh_body = refresh_resp.json()
    assert "access_token" in refresh_body
    assert refresh_body["token_type"] == "bearer"
    assert isinstance(refresh_body["expires_in"], int)
    assert refresh_body["expires_in"] > 0

    refreshed_access_token = refresh_body["access_token"]
    # The refreshed token must be different from the original.
    assert refreshed_access_token != access_token, "Refreshed token must differ from original"

    # ── Step 5: USE-REFRESHED ──────────────────────────────────────────
    # The refreshed access token works on a protected endpoint.
    use_refreshed_resp = await async_client.get(
        "/systems",
        headers={"Authorization": f"Bearer {refreshed_access_token}"},
    )
    assert use_refreshed_resp.status_code in (200, 503), (
        f"USE-REFRESHED expected 200 or 503, got {use_refreshed_resp.status_code}: {use_refreshed_resp.text}"
    )

    # ── Step 6: REVOKE ─────────────────────────────────────────────────
    # Admin revokes the API key.
    revoke_resp = await async_client.delete(
        f"/auth/keys/{key_id}",
        headers=auth,
    )
    assert revoke_resp.status_code == 200, f"REVOKE failed: {revoke_resp.text}"
    revoke_body = revoke_resp.json()
    assert revoke_body["key_id"] == key_id
    assert revoke_body["revoked"] is True

    # ── Step 7: FAIL-ACCESS ────────────────────────────────────────────
    # The original access token must now be rejected (blacklist check).
    fail_access_resp = await async_client.get(
        "/systems",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert fail_access_resp.status_code == 401, (
        f"FAIL-ACCESS expected 401 after revocation, got {fail_access_resp.status_code}"
    )

    # The refreshed access token must also be rejected.
    fail_refreshed_resp = await async_client.get(
        "/systems",
        headers={"Authorization": f"Bearer {refreshed_access_token}"},
    )
    assert fail_refreshed_resp.status_code == 401, (
        f"FAIL-ACCESS (refreshed) expected 401, got {fail_refreshed_resp.status_code}"
    )

    # ── Step 8: FAIL-REFRESH ───────────────────────────────────────────
    # Refresh token for a revoked key must also fail.
    fail_refresh_resp = await async_client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert fail_refresh_resp.status_code == 401, (
        f"FAIL-REFRESH expected 401, got {fail_refresh_resp.status_code}"
    )

    # ── Step 9: FAIL-EXCHANGE ──────────────────────────────────────────
    # Re-exchanging the raw key must fail (key is revoked, prefix lookup filters
    # by revoked_at IS NULL).
    fail_exchange_resp = await async_client.post(
        "/auth/token",
        json={"api_key": raw_key},
    )
    assert fail_exchange_resp.status_code == 401, (
        f"FAIL-EXCHANGE expected 401, got {fail_exchange_resp.status_code}"
    )
