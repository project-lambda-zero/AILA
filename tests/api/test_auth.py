"""Tests for authentication endpoints and behaviors.

Covers: AUTH-01, AUTH-02, AUTH-03, AUTH-04, AUTH-05, AUTH-06, AUTH-07,
        INFRA-01 (startup), API-08 (OpenAPI docs), INFRA-04 (async test infrastructure)
"""
from __future__ import annotations

import os

import jwt


async def test_openapi_docs_accessible(async_client):
    """GET /docs returns 200 with OpenAPI UI (API-08, INFRA-01)."""
    response = await async_client.get("/docs")
    assert response.status_code == 200


async def test_openapi_json_accessible(async_client):
    """GET /openapi.json returns a valid OpenAPI schema (API-08)."""
    response = await async_client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert "paths" in schema
    assert "info" in schema


async def test_protected_routes_return_401_without_token(async_client):
    """Every route except /health and /status returns 401 without Bearer token (AUTH-06)."""
    PUBLIC_PATHS = {
        "/health", "/status",
        "/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect",
        "/auth/token", "/auth/refresh",
        # Phase 138-01: new public user auth endpoints (no Bearer required)
        "/auth/login", "/auth/refresh/user", "/auth/logout",
        "/auth/oidc/authorize", "/auth/oidc/callback",
    }
    for route in async_client._transport.app.routes:
        path = getattr(route, "path", "")
        if not path or "{" in path:
            continue  # skip parameterized routes in this sweep
        if path in PUBLIC_PATHS:
            continue
        response = await async_client.get(path)
        if response.status_code == 405:
            # Method not allowed — route exists but wrong method; try without trailing
            continue
        assert response.status_code == 401, (
            f"Expected 401 on {path} without token, got {response.status_code}"
        )


async def test_login_with_valid_api_key(async_client, admin_key_record):
    """POST /auth/token with valid raw key returns access and refresh tokens (AUTH-03, AUTH-04)."""
    response = await async_client.post(
        "/auth/token",
        json={"api_key": admin_key_record._raw_key},
    )
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"
    assert isinstance(body["expires_in"], int)
    assert body["expires_in"] > 0


async def test_login_with_invalid_api_key(async_client):
    """POST /auth/token with wrong key returns 401 (AUTH-03)."""
    response = await async_client.post(
        "/auth/token",
        json={"api_key": "aila_sk_notarealkey00000000000000000000"},
    )
    assert response.status_code == 401


async def test_jwt_carries_role_and_key_id_claims(async_client, admin_key_record):
    """JWT access token contains role and key_id claims (D-07, AUTH-04)."""
    os.environ.setdefault("AILA_JWT_SECRET_KEY", "test-secret-key-for-tests")
    from aila.config import _build_settings
    _build_settings.cache_clear()

    from aila.config import get_settings
    settings = get_settings()

    response = await async_client.post(
        "/auth/token",
        json={"api_key": admin_key_record._raw_key},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]

    payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
    assert payload.get("role") == "admin"
    assert payload.get("key_id") == admin_key_record.id
    assert payload.get("typ") == "access"


async def test_refresh_token_issues_new_access_token(async_client, admin_key_record):
    """POST /auth/refresh with valid refresh token returns new access token (D-06)."""
    login_resp = await async_client.post(
        "/auth/token",
        json={"api_key": admin_key_record._raw_key},
    )
    assert login_resp.status_code == 200
    refresh_token = login_resp.json()["refresh_token"]

    refresh_resp = await async_client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_resp.status_code == 200
    body = refresh_resp.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"


async def test_bearer_token_auth_succeeds(async_client, admin_token):
    """Valid admin JWT on GET /auth/keys returns 200, not 401 (AUTH-03)."""
    response = await async_client.get(
        "/auth/keys",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200


async def test_create_api_key_requires_admin(async_client, reader_token):
    """POST /auth/keys with reader token returns 403 (AUTH-05, D-09)."""
    response = await async_client.post(
        "/auth/keys",
        json={"role": "reader", "label": "test"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 403


async def test_create_api_key_succeeds_as_admin(async_client, admin_token):
    """POST /auth/keys with admin token creates a key and returns 201 (AUTH-01, D-02)."""
    response = await async_client.post(
        "/auth/keys",
        json={"role": "operator", "label": "ci-key"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 201
    body = response.json()
    assert "key_id" in body
    assert "raw_key" in body
    assert body["raw_key"].startswith("aila_sk_"), f"Expected aila_sk_ prefix: {body['raw_key']}"
    assert body["role"] == "operator"
    assert body["label"] == "ci-key"


async def test_created_key_raw_key_not_stored_in_list(async_client, admin_token):
    """GET /auth/keys never returns raw keys — only prefix (AUTH-02)."""
    response = await async_client.get(
        "/auth/keys",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    for key in response.json()["keys"]:
        assert "raw_key" not in key, "raw_key must not appear in key listing"
        assert "hashed_key" not in key, "hashed_key must not appear in key listing"


async def test_revoke_api_key(async_client, admin_token, admin_key_record):
    """DELETE /auth/keys/{key_id} revokes the key (AUTH-07)."""
    # Create a new key to revoke (don't revoke the admin key we're using)
    create_resp = await async_client.post(
        "/auth/keys",
        json={"role": "reader", "label": "to-revoke"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert create_resp.status_code == 201
    new_key_id = create_resp.json()["key_id"]

    revoke_resp = await async_client.delete(
        f"/auth/keys/{new_key_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["revoked"] is True


async def test_revoked_key_jwt_returns_401(async_client, admin_token, admin_key_record):
    """JWT for a revoked key returns 401 on next request — token blacklist (D-11, AUTH-07)."""
    # Create a new key, get its JWT, then revoke it
    create_resp = await async_client.post(
        "/auth/keys",
        json={"role": "reader", "label": "revocation-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert create_resp.status_code == 201
    new_raw_key = create_resp.json()["raw_key"]
    new_key_id = create_resp.json()["key_id"]

    # Get a JWT for the new key
    login_resp = await async_client.post("/auth/token", json={"api_key": new_raw_key})
    assert login_resp.status_code == 200
    new_jwt = login_resp.json()["access_token"]

    # Revoke the key
    revoke_resp = await async_client.delete(
        f"/auth/keys/{new_key_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert revoke_resp.status_code == 200

    # JWT for revoked key must now be rejected (D-11 blacklist check)
    check_resp = await async_client.get(
        "/auth/keys",
        headers={"Authorization": f"Bearer {new_jwt}"},
    )
    assert check_resp.status_code == 401, (
        f"Expected 401 after revocation but got {check_resp.status_code}"
    )


async def test_missing_bearer_token_returns_401(async_client):
    """No Authorization header on protected endpoint returns 401 (AUTH-06)."""
    response = await async_client.get("/auth/keys")
    assert response.status_code == 401


async def test_async_client_does_not_hang(async_client):
    """Async client runs without hanging — pytest-asyncio + httpx works (INFRA-04)."""
    # This test itself proves the async infrastructure works: if it runs, it passed.
    response = await async_client.get("/health")
    assert response.status_code == 200


# ─── Wave 0: F-02 / F-03 error-path contract tests ────────────────────────────


async def test_revoke_nonexistent_key_returns_404(async_client, admin_token):
    """DELETE /auth/keys/{nonexistent} returns 404 (F-03 contract)."""
    response = await async_client.delete(
        "/auth/keys/nonexistent-key-id-00000",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


async def test_revoke_already_revoked_key_returns_409(async_client, admin_token):
    """DELETE /auth/keys/{key_id} on already-revoked key returns 409 (F-03 contract)."""
    # Create a new key
    create_resp = await async_client.post(
        "/auth/keys",
        json={"role": "reader", "label": "double-revoke-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert create_resp.status_code == 201
    key_id = create_resp.json()["key_id"]

    # First revoke — should succeed
    first_revoke = await async_client.delete(
        f"/auth/keys/{key_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert first_revoke.status_code == 200

    # Second revoke — should 409
    second_revoke = await async_client.delete(
        f"/auth/keys/{key_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert second_revoke.status_code == 409
    assert "already revoked" in second_revoke.json()["detail"].lower()


async def test_refresh_token_blacklist_check(async_client, admin_token):
    """Refresh with a revoked key's token returns 401 (F-02 contract)."""
    # Create a new key
    create_resp = await async_client.post(
        "/auth/keys",
        json={"role": "reader", "label": "refresh-blacklist-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert create_resp.status_code == 201
    raw_key = create_resp.json()["raw_key"]
    key_id = create_resp.json()["key_id"]

    # Login with the new key to get a refresh token
    login_resp = await async_client.post(
        "/auth/token",
        json={"api_key": raw_key},
    )
    assert login_resp.status_code == 200
    refresh_token = login_resp.json()["refresh_token"]

    # Revoke the key
    revoke_resp = await async_client.delete(
        f"/auth/keys/{key_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert revoke_resp.status_code == 200

    # Attempt refresh — should fail with 401
    refresh_resp = await async_client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_resp.status_code == 401


# ─── Wave 1: F-04 / F-05 / F-06 contract tests ─────────────────────────────


async def test_jwt_expiry_from_config_registry(async_client, admin_key_record):
    """JWT expiry reads from ConfigRegistry via get_task_tuning, not os.getenv (F-04)."""
    response = await async_client.post(
        "/auth/token",
        json={"api_key": admin_key_record._raw_key},
    )
    assert response.status_code == 200
    body = response.json()
    # Default expiry is 2_592_000 (30 days) from _ACCESS_EXPIRY_DEFAULT
    assert body["expires_in"] == 2_592_000


async def test_jwt_contains_jti_claim(async_client, admin_key_record):
    """JWT access token contains a unique jti (JWT ID) claim (F-05)."""
    os.environ.setdefault("AILA_JWT_SECRET_KEY", "test-secret-key-for-tests")
    from aila.config import _build_settings
    _build_settings.cache_clear()
    from aila.config import get_settings
    settings = get_settings()

    response = await async_client.post(
        "/auth/token",
        json={"api_key": admin_key_record._raw_key},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]

    payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
    assert "jti" in payload, "JWT must contain 'jti' claim"
    assert isinstance(payload["jti"], str)
    assert len(payload["jti"]) == 32, f"jti should be 32-char hex, got {len(payload['jti'])}"


async def test_jti_unique_across_tokens(async_client, admin_key_record):
    """Two JWTs from the same key have different jti values (F-05 uniqueness)."""
    os.environ.setdefault("AILA_JWT_SECRET_KEY", "test-secret-key-for-tests")
    from aila.config import _build_settings
    _build_settings.cache_clear()
    from aila.config import get_settings
    settings = get_settings()

    resp1 = await async_client.post(
        "/auth/token",
        json={"api_key": admin_key_record._raw_key},
    )
    resp2 = await async_client.post(
        "/auth/token",
        json={"api_key": admin_key_record._raw_key},
    )
    assert resp1.status_code == 200
    assert resp2.status_code == 200

    payload1 = jwt.decode(resp1.json()["access_token"], settings.jwt_secret_key, algorithms=["HS256"])
    payload2 = jwt.decode(resp2.json()["access_token"], settings.jwt_secret_key, algorithms=["HS256"])

    assert payload1["jti"] != payload2["jti"], "Each token must have a unique jti"


async def test_list_api_keys_active_only_filter(async_client, admin_token):
    """GET /auth/keys?active_only=true excludes revoked keys (F-06)."""
    # Create a key then revoke it
    create_resp = await async_client.post(
        "/auth/keys",
        json={"role": "reader", "label": "filter-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert create_resp.status_code == 201
    revoke_key_id = create_resp.json()["key_id"]

    revoke_resp = await async_client.delete(
        f"/auth/keys/{revoke_key_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert revoke_resp.status_code == 200

    # Without filter: revoked key appears in list
    all_resp = await async_client.get(
        "/auth/keys",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert all_resp.status_code == 200
    all_ids = [k["key_id"] for k in all_resp.json()["keys"]]
    assert revoke_key_id in all_ids, "Revoked key should appear in unfiltered list"

    # With active_only=true: revoked key excluded
    active_resp = await async_client.get(
        "/auth/keys",
        params={"active_only": "true"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert active_resp.status_code == 200
    active_ids = [k["key_id"] for k in active_resp.json()["keys"]]
    assert revoke_key_id not in active_ids, "Revoked key must NOT appear when active_only=true"
