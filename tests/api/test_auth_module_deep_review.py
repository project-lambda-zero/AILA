"""Deep review tests for auth.py internals: JWT crypto correctness, blacklist
consistency, and refresh token lifecycle.

Covers FILE-10 requirements not addressed by test_auth.py (which focuses on
endpoint-level behavior). These tests verify:

- Group 1: Signature tamper rejection (byte-flip, wrong-secret)
- Group 2: Token type enforcement (refresh-as-access, access-as-refresh)
- Group 3: Payload integrity (missing key_id, nonexistent key_id, garbage token)
- Group 4: Algorithm pinning (alg=none attack rejected)
- Group 5: Refresh token expiry and independent access/refresh timers
- Group 6: Blacklist enforcement on non-auth protected endpoints
"""
from __future__ import annotations

import base64
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import jwt as pyjwt
import pytest

from aila.api.auth import (
    decode_and_blacklist_check,
    issue_jwt_token,
    issue_refresh_token,
)
from aila.api.constants import JWT_ALGORITHM, JWT_TYP_ACCESS, JWT_TYP_REFRESH

# Ensure consistent JWT secret across tests
os.environ.setdefault("AILA_JWT_SECRET_KEY", "test-secret-key-for-deep-review")


def _get_jwt_secret() -> str:
    """Return the JWT signing secret used by the current Settings singleton."""
    from aila.config import _build_settings

    _build_settings.cache_clear()
    from aila.config import get_settings

    return get_settings().jwt_secret_key


# ── Group 1: Signature tamper rejection ──────────────────────────────────────


async def test_signature_tamper_byte_flip_rejected(async_client, admin_key_record):
    """A JWT with a single byte flipped in the signature is rejected with 401."""
    token, _ = issue_jwt_token(admin_key_record)

    # Split the JWT into header.payload.signature parts
    parts = token.split(".")
    assert len(parts) == 3, "JWT must have 3 dot-separated parts"

    # Decode the signature (base64url), flip the last byte, re-encode
    sig_bytes = base64.urlsafe_b64decode(parts[2] + "==")
    tampered_sig = sig_bytes[:-1] + bytes([(sig_bytes[-1] ^ 0xFF)])
    tampered_sig_b64 = base64.urlsafe_b64encode(tampered_sig).rstrip(b"=").decode()

    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig_b64}"

    response = await async_client.get(
        "/auth/keys",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert response.status_code == 401
    assert "malformed or has an invalid signature" in response.json()["detail"]


async def test_wrong_secret_jwt_rejected(async_client, admin_key_record):
    """A JWT signed with a wrong secret is rejected with 401."""
    # Craft a JWT with correct claims but wrong signing secret
    payload = {
        "jti": uuid4().hex,
        "key_id": admin_key_record.id,
        "role": admin_key_record.role,
        "typ": JWT_TYP_ACCESS,
        "exp": datetime.now(UTC) + timedelta(hours=1),
        "iat": datetime.now(UTC),
    }
    wrong_secret_token = pyjwt.encode(payload, "wrong-secret-key", algorithm=JWT_ALGORITHM)

    response = await async_client.get(
        "/auth/keys",
        headers={"Authorization": f"Bearer {wrong_secret_token}"},
    )
    assert response.status_code == 401
    assert "malformed or has an invalid signature" in response.json()["detail"]


# ── Group 2: Token type enforcement ──────────────────────────────────────────


async def test_refresh_token_rejected_as_bearer_auth(async_client, admin_key_record):
    """Submitting a refresh token (typ='refresh') as Bearer auth on a protected endpoint returns 401."""
    refresh_token = issue_refresh_token(admin_key_record)

    response = await async_client.get(
        "/auth/keys",
        headers={"Authorization": f"Bearer {refresh_token}"},
    )
    assert response.status_code == 401
    assert "Expected 'access' token" in response.json()["detail"]


async def test_access_token_rejected_for_refresh(async_client, admin_key_record):
    """Submitting an access token (typ='access') to POST /auth/refresh returns 401."""
    access_token, _ = issue_jwt_token(admin_key_record)

    response = await async_client.post(
        "/auth/refresh",
        json={"refresh_token": access_token},
    )
    assert response.status_code == 401
    assert "Expected 'refresh' token" in response.json()["detail"]


# ── Group 3: Payload integrity ───────────────────────────────────────────────


async def test_missing_key_id_claim_rejected(async_client, admin_key_record):
    """A JWT with valid signature but missing key_id claim returns 401."""
    secret = _get_jwt_secret()
    payload = {
        "jti": uuid4().hex,
        "role": "admin",
        "typ": JWT_TYP_ACCESS,
        "exp": datetime.now(UTC) + timedelta(hours=1),
        "iat": datetime.now(UTC),
        # key_id intentionally omitted
    }
    token = pyjwt.encode(payload, secret, algorithm=JWT_ALGORITHM)

    response = await async_client.get(
        "/auth/keys",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert "missing the 'key_id' claim" in response.json()["detail"]


async def test_nonexistent_key_id_rejected(async_client, admin_key_record):
    """A JWT whose key_id points to a nonexistent key returns 401."""
    secret = _get_jwt_secret()
    payload = {
        "jti": uuid4().hex,
        "key_id": "nonexistent-uuid-00000",
        "role": "admin",
        "typ": JWT_TYP_ACCESS,
        "exp": datetime.now(UTC) + timedelta(hours=1),
        "iat": datetime.now(UTC),
    }
    token = pyjwt.encode(payload, secret, algorithm=JWT_ALGORITHM)

    response = await async_client.get(
        "/auth/keys",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert "revoked or does not exist" in response.json()["detail"]


async def test_random_garbage_token_rejected(async_client):
    """Random base64 garbage submitted as Bearer token returns 401."""
    garbage = base64.urlsafe_b64encode(os.urandom(64)).decode()

    response = await async_client.get(
        "/auth/keys",
        headers={"Authorization": f"Bearer {garbage}"},
    )
    assert response.status_code == 401


# ── Group 4: Algorithm pinning ───────────────────────────────────────────────


def test_alg_none_attack_rejected(admin_key_record):
    """decode_and_blacklist_check rejects a token with algorithm='none' (alg=none attack).

    This verifies the algorithms=[JWT_ALGORITHM] pinning prevents unsigned
    tokens from being accepted.
    """
    # Craft a token with alg=none. PyJWT >= 2.4 refuses to encode with
    # algorithm="none" unless the key is "", so we build the token manually.
    import json

    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()

    payload_data = {
        "jti": uuid4().hex,
        "key_id": admin_key_record.id,
        "role": admin_key_record.role,
        "typ": JWT_TYP_ACCESS,
        "exp": (datetime.now(UTC) + timedelta(hours=1)).timestamp(),
        "iat": datetime.now(UTC).timestamp(),
    }
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload_data).encode()
    ).rstrip(b"=").decode()

    # alg=none token has empty signature
    none_token = f"{header}.{payload_b64}."

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        decode_and_blacklist_check(none_token, expected_typ=JWT_TYP_ACCESS)
    assert exc_info.value.status_code == 401


# ── Group 5: Refresh token expiry and independent timers ─────────────────────


async def test_expired_refresh_token_rejected(async_client, admin_key_record):
    """An expired refresh token cannot be exchanged for a new access token (401)."""
    secret = _get_jwt_secret()
    # Craft a refresh token that expired 10 seconds ago
    payload = {
        "jti": uuid4().hex,
        "key_id": admin_key_record.id,
        "role": admin_key_record.role,
        "typ": JWT_TYP_REFRESH,
        "exp": datetime.now(UTC) - timedelta(seconds=10),
        "iat": datetime.now(UTC) - timedelta(hours=1),
    }
    expired_refresh = pyjwt.encode(payload, secret, algorithm=JWT_ALGORITHM)

    response = await async_client.post(
        "/auth/refresh",
        json={"refresh_token": expired_refresh},
    )
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


async def test_refresh_works_independently_of_access_expiry(async_client, admin_key_record):
    """Refreshing works independently of access token expiry -- separate timers.

    Even when the access token has a very short expiry, the refresh token
    (with a much longer expiry) should still be valid for obtaining a new
    access token.
    """
    # Patch access expiry to 1 second, refresh expiry to 86400 seconds
    with (
        patch("aila.api.auth._access_expiry_seconds", return_value=1),
        patch("aila.api.auth._refresh_expiry_seconds", return_value=86400),
    ):
        access_token, access_expiry = issue_jwt_token(admin_key_record)
        refresh_token = issue_refresh_token(admin_key_record)

    assert access_expiry == 1, "Access expiry should be patched to 1 second"

    # The refresh token should still work regardless of access token state
    response = await async_client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"


# ── Group 6: Blacklist consistency across endpoints ──────────────────────────


async def test_blacklisted_token_rejected_on_non_auth_endpoint(async_client, admin_token, admin_key_record):
    """A blacklisted (revoked) key's token is rejected on non-auth endpoints, not just /auth/keys.

    Creates a new key, gets its JWT, revokes the key, then attempts to access
    GET /systems (a non-auth protected endpoint) -- must return 401.
    """
    # Create a new key
    create_resp = await async_client.post(
        "/auth/keys",
        json={"role": "operator", "label": "blacklist-non-auth-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert create_resp.status_code == 201
    raw_key = create_resp.json()["raw_key"]
    key_id = create_resp.json()["key_id"]

    # Login with the new key to get a JWT
    login_resp = await async_client.post(
        "/auth/token",
        json={"api_key": raw_key},
    )
    assert login_resp.status_code == 200
    victim_jwt = login_resp.json()["access_token"]

    # Revoke the key
    revoke_resp = await async_client.delete(
        f"/auth/keys/{key_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert revoke_resp.status_code == 200

    # Attempt to access a non-auth protected endpoint with the revoked key's JWT
    systems_resp = await async_client.get(
        "/systems",
        headers={"Authorization": f"Bearer {victim_jwt}"},
    )
    assert systems_resp.status_code == 401, (
        f"Expected 401 on /systems with revoked key JWT, got {systems_resp.status_code}"
    )
