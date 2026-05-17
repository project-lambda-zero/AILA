"""Stress tests for JWT attack surface: expired and malformed tokens.

STRESS-13: Expired JWT returns exactly 401 with "expired" indication.
STRESS-14: Malformed JWTs (truncated, wrong algorithm, empty, garbage) all return 401.

Every test hits the full HTTP stack through async_client, proving no path
produces a 500. Phase 73 verified crypto correctness at function level;
this phase verifies the HTTP error shape under adversarial inputs.
"""
from __future__ import annotations

import base64
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt as pyjwt
import pytest
from httpx import AsyncClient

from aila.api.constants import JWT_ALGORITHM, JWT_TYP_ACCESS

# Consistent secret for test token crafting
os.environ.setdefault("AILA_JWT_SECRET_KEY", "test-secret-key-for-jwt-attack-surface")

PROTECTED_ENDPOINT = "/auth/keys"


def _get_jwt_secret() -> str:
    """Return the JWT signing secret from current Settings."""
    from aila.config import _build_settings

    _build_settings.cache_clear()
    from aila.config import get_settings

    return get_settings().jwt_secret_key


def _craft_valid_payload(key_id: str, role: str = "admin") -> dict:
    """Build a valid JWT payload dict for crafting attack tokens."""
    return {
        "jti": uuid4().hex,
        "key_id": key_id,
        "role": role,
        "typ": JWT_TYP_ACCESS,
        "exp": datetime.now(UTC) + timedelta(hours=1),
        "iat": datetime.now(UTC),
    }


# ---------------------------------------------------------------------------
# STRESS-13: Expired JWT exact 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_expired_access_token_returns_401(
    async_client: AsyncClient, admin_key_record
) -> None:
    """An access token expired 10 seconds ago returns 401 with 'expired' detail."""
    secret = _get_jwt_secret()
    payload = _craft_valid_payload(admin_key_record.id)
    payload["exp"] = datetime.now(UTC) - timedelta(seconds=10)
    payload["iat"] = datetime.now(UTC) - timedelta(hours=1)
    expired_token = pyjwt.encode(payload, secret, algorithm=JWT_ALGORITHM)

    resp = await async_client.get(
        PROTECTED_ENDPOINT,
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
    assert "expired" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_expired_by_one_second_returns_401(
    async_client: AsyncClient, admin_key_record
) -> None:
    """Boundary case: token expired 1 second ago still returns 401."""
    secret = _get_jwt_secret()
    payload = _craft_valid_payload(admin_key_record.id)
    payload["exp"] = datetime.now(UTC) - timedelta(seconds=1)
    expired_token = pyjwt.encode(payload, secret, algorithm=JWT_ALGORITHM)

    resp = await async_client.get(
        PROTECTED_ENDPOINT,
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
    assert "expired" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_expired_epoch_zero_returns_401(
    async_client: AsyncClient, admin_key_record
) -> None:
    """Token with exp=0 (Unix epoch start, 1970) returns 401."""
    secret = _get_jwt_secret()
    payload = _craft_valid_payload(admin_key_record.id)
    payload["exp"] = 0  # 1970-01-01T00:00:00Z
    expired_token = pyjwt.encode(payload, secret, algorithm=JWT_ALGORITHM)

    resp = await async_client.get(
        PROTECTED_ENDPOINT,
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
    assert "expired" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# STRESS-14: Malformed JWT all 401
# ---------------------------------------------------------------------------

# Parametrized malformed tokens: (description, token_value)
_MALFORMED_TOKENS: list[tuple[str, str]] = [
    ("empty_string", ""),
    ("literal_null", "null"),
    ("literal_undefined", "undefined"),
    ("random_garbage_ascii", "this-is-not-a-jwt-at-all!!!"),
    (
        "random_base64_bytes",
        base64.urlsafe_b64encode(os.urandom(64)).rstrip(b"=").decode(),
    ),
    ("single_dot", "."),
    ("two_dots_no_content", ".."),
    ("three_dots", "..."),
    (
        "truncated_header_only",
        base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode(),
    ),
    (
        "two_segments_missing_signature",
        base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
        + "."
        + base64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b"=").decode(),
    ),
    (
        "valid_header_empty_payload_empty_sig",
        base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
        + "..",
    ),
    (
        "corrupt_base64_in_payload",
        base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
        + ".!!!invalid-base64!!!."
        + "fakesig",
    ),
    ("long_random_10kb", base64.urlsafe_b64encode(os.urandom(10240)).rstrip(b"=").decode()),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("description", "token"),
    _MALFORMED_TOKENS,
    ids=[t[0] for t in _MALFORMED_TOKENS],
)
async def test_malformed_jwt_returns_401(
    async_client: AsyncClient, description: str, token: str
) -> None:
    """Every malformed token variant returns 401, never 500."""
    resp = await async_client.get(
        PROTECTED_ENDPOINT,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401, (
        f"[{description}] Expected 401, got {resp.status_code}: {resp.text}"
    )


@pytest.mark.asyncio
async def test_wrong_secret_returns_401(
    async_client: AsyncClient, admin_key_record
) -> None:
    """Token signed with a completely different HS256 secret returns 401."""
    payload = _craft_valid_payload(admin_key_record.id)
    wrong_token = pyjwt.encode(payload, "completely-different-secret", algorithm=JWT_ALGORITHM)

    resp = await async_client.get(
        PROTECTED_ENDPOINT,
        headers={"Authorization": f"Bearer {wrong_token}"},
    )
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
    detail = resp.json()["detail"]
    assert "malformed" in detail.lower() or "invalid" in detail.lower()


@pytest.mark.asyncio
async def test_hs384_algorithm_returns_401(
    async_client: AsyncClient, admin_key_record
) -> None:
    """Token signed with HS384 instead of HS256 returns 401 (algorithm mismatch)."""
    secret = _get_jwt_secret()
    payload = _craft_valid_payload(admin_key_record.id)
    hs384_token = pyjwt.encode(payload, secret, algorithm="HS384")

    resp = await async_client.get(
        PROTECTED_ENDPOINT,
        headers={"Authorization": f"Bearer {hs384_token}"},
    )
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"


@pytest.mark.asyncio
async def test_rs256_algorithm_attempt_returns_401(
    async_client: AsyncClient, admin_key_record
) -> None:
    """Manually crafted token with alg=RS256 header returns 401.

    PyJWT refuses to encode RS256 with a symmetric key, so craft manually.
    """
    import json

    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()

    payload_data = _craft_valid_payload(admin_key_record.id)
    # Convert datetime to timestamp for manual encoding
    payload_data["exp"] = payload_data["exp"].timestamp()
    payload_data["iat"] = payload_data["iat"].timestamp()
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload_data).encode()
    ).rstrip(b"=").decode()

    fake_sig = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    crafted_token = f"{header}.{payload_b64}.{fake_sig}"

    resp = await async_client.get(
        PROTECTED_ENDPOINT,
        headers={"Authorization": f"Bearer {crafted_token}"},
    )
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
