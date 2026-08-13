"""Regression tests for issue #172: rate-limit bucket key MUST verify JWT.

`aila.api.limiter._authenticated_user_key` used to decode the Bearer JWT with
`options={"verify_signature": False}` and trust the `user_id` / `key_id` claim
as the rate-limit bucket.  Anyone could forge a JWT with a fabricated (or
rotating) identity to escape the per-IP brute-force limit on `/auth/token`
and `/auth/login`, or set a real admin `key_id` to exhaust that admin's quota.

The fix verifies the signature with the platform HS256 secret.  Only a token
whose signature checks out is trusted for bucketing; every failure mode
(missing header, malformed token, bad signature, expired token, tampered
payload) falls back to the client IP.

These tests exercise the pure function with a synthetic Starlette Request so
they do not need Postgres or the full app stack.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt as pyjwt
import pytest
from starlette.requests import Request

from aila.api.constants import JWT_ALGORITHM, JWT_TYP_ACCESS
from aila.api.limiter import _authenticated_user_key
from aila.config import _build_settings, get_settings


def _make_request(*, authorization: str | None = None, client_ip: str = "203.0.113.7") -> Request:
    """Build a minimal Starlette Request with an optional Authorization header.

    `get_remote_address` reads `request.client.host`, so the scope needs a
    concrete client tuple.  Headers on the ASGI scope are lower-case byte
    tuples; Starlette's `Request.headers` mapping is case-insensitive.
    """
    headers: list[tuple[bytes, bytes]] = []
    if authorization is not None:
        headers.append((b"authorization", authorization.encode("latin-1")))
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/auth/login",
        "headers": headers,
        "client": (client_ip, 12345),
    }
    return Request(scope)


def _valid_payload(user_id: str) -> dict:
    return {
        "jti": uuid4().hex,
        "user_id": user_id,
        "key_id": user_id,
        "role": "reader",
        "typ": JWT_TYP_ACCESS,
        "exp": datetime.now(UTC) + timedelta(hours=1),
        "iat": datetime.now(UTC),
    }


@pytest.fixture()
def jwt_secret(monkeypatch: pytest.MonkeyPatch) -> str:
    """Pin the JWT signing secret for this test module."""
    secret = "unit-test-jwt-signing-secret-172"
    monkeypatch.setenv("AILA_JWT_SECRET_KEY", secret)
    _build_settings.cache_clear()
    assert get_settings().jwt_secret_key == secret
    yield secret
    _build_settings.cache_clear()


# ---------------------------------------------------------------------------
# (a) Genuine, signature-valid token -> bucket by identity claim.
# ---------------------------------------------------------------------------


def test_valid_signed_token_buckets_by_user_id(jwt_secret: str) -> None:
    user_id = "user-real-abc"
    token = pyjwt.encode(_valid_payload(user_id), jwt_secret, algorithm=JWT_ALGORITHM)
    request = _make_request(authorization=f"Bearer {token}", client_ip="198.51.100.9")

    assert _authenticated_user_key(request) == user_id


def test_valid_signed_token_prefers_user_id_over_key_id(jwt_secret: str) -> None:
    payload = _valid_payload("user-real-xyz")
    payload["user_id"] = "user-priority"
    payload["key_id"] = "key-should-not-win"
    token = pyjwt.encode(payload, jwt_secret, algorithm=JWT_ALGORITHM)
    request = _make_request(authorization=f"Bearer {token}")

    assert _authenticated_user_key(request) == "user-priority"


def test_valid_signed_token_falls_back_to_key_id_when_no_user_id(jwt_secret: str) -> None:
    payload = _valid_payload("ignored")
    del payload["user_id"]
    payload["key_id"] = "key-only-identity"
    token = pyjwt.encode(payload, jwt_secret, algorithm=JWT_ALGORITHM)
    request = _make_request(authorization=f"Bearer {token}")

    assert _authenticated_user_key(request) == "key-only-identity"


# ---------------------------------------------------------------------------
# (b) Forged / invalid-signature tokens -> MUST fall back to remote IP.
#     These fail on the pre-fix code, which trusted the unverified claim.
# ---------------------------------------------------------------------------


def test_forged_token_signed_with_wrong_secret_buckets_by_ip(jwt_secret: str) -> None:
    """Attacker signs a JWT with their own secret and injects any user_id.

    Under the pre-fix code this returns "forged-admin-id".  Under the fix it
    returns the client IP, preserving the per-IP brute-force cap.
    """
    payload = _valid_payload("forged-admin-id")
    forged = pyjwt.encode(payload, "attacker-controlled-secret", algorithm=JWT_ALGORITHM)
    request = _make_request(authorization=f"Bearer {forged}", client_ip="192.0.2.55")

    assert _authenticated_user_key(request) == "192.0.2.55"


def test_tampered_payload_buckets_by_ip(jwt_secret: str) -> None:
    """Flip a byte in the payload segment: the signature no longer verifies."""
    token = pyjwt.encode(_valid_payload("legit-user"), jwt_secret, algorithm=JWT_ALGORITHM)
    header_b64, payload_b64, sig_b64 = token.split(".")
    # Corrupt the last character of the payload segment deterministically.
    swap = "A" if payload_b64[-1] != "A" else "B"
    tampered = f"{header_b64}.{payload_b64[:-1]}{swap}.{sig_b64}"
    request = _make_request(authorization=f"Bearer {tampered}", client_ip="192.0.2.77")

    assert _authenticated_user_key(request) == "192.0.2.77"


def test_unsigned_alg_none_token_buckets_by_ip(jwt_secret: str) -> None:
    """A `alg: none` token with a real user_id must NOT be trusted."""
    unsigned = pyjwt.encode(_valid_payload("nobody-should-trust-me"), key="", algorithm="none")
    request = _make_request(authorization=f"Bearer {unsigned}", client_ip="192.0.2.88")

    assert _authenticated_user_key(request) == "192.0.2.88"


def test_garbage_bearer_value_buckets_by_ip(jwt_secret: str) -> None:
    request = _make_request(authorization="Bearer not-even-a-jwt", client_ip="192.0.2.99")

    assert _authenticated_user_key(request) == "192.0.2.99"


def test_expired_token_buckets_by_ip(jwt_secret: str) -> None:
    payload = _valid_payload("expired-user")
    payload["exp"] = datetime.now(UTC) - timedelta(minutes=1)
    payload["iat"] = datetime.now(UTC) - timedelta(hours=1)
    expired = pyjwt.encode(payload, jwt_secret, algorithm=JWT_ALGORITHM)
    request = _make_request(authorization=f"Bearer {expired}", client_ip="192.0.2.111")

    assert _authenticated_user_key(request) == "192.0.2.111"


# ---------------------------------------------------------------------------
# (c) No Authorization header at all -> bucket by remote IP.
# ---------------------------------------------------------------------------


def test_no_authorization_header_buckets_by_ip(jwt_secret: str) -> None:
    request = _make_request(authorization=None, client_ip="203.0.113.42")

    assert _authenticated_user_key(request) == "203.0.113.42"


def test_non_bearer_authorization_scheme_buckets_by_ip(jwt_secret: str) -> None:
    """Basic auth or any non-Bearer scheme must not be treated as a JWT."""
    request = _make_request(authorization="Basic dXNlcjpwYXNz", client_ip="203.0.113.43")

    assert _authenticated_user_key(request) == "203.0.113.43"


# ---------------------------------------------------------------------------
# Circular-import sanity check: importing limiter must not blow up standalone.
# ---------------------------------------------------------------------------


def test_limiter_module_imports_cleanly() -> None:
    import importlib

    module = importlib.import_module("aila.api.limiter")
    assert hasattr(module, "limiter")
    assert callable(module._authenticated_user_key)
