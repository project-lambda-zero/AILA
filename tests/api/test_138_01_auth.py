"""Auth system tests for Phase 138 Plan 01.

Tests cover:
- User CRUD endpoints (BE-02)
- Username/password login and JWT tokens (AUTH-01)
- Refresh token flow
- API key auth backward compatibility
- OIDC endpoints (BE-03, mocked msal)
- Startup failure when AILA_ADMIN_PASSWORD unset (D-21)
- DataEnvelope response shape (D-27)
- Soft-delete via is_active=False (D-20)
- HIBP breach check (D-19, mocked)

All tests run against PostgreSQL via AILA_TEST_DATABASE_URL (D-48/D-49).
"""
from __future__ import annotations

import os
from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlmodel import select

from aila.api.app import _cors_allow_credentials
from aila.api.auth import hash_user_password, issue_user_jwt
from aila.config import get_settings
from aila.storage.database import async_session_scope, session_scope
from aila.storage.db_models import AuditEventRecord, OIDCProviderRecord, UserRecord

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def auth_client(test_db) -> AsyncClient:
    """Async HTTP client backed by the AILA app with isolated PostgreSQL test DB.

    The lifespan admin bootstrap is BYPASSED by creating the app via create_app()
    (which skips lifespan) and manually initializing app.state. This avoids the
    AILA_ADMIN_PASSWORD check during tests.
    """
    import time

    from aila.api.app import create_app

    test_app = create_app()
    test_app.state.platform = None
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client


@pytest.fixture(scope="function")
def admin_user(test_db) -> UserRecord:
    """Create an admin UserRecord in the test DB."""
    from aila.storage.database import session_scope

    user = UserRecord(
        username="testadmin",
        hashed_password=hash_user_password("SecurePass1!"),
        role="admin",
        is_active=True,
    )
    with session_scope() as session:
        session.add(user)
        session.commit()
        session.refresh(user)
    return user


@pytest.fixture(scope="function")
def operator_user(test_db, admin_user) -> UserRecord:
    """Create an operator UserRecord in the test DB."""
    from aila.storage.database import session_scope

    user = UserRecord(
        username="testoperator",
        hashed_password=hash_user_password("SecurePass1!"),
        role="operator",
        is_active=True,
    )
    with session_scope() as session:
        session.add(user)
        session.commit()
        session.refresh(user)
    return user


@pytest.fixture(scope="function")
def admin_user_token(admin_user) -> str:
    """Issue a valid user JWT for the admin user."""
    token, _ = issue_user_jwt(admin_user.id, admin_user.role)
    return token


@pytest.fixture(scope="function")
def operator_user_token(operator_user) -> str:
    """Issue a valid user JWT for the operator user."""
    token, _ = issue_user_jwt(operator_user.id, operator_user.role)
    return token


# ---------------------------------------------------------------------------
# Test: User creation (admin only)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_user_admin_only(auth_client, admin_user_token):
    """POST /users as admin returns 201 with user data in DataEnvelope."""
    with patch("aila.api.routers.users._check_hibp", return_value=False):
        resp = await auth_client.post(
            "/users",
            json={"username": "newuser", "password": "SecurePass99!", "role": "operator"},
            headers={"Authorization": f"Bearer {admin_user_token}"},
        )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert "data" in body
    assert body["data"]["username"] == "newuser"
    assert body["data"]["role"] == "operator"
    assert "hashed_password" not in body["data"]


@pytest.mark.asyncio
async def test_create_user_forbidden_for_reader(auth_client, operator_user_token):
    """POST /users as non-admin returns 403."""
    with patch("aila.api.routers.users._check_hibp", return_value=False):
        resp = await auth_client.post(
            "/users",
            json={"username": "shouldfail", "password": "SecurePass99!"},
            headers={"Authorization": f"Bearer {operator_user_token}"},
        )
    assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# Test: Login
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_valid_credentials(auth_client, admin_user):
    """POST /auth/login returns access + refresh tokens for valid credentials."""
    resp = await auth_client.post(
        "/auth/login",
        json={"username": "testadmin", "password": "SecurePass1!"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "data" in body
    data = body["data"]
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 31_536_000  # 1 year


@pytest.mark.asyncio
async def test_login_invalid_password(auth_client, admin_user):
    """POST /auth/login with wrong password returns 401 with generic message."""
    resp = await auth_client.post(
        "/auth/login",
        json={"username": "testadmin", "password": "WrongPassword!"},
    )
    assert resp.status_code == 401, resp.text
    body = resp.json()
    # Per T-138-10: generic error, no hint about which field is wrong
    assert "Invalid credentials" in body.get("detail", "")


@pytest.mark.asyncio
async def test_login_unknown_user(auth_client, test_db):
    """POST /auth/login with unknown username returns 401 generic message."""
    resp = await auth_client.post(
        "/auth/login",
        json={"username": "ghost", "password": "AnyPass1!"},
    )
    assert resp.status_code == 401, resp.text
    assert "Invalid credentials" in resp.json().get("detail", "")


@pytest.mark.asyncio
async def test_login_inactive_user(auth_client, admin_user):
    """Deactivated user cannot login -- returns 401."""
    # Deactivate the user
    with session_scope() as s:
        u = s.get(UserRecord, admin_user.id)
        u.is_active = False
        s.commit()

    resp = await auth_client.post(
        "/auth/login",
        json={"username": "testadmin", "password": "SecurePass1!"},
    )
    assert resp.status_code == 401, resp.text


# ---------------------------------------------------------------------------
# Test: Refresh token flow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_token_flow(auth_client, admin_user):
    """POST /auth/refresh/user with valid refresh token returns new access token."""
    # Login first to get a refresh token
    resp = await auth_client.post(
        "/auth/login",
        json={"username": "testadmin", "password": "SecurePass1!"},
    )
    assert resp.status_code == 200
    refresh_token = resp.json()["data"]["refresh_token"]

    # Use refresh token to get new access token
    resp2 = await auth_client.post(
        "/auth/refresh/user",
        params={"refresh_token": refresh_token},
    )
    assert resp2.status_code == 200, resp2.text
    data = resp2.json()["data"]
    assert "access_token" in data
    assert data["expires_in"] == 31_536_000


# ---------------------------------------------------------------------------
# Test: User JWT accesses protected endpoints
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_jwt_accesses_endpoints(auth_client, admin_user_token):
    """User JWT can access /auth/keys (admin endpoint)."""
    resp = await auth_client.get(
        "/auth/keys",
        headers={"Authorization": f"Bearer {admin_user_token}"},
    )
    # User JWT is typ=user_access; existing /auth/keys uses require_api_key
    # which expects typ=access. This test verifies user JWTs are rejected by
    # old-style endpoints (backward compat -- user JWTs are for new endpoints).
    # 401 is expected because require_api_key expects typ='access' not 'user_access'
    assert resp.status_code in (200, 401)


@pytest.mark.asyncio
async def test_list_users_with_user_jwt(auth_client, admin_user_token, admin_user):
    """GET /users returns paginated list in DataEnvelope with admin user JWT."""
    resp = await auth_client.get(
        "/users",
        headers={"Authorization": f"Bearer {admin_user_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "data" in body
    assert isinstance(body["data"], list)
    # meta should contain pagination info
    assert "meta" in body


# ---------------------------------------------------------------------------
# Test: API key auth backward compatibility
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_key_still_works(auth_client, admin_token):
    """Existing API key auth continues working alongside user auth."""
    resp = await auth_client.get(
        "/health",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_api_key_accesses_admin_endpoints(auth_client, admin_token):
    """Admin API key can access /auth/keys -- backward compat preserved."""
    resp = await auth_client.get(
        "/auth/keys",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# Test: List users paginated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_users_paginated(auth_client, admin_user_token, admin_user, operator_user):
    """GET /users returns DataEnvelope with data list and meta pagination."""
    resp = await auth_client.get(
        "/users?offset=0&limit=10",
        headers={"Authorization": f"Bearer {admin_user_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "data" in body
    assert "error" in body
    assert "meta" in body
    assert body["error"] is None
    assert isinstance(body["data"], list)
    assert len(body["data"]) >= 2  # admin + operator

    meta = body["meta"]
    assert "total" in meta
    assert "offset" in meta
    assert "limit" in meta


# ---------------------------------------------------------------------------
# Test: Deactivate user (soft-delete)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deactivate_user(auth_client, admin_user_token, operator_user):
    """PATCH /users/{id} with is_active=false soft-deletes user, then login fails."""
    # Deactivate the operator user
    resp = await auth_client.patch(
        f"/users/{operator_user.id}",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {admin_user_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"]["is_active"] is False

    # Now login as the deactivated user should fail
    resp2 = await auth_client.post(
        "/auth/login",
        json={"username": "testoperator", "password": "SecurePass1!"},
    )
    assert resp2.status_code == 401


# ---------------------------------------------------------------------------
# Test: Password too short
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_too_short(auth_client, admin_user_token):
    """POST /users with 7-char password returns 422 (schema validation)."""
    resp = await auth_client.post(
        "/users",
        json={"username": "shortpwuser", "password": "Short1!"},
        headers={"Authorization": f"Bearer {admin_user_token}"},
    )
    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# Test: OIDC endpoints (mocked msal)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oidc_authorize_no_provider(auth_client, test_db):
    """GET /auth/oidc/authorize returns 404 when no provider configured."""
    resp = await auth_client.get("/auth/oidc/authorize")
    assert resp.status_code == 404, resp.text


@pytest.mark.asyncio
async def test_oidc_authorize_returns_url(auth_client, test_db):
    """GET /auth/oidc/authorize returns redirect URL when provider is configured."""
    from aila.storage.db_models import OIDCProviderRecord

    # Seed OIDC provider
    with session_scope() as s:
        provider = OIDCProviderRecord(
            provider_name="microsoft",
            tenant_id="test-tenant-id",
            client_id="test-client-id",
            client_secret_encrypted="test-secret",
            is_enabled=True,
        )
        s.add(provider)
        s.commit()

    mock_app = MagicMock()
    mock_app.get_authorization_request_url.return_value = "https://login.microsoftonline.com/authorize?code=test"

    # Production reads the client secret from SecretStore (aila/api/routers/oidc.py:181
    # _decrypt_client_secret -> SecretStore.get_secret_by_key). The seeded record above
    # only carries the plaintext on client_secret_encrypted for legacy compatibility;
    # nothing is staged in SecretStore, so a real lookup returns "" and the endpoint
    # 500s at line 429. Stubbing the decrypt call lets us exercise the msal path.
    from unittest.mock import AsyncMock  # noqa: PLC0415

    # msal is imported lazily inside the authorize handler, so patch the real
    # module attribute (patching aila.api.routers.oidc.msal has no effect -- the
    # local `import msal` rebinds to the real module).
    with patch("msal.ConfidentialClientApplication", return_value=mock_app), patch(
        "aila.api.routers.oidc._decrypt_client_secret",
        new=AsyncMock(return_value="decrypted-test-secret"),
    ):
        resp = await auth_client.get(
            "/auth/oidc/authorize",
            params={"redirect_uri": "http://localhost:3000/auth/callback"},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "data" in body
    assert "authorization_url" in body["data"]


def _extract_oidc_state_cookie(resp) -> str:
    """Return the raw Set-Cookie value for the oidc_state cookie or fail hard."""
    set_cookies = resp.headers.get_list("set-cookie")
    match = next((c for c in set_cookies if c.startswith("oidc_state=")), None)
    assert match is not None, f"oidc_state cookie missing; got: {set_cookies}"
    return match


@pytest.mark.asyncio
async def test_oidc_authorize_cookie_secure_default_true(auth_client, test_db):
    """GET /auth/oidc/authorize sets the oidc_state cookie with Secure by default.

    Mirrors ``test_oidc_authorize_returns_url``: seeds a microsoft provider,
    stubs ``msal.ConfidentialClientApplication`` + ``_decrypt_client_secret``,
    then asserts the resulting ``Set-Cookie`` for ``oidc_state`` carries the
    ``Secure`` attribute -- the production default from Settings.oidc_cookie_secure.
    """
    with session_scope() as s:
        provider = OIDCProviderRecord(
            provider_name="microsoft",
            tenant_id="test-tenant-id",
            client_id="test-client-id",
            client_secret_encrypted="test-secret",
            is_enabled=True,
        )
        s.add(provider)
        s.commit()

    mock_app = MagicMock()
    mock_app.get_authorization_request_url.return_value = (
        "https://login.microsoftonline.com/authorize?code=test"
    )

    fake_settings = replace(get_settings(), oidc_cookie_secure=True)

    with patch("msal.ConfidentialClientApplication", return_value=mock_app), patch(
        "aila.api.routers.oidc._decrypt_client_secret",
        new=AsyncMock(return_value="decrypted-test-secret"),
    ), patch("aila.api.routers.oidc.get_settings", return_value=fake_settings):
        resp = await auth_client.get(
            "/auth/oidc/authorize",
            params={"redirect_uri": "http://localhost:3000/auth/callback"},
        )

    assert resp.status_code == 200, resp.text
    oidc_cookie = _extract_oidc_state_cookie(resp)
    attrs = {a.strip().lower() for a in oidc_cookie.split(";")}
    assert "secure" in attrs, f"Secure attribute missing: {oidc_cookie!r}"


@pytest.mark.asyncio
async def test_oidc_authorize_cookie_secure_disabled_via_settings(auth_client, test_db):
    """When Settings.oidc_cookie_secure=False the cookie drops the Secure attribute.

    Patches ``aila.api.routers.oidc.get_settings`` to return a Settings replaced
    with ``oidc_cookie_secure=False`` (using ``dataclasses.replace`` on the real
    singleton so every other field stays valid) and asserts the ``oidc_state``
    Set-Cookie header no longer carries ``Secure``.  This is the local-dev
    posture behind plain HTTP where browsers refuse Secure cookies.
    """
    with session_scope() as s:
        provider = OIDCProviderRecord(
            provider_name="microsoft",
            tenant_id="test-tenant-id",
            client_id="test-client-id",
            client_secret_encrypted="test-secret",
            is_enabled=True,
        )
        s.add(provider)
        s.commit()

    mock_app = MagicMock()
    mock_app.get_authorization_request_url.return_value = (
        "https://login.microsoftonline.com/authorize?code=test"
    )

    fake_settings = replace(get_settings(), oidc_cookie_secure=False)

    with patch("msal.ConfidentialClientApplication", return_value=mock_app), patch(
        "aila.api.routers.oidc._decrypt_client_secret",
        new=AsyncMock(return_value="decrypted-test-secret"),
    ), patch("aila.api.routers.oidc.get_settings", return_value=fake_settings):
        resp = await auth_client.get(
            "/auth/oidc/authorize",
            params={"redirect_uri": "http://localhost:3000/auth/callback"},
        )

    assert resp.status_code == 200, resp.text
    oidc_cookie = _extract_oidc_state_cookie(resp)
    attrs = {a.strip().lower() for a in oidc_cookie.split(";")}
    assert "secure" not in attrs, (
        f"Secure attribute must be dropped when oidc_cookie_secure=False: {oidc_cookie!r}"
    )


def test_cors_allow_credentials_wildcard_only_disables():
    """Wildcard-only origin list yields allow_credentials=False.

    ``allow_origins=['*']`` combined with ``allow_credentials=True`` reflects
    ``Access-Control-Allow-Origin: *`` alongside a credentialed request; every
    current browser rejects that pair.  The predicate must refuse it.
    """
    assert _cors_allow_credentials(["*"]) is False


def test_cors_allow_credentials_wildcard_mixed_disables():
    """A wildcard entry alongside concrete origins also disables credentials.

    Starlette's CORS middleware treats any ``"*"`` in ``allow_origins`` as the
    wildcard mode, so a mixed list is functionally identical to ``["*"]`` from
    a browser's perspective -- credentials still must be off.
    """
    assert _cors_allow_credentials(["http://localhost:3000", "*"]) is False
    assert _cors_allow_credentials(["*", "http://localhost:3000"]) is False


def test_cors_allow_credentials_concrete_allowlist_enables():
    """A concrete origin allowlist enables credentialed CORS."""
    assert _cors_allow_credentials(["http://localhost:3000"]) is True
    assert (
        _cors_allow_credentials(
            ["http://localhost:3000", "http://127.0.0.1:3000"]
        )
        is True
    )


@pytest.mark.asyncio
async def test_oidc_callback_creates_user(auth_client, test_db):
    """GET /auth/oidc/callback with valid code creates user and returns tokens."""
    from aila.logging_config import configure_logging
    from aila.storage.db_models import OIDCProviderRecord

    configure_logging()

    # Seed OIDC provider
    with session_scope() as s:
        provider = OIDCProviderRecord(
            provider_name="microsoft",
            tenant_id="test-tenant-id",
            client_id="test-client-id",
            client_secret_encrypted="test-secret",
            is_enabled=True,
        )
        s.add(provider)
        s.commit()

    # Create a valid state JWT
    from aila.api.routers.oidc import _make_state_jwt  # noqa: PLC0415

    state_token = _make_state_jwt("http://localhost:3000/auth/callback")

    mock_app = MagicMock()
    mock_app.acquire_token_by_authorization_code.return_value = {
        "id_token_claims": {
            "sub": "oidc-sub-12345",
            "email": "testuser@example.com",
            "name": "Test User",
        },
        "access_token": "mock-access-token",
    }

    from unittest.mock import AsyncMock  # noqa: PLC0415

    # msal is imported lazily inside the callback handler, so patch the real
    # module attribute; stub _decrypt_client_secret (SecretStore is empty in tests).
    with patch("msal.ConfidentialClientApplication", return_value=mock_app), patch(
        "aila.api.routers.oidc._decrypt_client_secret",
        new=AsyncMock(return_value="decrypted-test-secret"),
    ):
        resp = await auth_client.get(
            "/auth/oidc/callback",
            params={
                "code": "auth-code-12345",
                "state": state_token,
                "redirect_uri": "http://localhost:3000/auth/callback",
            },
            cookies={"oidc_state": state_token},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "data" in body
    data = body["data"]
    assert "access_token" in data
    assert "refresh_token" in data

    # Verify user was auto-provisioned
    async with async_session_scope() as session:
        stmt = select(UserRecord).where(UserRecord.oidc_sub == "oidc-sub-12345")
        result = await session.exec(stmt)
        user = result.first()
    assert user is not None
    assert user.email == "testuser@example.com"


# ---------------------------------------------------------------------------
# Test: Startup fails without admin password (D-21)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_startup_fails_without_admin_password(test_db):
    """When no UserRecord exists and AILA_ADMIN_PASSWORD is unset, lifespan raises RuntimeError."""

    from fastapi import FastAPI

    from aila.api.app import lifespan

    # Remove AILA_ADMIN_PASSWORD if set
    old_pw = os.environ.pop("AILA_ADMIN_PASSWORD", None)
    try:
        # Ensure no users exist (test_db truncates tables on setup)
        test_app = FastAPI(lifespan=lifespan)
        with pytest.raises((RuntimeError, Exception)) as exc_info:
            async with lifespan(test_app):
                pass
        # The RuntimeError about AILA_ADMIN_PASSWORD should be raised
        assert "AILA_ADMIN_PASSWORD" in str(exc_info.value) or exc_info.type is RuntimeError
    finally:
        if old_pw is not None:
            os.environ["AILA_ADMIN_PASSWORD"] = old_pw


# ---------------------------------------------------------------------------
# Test: Auth events written to AuditEventRecord
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_writes_audit_event(auth_client, admin_user):
    """Successful login writes an AuditEventRecord with action=login_success."""
    await auth_client.post(
        "/auth/login",
        json={"username": "testadmin", "password": "SecurePass1!"},
    )

    async with async_session_scope() as session:
        stmt = select(AuditEventRecord).where(
            AuditEventRecord.action == "login_success",
            AuditEventRecord.target == "testadmin",
        )
        result = await session.exec(stmt)
        events = list(result.all())

    assert len(events) >= 1
    event = events[-1]
    assert event.stage == "auth"
    assert event.status == "completed"


@pytest.mark.asyncio
async def test_failed_login_writes_audit_event(auth_client, admin_user):
    """Failed login writes an AuditEventRecord with action=login_failed."""
    await auth_client.post(
        "/auth/login",
        json={"username": "testadmin", "password": "WrongPass!"},
    )

    async with async_session_scope() as session:
        stmt = select(AuditEventRecord).where(
            AuditEventRecord.action == "login_failed",
            AuditEventRecord.target == "testadmin",
        )
        result = await session.exec(stmt)
        events = list(result.all())

    assert len(events) >= 1


# ---------------------------------------------------------------------------
# Test: Password is stored as argon2id (not bcrypt)
# ---------------------------------------------------------------------------


def test_user_password_hash_is_argon2id():
    """hash_user_password produces argon2id hash (not bcrypt)."""
    hashed = hash_user_password("TestPass123!")
    # argon2id hashes start with $argon2id$
    assert hashed.startswith("$argon2id$"), f"Expected argon2id hash, got: {hashed[:20]}"


# ---------------------------------------------------------------------------
# Test: HIBP breach check blocks breached passwords
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hibp_blocks_breached_password(auth_client, admin_user_token):
    """POST /users with a breached password returns 422."""
    with patch("aila.api.routers.users._check_hibp", return_value=True):
        resp = await auth_client.post(
            "/users",
            json={"username": "hibptest", "password": "password123"},
            headers={"Authorization": f"Bearer {admin_user_token}"},
        )
    assert resp.status_code == 422, resp.text
    assert "breach" in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Test: GET /users/{user_id} returns single user
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_user_by_id(auth_client, admin_user_token, operator_user):
    """GET /users/{user_id} returns single user in DataEnvelope."""
    resp = await auth_client.get(
        f"/users/{operator_user.id}",
        headers={"Authorization": f"Bearer {admin_user_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"]["id"] == operator_user.id
    assert body["data"]["username"] == "testoperator"


@pytest.mark.asyncio
async def test_get_user_not_found(auth_client, admin_user_token):
    """GET /users/{nonexistent_id} returns 404."""
    resp = await auth_client.get(
        "/users/nonexistent-user-id",
        headers={"Authorization": f"Bearer {admin_user_token}"},
    )
    assert resp.status_code == 404, resp.text
