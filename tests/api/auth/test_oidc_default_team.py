"""#36 -- OIDC provider default_team_id + the issued JWT carrying the user team.

An OIDC provider can be bound to a default team so auto-provisioned users are
scoped on first login. OIDC sign-in is refused for any account without a team,
so the JWT issued by the callback always carries the user's team.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import jwt
import pytest
from httpx import AsyncClient
from sqlmodel import select

from aila.api.auth import issue_user_jwt
from aila.api.routers.oidc import _make_state_jwt
from aila.storage.database import async_session_scope
from aila.storage.db_models import OIDCProviderRecord, UserRecord

_REDIRECT_URI = "http://localhost:3000/auth/callback"


def test_issue_user_jwt_carries_team_id() -> None:
    """The JWT reflects the team passed to issue_user_jwt."""
    scoped, _ = issue_user_jwt("u-scoped", "operator", team_id="team-x")
    claims = jwt.decode(scoped, options={"verify_signature": False})
    assert claims["team_id"] == "team-x"


@pytest.mark.asyncio
async def test_create_provider_persists_default_team_id(
    async_client: AsyncClient, admin_token: str
) -> None:
    resp = await async_client.post(
        "/auth/oidc/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "provider_name": "google-team",
            "provider_type": "google",
            "client_id": "google-client",
            "client_secret": "google-secret",
            "default_team_id": "team-x",
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["data"]["default_team_id"] == "team-x"


@pytest.mark.asyncio
async def test_create_provider_default_team_none_by_default(
    async_client: AsyncClient, admin_token: str
) -> None:
    resp = await async_client.post(
        "/auth/oidc/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "provider_name": "google-noteam",
            "provider_type": "google",
            "client_id": "google-client",
            "client_secret": "google-secret",
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["data"]["default_team_id"] is None


@pytest.mark.asyncio
async def test_update_provider_sets_default_team_id(
    async_client: AsyncClient, admin_token: str
) -> None:
    headers = {"Authorization": f"Bearer {admin_token}"}
    create = await async_client.post(
        "/auth/oidc/providers",
        headers=headers,
        json={
            "provider_name": "google-upd",
            "provider_type": "google",
            "client_id": "google-client",
            "client_secret": "google-secret",
        },
    )
    assert create.status_code == 201, create.text
    provider_id = create.json()["data"]["id"]

    upd = await async_client.put(
        f"/auth/oidc/providers/{provider_id}",
        headers=headers,
        json={"default_team_id": "team-y"},
    )
    assert upd.status_code == 200, upd.text
    assert upd.json()["data"]["default_team_id"] == "team-y"


# ---------------------------------------------------------------------------
# OIDC callback: team requirement
# ---------------------------------------------------------------------------


async def _seed_provider(default_team_id: str | None) -> str:
    provider_id = f"oidc-prov-{uuid4().hex[:8]}"
    async with async_session_scope() as session:
        session.add(
            OIDCProviderRecord(
                id=provider_id,
                provider_name=f"ms-{uuid4().hex[:8]}",
                provider_type="microsoft",
                tenant_id="test-tenant-id",
                client_id="test-client-id",
                client_secret_encrypted="test-secret",
                is_enabled=True,
                default_team_id=default_team_id,
            )
        )
        await session.commit()
    return provider_id


async def _seed_teamless_user(subject: str) -> None:
    async with async_session_scope() as session:
        session.add(
            UserRecord(
                username=f"teamless-{uuid4().hex[:8]}",
                oidc_sub=subject,
                role="operator",
                team_id=None,
                is_active=True,
            )
        )
        await session.commit()


async def _find_user(subject: str) -> UserRecord | None:
    async with async_session_scope() as session:
        result = await session.exec(select(UserRecord).where(UserRecord.oidc_sub == subject))
        return result.first()


async def _oidc_callback(client: AsyncClient, provider_id: str, subject: str):
    state_token = _make_state_jwt(_REDIRECT_URI, provider_id=provider_id)
    mock_app = MagicMock()
    mock_app.acquire_token_by_authorization_code.return_value = {
        "id_token_claims": {
            "sub": subject,
            "email": f"{subject}@example.com",
            "name": "Test User",
        },
        "access_token": "mock-access-token",
    }
    with patch("msal.ConfidentialClientApplication", return_value=mock_app), patch(
        "aila.api.routers.oidc._decrypt_client_secret",
        new=AsyncMock(return_value="decrypted-test-secret"),
    ):
        return await client.get(
            "/auth/oidc/callback",
            params={
                "code": "auth-code-default-team",
                "state": state_token,
                "redirect_uri": _REDIRECT_URI,
            },
            cookies={"oidc_state": state_token},
        )


@pytest.mark.asyncio
async def test_callback_refuses_new_subject_without_provider_team(
    async_client: AsyncClient,
) -> None:
    provider_id = await _seed_provider(default_team_id=None)
    subject = f"oidc-noteam-{uuid4().hex[:8]}"

    resp = await _oidc_callback(async_client, provider_id, subject)

    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"] == (
        "OIDC sign-in requires a team. Set a default team on this identity provider."
    )
    assert await _find_user(subject) is None


@pytest.mark.asyncio
async def test_callback_refuses_existing_teamless_user(async_client: AsyncClient) -> None:
    provider_id = await _seed_provider(default_team_id=f"team-{uuid4().hex[:8]}")
    subject = f"oidc-legacy-{uuid4().hex[:8]}"
    await _seed_teamless_user(subject)

    resp = await _oidc_callback(async_client, provider_id, subject)

    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"] == (
        "This account has no team. Ask an administrator to assign one before "
        "signing in with OIDC."
    )
    assert "data" not in resp.json()


@pytest.mark.asyncio
async def test_callback_with_provider_team_issues_scoped_token(
    async_client: AsyncClient,
) -> None:
    team_id = f"team-{uuid4().hex[:8]}"
    provider_id = await _seed_provider(default_team_id=team_id)
    subject = f"oidc-scoped-{uuid4().hex[:8]}"

    resp = await _oidc_callback(async_client, provider_id, subject)

    assert resp.status_code == 200, resp.text
    user = await _find_user(subject)
    assert user is not None
    assert user.team_id == team_id
    claims = jwt.decode(resp.json()["data"]["access_token"], options={"verify_signature": False})
    assert claims["team_id"] == team_id
