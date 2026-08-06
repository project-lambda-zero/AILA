"""#36 -- OIDC provider default_team_id + the issued JWT carrying the user team.

An OIDC provider can be bound to a default team so auto-provisioned users are
scoped on first login, and the JWT issued after the callback carries the user's
team (a team-assigned OIDC user was previously handed a god-tier token).
"""
from __future__ import annotations

import jwt
import pytest
from httpx import AsyncClient

from aila.api.auth import issue_user_jwt


def test_issue_user_jwt_carries_team_id() -> None:
    """The JWT reflects the team passed to issue_user_jwt (the OIDC callback
    now passes the user's team). Without a team the claim is None (god-tier)."""
    scoped, _ = issue_user_jwt("u-scoped", "operator", team_id="team-x")
    claims = jwt.decode(scoped, options={"verify_signature": False})
    assert claims["team_id"] == "team-x"

    god, _ = issue_user_jwt("u-god", "operator")
    claims_god = jwt.decode(god, options={"verify_signature": False})
    assert claims_god["team_id"] is None


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
