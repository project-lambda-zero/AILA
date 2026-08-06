"""#36 -- API keys are team-scoped.

create stamps the creating admin's team; list and revoke are filtered so a
team-scoped admin cannot see or revoke another team's keys. A god-tier admin
(team_id=None, TEAM-06) sees and manages every team's keys. Handlers are
invoked directly with an explicit AuthContext (the require_role/limiter
dependencies are not resolved on direct invocation).
"""
from __future__ import annotations

import types
from uuid import uuid4

import pytest
from fastapi import HTTPException

from aila.api.auth import AuthContext
from aila.api.routers.auth import create_api_key, list_api_keys, revoke_api_key
from aila.api.schemas.auth import ApiKeyCreateRequest
from aila.storage.database import async_session_scope
from aila.storage.db_models import ApiKeyRecord

pytestmark = pytest.mark.asyncio


def _req() -> object:
    return types.SimpleNamespace(
        app=types.SimpleNamespace(state=types.SimpleNamespace(platform=None))
    )


def _auth(team_id: str | None, role: str = "admin") -> AuthContext:
    return AuthContext(
        user_id=f"u-{team_id}", role=role, auth_type="user", team_id=team_id
    )


async def _create(team_id: str | None) -> str:
    body = ApiKeyCreateRequest(role="operator", label=f"k-{uuid4().hex[:6]}")
    resp = await create_api_key(request=_req(), body=body, admin=_auth(team_id))
    return resp.key_id


@pytest.mark.usefixtures("test_db")
async def test_api_key_create_stamps_admin_team() -> None:
    key_id = await _create("team-a")
    async with async_session_scope() as session:
        rec = await session.get(ApiKeyRecord, key_id)
    assert rec is not None
    assert rec.team_id == "team-a"


@pytest.mark.usefixtures("test_db")
async def test_god_tier_key_is_team_less() -> None:
    key_id = await _create(None)
    async with async_session_scope() as session:
        rec = await session.get(ApiKeyRecord, key_id)
    assert rec is not None
    assert rec.team_id is None


@pytest.mark.usefixtures("test_db")
async def test_api_key_list_scoped_to_team() -> None:
    a = await _create("team-a")
    b = await _create("team-b")

    team_a = await list_api_keys(active_only=False, admin=_auth("team-a"))
    ids_a = {k.key_id for k in team_a.keys}
    assert a in ids_a
    assert b not in ids_a, "team-a admin must not see team-b's key"

    god = await list_api_keys(active_only=False, admin=_auth(None))
    ids_god = {k.key_id for k in god.keys}
    assert {a, b} <= ids_god, "god-tier admin sees every team's keys"


@pytest.mark.usefixtures("test_db")
async def test_api_key_revoke_blocked_cross_team() -> None:
    b = await _create("team-b")

    with pytest.raises(HTTPException) as exc:
        await revoke_api_key(request=_req(), key_id=b, admin=_auth("team-a"))
    assert exc.value.status_code == 404, "cross-team revoke must 404 (existence hidden)"

    resp = await revoke_api_key(request=_req(), key_id=b, admin=_auth("team-b"))
    assert resp.revoked is True
