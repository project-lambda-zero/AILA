"""#57 IDOR guard for the platform systems + tags routers.

ManagedSystemRecord is team-scoped, but the systems and tags routers loaded
rows with session.get (which bypasses the do_orm_execute team filter) inside
bare async_session_scope() and checked only for None. Any authenticated
principal could therefore read, update, delete, or enumerate another team's
SSH systems by id. get_system_heartbeat additionally returned a shared cached
probe result before any ownership check.

These tests invoke the real route endpoints against the Postgres test_db with
a non-admin team-A identity and assert 404 across the team boundary, plus that
list_systems only returns the caller's team. The slowapi limiter is disabled
process-wide by the autouse fixture; require_role/require_user_or_api_key
dependencies are not resolved on direct invocation, so auth is passed
explicitly.
"""
from __future__ import annotations

import types
from uuid import uuid4

import pytest
from fastapi import HTTPException

from aila.api.auth import AuthContext
from aila.api.routers.systems import router as systems_router
from aila.api.routers.tags import router as tags_router
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord


def _req() -> object:
    return types.SimpleNamespace(
        app=types.SimpleNamespace(state=types.SimpleNamespace(platform=None))
    )


class _StubModule:
    async def list_system_tags(self, system_id: int, session: object) -> list:
        return []


class _StubRegistry:
    def require(self, name: str) -> object:
        return _StubModule()


def _req_with_platform() -> object:
    """Request whose platform is present so the tags handler reaches the
    ownership check instead of short-circuiting on a 503."""
    platform = types.SimpleNamespace(
        runtime=types.SimpleNamespace(module_registry=_StubRegistry())
    )
    return types.SimpleNamespace(
        app=types.SimpleNamespace(state=types.SimpleNamespace(platform=platform))
    )


def _endpoint(router: object, path: str, method: str):
    for route in router.routes:
        if getattr(route, "path", None) == path and method in getattr(route, "methods", set()):
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


def _auth(team_id: str, role: str = "operator") -> AuthContext:
    return AuthContext(
        user_id="u-" + team_id, role=role, auth_type="user", team_id=team_id
    )


async def _seed_two() -> tuple[str, str, int, int]:
    suffix = uuid4().hex[:8]
    team_a = f"team-a-{suffix}"
    team_b = f"team-b-{suffix}"
    async with async_session_scope() as session:  # admin => unfiltered insert
        a = ManagedSystemRecord(
            team_id=team_a, name=f"sys-a-{suffix}", host="10.0.0.1", username="u"
        )
        b = ManagedSystemRecord(
            team_id=team_b, name=f"sys-b-{suffix}", host="10.0.0.2", username="u"
        )
        session.add(a)
        session.add(b)
        await session.commit()
        await session.refresh(a)
        await session.refresh(b)
        return team_a, team_b, a.id, b.id


async def test_get_system_cross_team_is_404(test_db) -> None:
    team_a, _tb, _a_id, b_id = await _seed_two()
    get_system = _endpoint(systems_router, "/systems/{system_id}", "GET")
    with pytest.raises(HTTPException) as exc:
        await get_system(system_id=b_id, request=_req(), auth=_auth(team_a))
    assert exc.value.status_code == 404


async def test_get_system_own_team_ok(test_db) -> None:
    team_a, _tb, a_id, _b_id = await _seed_two()
    get_system = _endpoint(systems_router, "/systems/{system_id}", "GET")
    resp = await get_system(system_id=a_id, request=_req(), auth=_auth(team_a))
    assert resp.id == a_id


async def test_get_connectivity_cross_team_is_404(test_db) -> None:
    team_a, _tb, _a_id, b_id = await _seed_two()
    conn = _endpoint(systems_router, "/systems/{system_id}/connectivity", "GET")
    with pytest.raises(HTTPException) as exc:
        await conn(system_id=b_id, request=_req(), auth=_auth(team_a))
    assert exc.value.status_code == 404


async def test_get_scans_cross_team_is_404(test_db) -> None:
    team_a, _tb, _a_id, b_id = await _seed_two()
    scans = _endpoint(systems_router, "/systems/{system_id}/scans", "GET")
    with pytest.raises(HTTPException) as exc:
        await scans(system_id=b_id, auth=_auth(team_a))
    assert exc.value.status_code == 404


async def test_delete_system_cross_team_is_404(test_db) -> None:
    team_a, _tb, _a_id, b_id = await _seed_two()
    delete_system = _endpoint(systems_router, "/systems/{system_id}", "DELETE")
    with pytest.raises(HTTPException) as exc:
        await delete_system(request=_req(), system_id=b_id, auth=_auth(team_a))
    assert exc.value.status_code == 404
    async with async_session_scope() as session:
        row = await session.get(ManagedSystemRecord, b_id)
    assert row is not None  # cross-team delete must not have removed it


async def test_list_systems_only_own_team(test_db) -> None:
    team_a, _tb, a_id, b_id = await _seed_two()
    list_systems = _endpoint(systems_router, "/systems", "GET")
    resp = await list_systems(request=_req(), page=1, page_size=50, auth=_auth(team_a))
    ids = {item.id for item in resp.items}
    assert a_id in ids
    assert b_id not in ids


async def test_list_system_tags_cross_team_is_404(test_db) -> None:
    team_a, _tb, _a_id, b_id = await _seed_two()
    list_tags = _endpoint(tags_router, "/tags/systems/{system_id}", "GET")
    with pytest.raises(HTTPException) as exc:
        await list_tags(request=_req_with_platform(), system_id=b_id, auth=_auth(team_a))
    assert exc.value.status_code == 404
