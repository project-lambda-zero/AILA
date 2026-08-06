"""#36 -- user management endpoints are team-scoped.

_admin_router mounted GET/POST /users and GET/PATCH /users/{user_id} behind
_require_admin, but did NOT distinguish a god-tier admin (team_id=None,
TEAM-06) from a team-scoped admin, so a team-scoped admin could list every
team's users and read or mutate a user in any other team. UserRecord is
team-scoped (user_records) and TeamScopedMixin populates the team_id column
at create time. Each endpoint now:

  * list_users -- adds ``WHERE team_id = auth.team_id`` to the count and
    list statements when the caller is team-scoped (both are plain selects
    that bypass the do_orm_execute listener).
  * get_user -- returns 404 (never 403, so no cross-tenant existence
    oracle) when the target row's team differs from the caller's.
  * create_user -- forces the new user's team_id to the caller's team when
    the caller is team-scoped; a god-tier admin retains the ability to set
    an arbitrary team_id, including None.
  * update_user -- applies the same 404 gate before mutating.

Handlers are invoked directly with an explicit AuthContext because the
router-level dependency stack (require_user_or_api_key, _require_admin)
is not resolved on a direct call. Query-default and dependency-default
params are passed explicitly so their FieldInfo sentinels never leak into
the body. The slowapi limiter is disabled by the autouse fixture in
tests/api/conftest.py.
"""
from __future__ import annotations

import types
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from aila.api.auth import AuthContext
from aila.api.routers.users import router as users_router
from aila.api.schemas.users import UserCreateRequest, UserUpdateRequest
from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import UserRecord


def _auth(team_id: str | None) -> AuthContext:
    return AuthContext(
        user_id="admin-" + (team_id or "god"),
        role="admin",
        auth_type="user",
        team_id=team_id,
    )


def _endpoint(path: str, method: str):
    for route in users_router.routes:
        if getattr(route, "path", None) == path and method in getattr(
            route, "methods", set()
        ):
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered on users router")


def _stub_request() -> types.SimpleNamespace:
    """A bare request object -- the raw handlers never dereference request.*."""
    return types.SimpleNamespace(
        app=types.SimpleNamespace(state=types.SimpleNamespace(platform=None)),
        client=None,
        headers={},
    )


async def _seed_user(team_id: str | None, username: str) -> str:
    """Insert one UserRecord bypassing the team-scope listener; return its id."""
    async with async_session_scope() as session:  # no team_context => unfiltered
        rec = UserRecord(
            username=username,
            email=f"{username}@example.test",
            hashed_password=None,
            role="operator",
            group_id=None,
            team_id=team_id,
            is_active=True,
            created_at=utc_now(),
            updated_at=utc_now(),
        )
        session.add(rec)
        await session.commit()
        await session.refresh(rec)
        return rec.id


async def _list(auth: AuthContext):
    ep = _endpoint("/users", "GET")
    return await ep(offset=0, limit=250, caller=auth)


# ---------------------------------------------------------------------------
# GET /users -- list scoping
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_list_users_scoped_to_team() -> None:
    ua = f"ua-{uuid4().hex[:6]}"
    ub = f"ub-{uuid4().hex[:6]}"
    await _seed_user("team-a", ua)
    await _seed_user("team-b", ub)

    env = await _list(_auth("team-a"))
    usernames = {u.username for u in env.data}
    assert ua in usernames
    assert ub not in usernames
    # meta.total must also be scoped -- the count statement bypasses the
    # do_orm_execute listener, so it needs its own team predicate.
    assert env.meta["total"] == sum(1 for u in env.data)


@pytest.mark.usefixtures("test_db")
async def test_list_users_god_tier_sees_all_teams() -> None:
    ua = f"ua-{uuid4().hex[:6]}"
    ub = f"ub-{uuid4().hex[:6]}"
    uc = f"uc-{uuid4().hex[:6]}"
    await _seed_user("team-a", ua)
    await _seed_user("team-b", ub)
    await _seed_user(None, uc)

    env = await _list(_auth(None))
    usernames = {u.username for u in env.data}
    assert ua in usernames
    assert ub in usernames
    assert uc in usernames


# ---------------------------------------------------------------------------
# GET /users/{user_id} -- cross-team 404
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_get_user_cross_team_is_404() -> None:
    target_id = await _seed_user("team-b", f"ub-{uuid4().hex[:6]}")
    ep = _endpoint("/users/{user_id}", "GET")

    with pytest.raises(HTTPException) as exc:
        await ep(user_id=target_id, caller=_auth("team-a"))
    assert exc.value.status_code == 404


@pytest.mark.usefixtures("test_db")
async def test_get_user_same_team_visible() -> None:
    target_id = await _seed_user("team-a", f"ua-{uuid4().hex[:6]}")
    ep = _endpoint("/users/{user_id}", "GET")

    env = await ep(user_id=target_id, caller=_auth("team-a"))
    assert env.data.id == target_id
    assert env.data.team_id == "team-a"


@pytest.mark.usefixtures("test_db")
async def test_get_user_god_tier_sees_any_team() -> None:
    target_id = await _seed_user("team-b", f"ub-{uuid4().hex[:6]}")
    ep = _endpoint("/users/{user_id}", "GET")

    env = await ep(user_id=target_id, caller=_auth(None))
    assert env.data.id == target_id
    assert env.data.team_id == "team-b"


# ---------------------------------------------------------------------------
# POST /users -- team-scoped admin cannot cross-team-create
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_create_user_team_scoped_admin_forces_own_team() -> None:
    ep = _endpoint("/users", "POST")
    username = f"new-{uuid4().hex[:6]}"
    body = UserCreateRequest(
        username=username,
        password="Str0ngPassw0rd!xyz",
        email=f"{username}@example.test",
        role="operator",
        group_id=None,
        team_id="team-b",  # attempt to place the new user in another team
    )

    with patch(
        "aila.api.routers.users._check_hibp", return_value=False
    ):
        env = await ep(
            request=_stub_request(),
            body=body,
            caller=_auth("team-a"),
        )
    # Response reports the caller's team, not the body's team.
    assert env.data.team_id == "team-a"

    # Persisted row stamps the caller's team.
    async with async_session_scope() as session:
        row = await session.get(UserRecord, env.data.id)
    assert row is not None
    assert row.team_id == "team-a"


@pytest.mark.usefixtures("test_db")
async def test_create_user_god_tier_may_set_any_team() -> None:
    ep = _endpoint("/users", "POST")
    username = f"new-{uuid4().hex[:6]}"
    body = UserCreateRequest(
        username=username,
        password="Str0ngPassw0rd!xyz",
        email=f"{username}@example.test",
        role="operator",
        group_id=None,
        team_id="team-b",
    )

    with patch(
        "aila.api.routers.users._check_hibp", return_value=False
    ):
        env = await ep(
            request=_stub_request(),
            body=body,
            caller=_auth(None),
        )
    assert env.data.team_id == "team-b"

    async with async_session_scope() as session:
        row = await session.get(UserRecord, env.data.id)
    assert row is not None
    assert row.team_id == "team-b"


@pytest.mark.usefixtures("test_db")
async def test_create_user_god_tier_may_create_admin_owned_user() -> None:
    """A god-tier admin passing team_id=None creates an admin-owned user."""
    ep = _endpoint("/users", "POST")
    username = f"new-{uuid4().hex[:6]}"
    body = UserCreateRequest(
        username=username,
        password="Str0ngPassw0rd!xyz",
        email=f"{username}@example.test",
        role="operator",
        group_id=None,
        team_id=None,
    )

    with patch(
        "aila.api.routers.users._check_hibp", return_value=False
    ):
        env = await ep(
            request=_stub_request(),
            body=body,
            caller=_auth(None),
        )
    assert env.data.team_id is None

    async with async_session_scope() as session:
        row = await session.get(UserRecord, env.data.id)
    assert row is not None
    assert row.team_id is None


# ---------------------------------------------------------------------------
# PATCH /users/{user_id} -- cross-team 404 leaves target unchanged
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_update_user_cross_team_is_404_and_no_mutation() -> None:
    target_id = await _seed_user("team-b", f"ub-{uuid4().hex[:6]}")
    ep = _endpoint("/users/{user_id}", "PATCH")
    req = UserUpdateRequest(is_active=False, email="hijacked@example.test")

    with pytest.raises(HTTPException) as exc:
        await ep(
            request=_stub_request(),
            user_id=target_id,
            body=req,
            caller=_auth("team-a"),
        )
    assert exc.value.status_code == 404

    # The team-B row was not mutated.
    async with async_session_scope() as session:
        row = await session.get(UserRecord, target_id)
    assert row is not None
    assert row.is_active is True
    assert row.email != "hijacked@example.test"


@pytest.mark.usefixtures("test_db")
async def test_update_user_same_team_succeeds() -> None:
    target_id = await _seed_user("team-a", f"ua-{uuid4().hex[:6]}")
    ep = _endpoint("/users/{user_id}", "PATCH")
    req = UserUpdateRequest(email="renamed@example.test")

    env = await ep(
        request=_stub_request(),
        user_id=target_id,
        body=req,
        caller=_auth("team-a"),
    )
    assert env.data.email == "renamed@example.test"


@pytest.mark.usefixtures("test_db")
async def test_update_user_god_tier_edits_any_team() -> None:
    target_id = await _seed_user("team-b", f"ub-{uuid4().hex[:6]}")
    ep = _endpoint("/users/{user_id}", "PATCH")
    req = UserUpdateRequest(email="godset@example.test")

    env = await ep(
        request=_stub_request(),
        user_id=target_id,
        body=req,
        caller=_auth(None),
    )
    assert env.data.email == "godset@example.test"
