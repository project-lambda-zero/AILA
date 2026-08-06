"""#36 -- SavedFilter shared_with_team is scoped to the caller's team.

A saved filter marked ``shared_with_team=True`` was returned to every
user on the platform because the list handler only checked the flag,
never the caller's team. ``SavedFilterRecord`` has no ``team_id`` column,
so the router now joins through ``UserRecord.team_id`` to keep the shared
filters visible only to members of the creator's team. God-tier admins
(``team_id`` is None, TEAM-06) still see every shared filter.

Also covers the create path indirectly: a user in team B never observes
a team-A shared filter, and a team-A member always observes their own
team's shared filter.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient

from aila.api.auth import hash_user_password, issue_user_jwt
from aila.storage.database import async_session_scope
from aila.storage.db_models import UserRecord


@pytest_asyncio.fixture
async def team_a_user(test_db) -> UserRecord:
    user = UserRecord(
        username="alice-team-a",
        hashed_password=hash_user_password("SecurePass1!"),
        role="operator",
        is_active=True,
        team_id="team-a",
    )
    async with async_session_scope() as session:
        session.add(user)
        await session.commit()
        await session.refresh(user)
    return user


@pytest_asyncio.fixture
async def team_a_user_2(test_db) -> UserRecord:
    user = UserRecord(
        username="anna-team-a",
        hashed_password=hash_user_password("SecurePass2!"),
        role="operator",
        is_active=True,
        team_id="team-a",
    )
    async with async_session_scope() as session:
        session.add(user)
        await session.commit()
        await session.refresh(user)
    return user


@pytest_asyncio.fixture
async def team_b_user(test_db) -> UserRecord:
    user = UserRecord(
        username="bob-team-b",
        hashed_password=hash_user_password("SecurePass3!"),
        role="operator",
        is_active=True,
        team_id="team-b",
    )
    async with async_session_scope() as session:
        session.add(user)
        await session.commit()
        await session.refresh(user)
    return user


@pytest_asyncio.fixture
async def god_admin(test_db) -> UserRecord:
    user = UserRecord(
        username="godmode-admin",
        hashed_password=hash_user_password("AdminPass1!"),
        role="admin",
        is_active=True,
        team_id=None,
    )
    async with async_session_scope() as session:
        session.add(user)
        await session.commit()
        await session.refresh(user)
    return user


def _token(user: UserRecord) -> str:
    tok, _ = issue_user_jwt(user.id, user.role, team_id=user.team_id)
    return tok


async def _post_shared_filter(
    client: AsyncClient, token: str, name: str, entity_type: str
) -> str:
    resp = await client.post(
        "/saved-filters",
        json={
            "name": name,
            "entity_type": entity_type,
            "filter_json": "{}",
            "shared_with_team": True,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["data"]["id"]


@pytest.mark.asyncio
async def test_team_b_does_not_see_team_a_shared_filter(
    async_client: AsyncClient,
    team_a_user: UserRecord,
    team_b_user: UserRecord,
) -> None:
    """A team-B caller MUST NOT see a filter shared_with_team=True by team A."""
    filter_id = await _post_shared_filter(
        async_client, _token(team_a_user), "team-a-shared", "findings"
    )

    resp = await async_client.get(
        "/saved-filters",
        headers={"Authorization": f"Bearer {_token(team_b_user)}"},
    )
    assert resp.status_code == 200, resp.text
    ids = [item["id"] for item in resp.json()["data"]]
    assert filter_id not in ids, "team-A shared filter leaked to team-B"


@pytest.mark.asyncio
async def test_team_a_peer_sees_team_a_shared_filter(
    async_client: AsyncClient,
    team_a_user: UserRecord,
    team_a_user_2: UserRecord,
) -> None:
    """Two members of the same team share the filter (no regression)."""
    filter_id = await _post_shared_filter(
        async_client, _token(team_a_user), "team-a-shared", "findings"
    )

    resp = await async_client.get(
        "/saved-filters",
        headers={"Authorization": f"Bearer {_token(team_a_user_2)}"},
    )
    assert resp.status_code == 200, resp.text
    ids = [item["id"] for item in resp.json()["data"]]
    assert filter_id in ids, "team-A shared filter missing from teammate's view"


@pytest.mark.asyncio
async def test_admin_sees_shared_filters_across_all_teams(
    async_client: AsyncClient,
    team_a_user: UserRecord,
    team_b_user: UserRecord,
    god_admin: UserRecord,
) -> None:
    """God-tier admin (team_id=None, TEAM-06) sees every team's shared filters."""
    fid_a = await _post_shared_filter(
        async_client, _token(team_a_user), "team-a-shared", "findings"
    )
    fid_b = await _post_shared_filter(
        async_client, _token(team_b_user), "team-b-shared", "findings"
    )

    resp = await async_client.get(
        "/saved-filters",
        headers={"Authorization": f"Bearer {_token(god_admin)}"},
    )
    assert resp.status_code == 200, resp.text
    ids = {item["id"] for item in resp.json()["data"]}
    assert fid_a in ids
    assert fid_b in ids


@pytest.mark.asyncio
async def test_own_filter_visible_even_when_not_shared(
    async_client: AsyncClient,
    team_a_user: UserRecord,
) -> None:
    """A private filter MUST remain visible to its owner (no regression)."""
    resp = await async_client.post(
        "/saved-filters",
        json={
            "name": "private",
            "entity_type": "findings",
            "filter_json": "{}",
            "shared_with_team": False,
        },
        headers={"Authorization": f"Bearer {_token(team_a_user)}"},
    )
    assert resp.status_code == 201, resp.text
    filter_id = resp.json()["data"]["id"]

    resp = await async_client.get(
        "/saved-filters",
        headers={"Authorization": f"Bearer {_token(team_a_user)}"},
    )
    assert resp.status_code == 200, resp.text
    ids = [item["id"] for item in resp.json()["data"]]
    assert filter_id in ids
