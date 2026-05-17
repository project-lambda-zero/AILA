"""Tests for admin teams endpoints (Phase 177).

Covers:
    - CRUD happy path (create, get, list, update, delete)
    - Admin-only enforcement (non-admin token hits 403)
    - Cross-team stats aggregation
    - Delete protection when systems reference the team (409)
    - Member add / remove / duplicate guard
    - UUID validation on path params
"""
from __future__ import annotations

from datetime import UTC
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def seed_user(test_db) -> str:
    """Create a plain user and return the user id (for member add tests)."""
    from datetime import datetime

    from aila.storage.database import async_session_scope
    from aila.storage.db_models import UserRecord

    now = datetime.now(UTC)
    user = UserRecord(
        username="team-member-1",
        email="tm1@example.com",
        role="operator",
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    async with async_session_scope() as session:
        session.add(user)
        await session.commit()
        await session.refresh(user)
    return user.id


# ---------------------------------------------------------------------------
# Admin-only enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_teams_requires_admin(
    async_client: AsyncClient, reader_token: str
) -> None:
    resp = await async_client.get(
        "/admin/teams",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_team_requires_admin(
    async_client: AsyncClient, operator_token: str
) -> None:
    resp = await async_client.post(
        "/admin/teams",
        headers={"Authorization": f"Bearer {operator_token}"},
        json={"name": "blue", "description": "blue team"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# CRUD happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_team_happy_path(
    async_client: AsyncClient, admin_token: str
) -> None:
    resp = await async_client.post(
        "/admin/teams",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "security-red", "description": "red team"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()["data"]
    assert body["name"] == "security-red"
    assert body["description"] == "red team"
    assert body["member_count"] == 0
    # id is a UUID
    from uuid import UUID
    UUID(body["id"])


@pytest.mark.asyncio
async def test_create_team_duplicate_name(
    async_client: AsyncClient, admin_token: str
) -> None:
    for _ in range(1):
        r = await async_client.post(
            "/admin/teams",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"name": "dup"},
        )
        assert r.status_code == 201

    r = await async_client.post(
        "/admin/teams",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "dup"},
    )
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_get_team_returns_detail(
    async_client: AsyncClient, admin_token: str
) -> None:
    create_resp = await async_client.post(
        "/admin/teams",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "detail-team"},
    )
    team_id = create_resp.json()["data"]["id"]

    get_resp = await async_client.get(
        f"/admin/teams/{team_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert get_resp.status_code == 200
    body = get_resp.json()["data"]
    assert body["team"]["id"] == team_id
    assert body["members"] == []


@pytest.mark.asyncio
async def test_get_team_invalid_uuid_returns_422(
    async_client: AsyncClient, admin_token: str
) -> None:
    resp = await async_client.get(
        "/admin/teams/not-a-uuid",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_get_team_not_found(
    async_client: AsyncClient, admin_token: str
) -> None:
    fake_id = str(uuid4())
    resp = await async_client.get(
        f"/admin/teams/{fake_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_team(
    async_client: AsyncClient, admin_token: str
) -> None:
    create = await async_client.post(
        "/admin/teams",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "old-name", "description": "old"},
    )
    team_id = create.json()["data"]["id"]

    resp = await async_client.put(
        f"/admin/teams/{team_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "new-name", "description": "new"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()["data"]
    assert body["name"] == "new-name"
    assert body["description"] == "new"


@pytest.mark.asyncio
async def test_delete_team(
    async_client: AsyncClient, admin_token: str
) -> None:
    create = await async_client.post(
        "/admin/teams",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "to-delete"},
    )
    team_id = create.json()["data"]["id"]

    resp = await async_client.delete(
        f"/admin/teams/{team_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["deleted"] == team_id

    # Follow-up GET returns 404
    get_resp = await async_client.get(
        f"/admin/teams/{team_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_team_blocked_by_systems(
    async_client: AsyncClient, admin_token: str
) -> None:
    """Deleting a team with ManagedSystemRecord rows must return 409."""
    from aila.storage.database import async_session_scope
    from aila.storage.db_models import ManagedSystemRecord

    create = await async_client.post(
        "/admin/teams",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "team-with-systems"},
    )
    team_id = create.json()["data"]["id"]

    async with async_session_scope() as session:
        sys = ManagedSystemRecord(
            name="srv-1",
            host="10.0.0.1",
            username="root",
            team_id=team_id,
        )
        session.add(sys)
        await session.commit()

    resp = await async_client.delete(
        f"/admin/teams/{team_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 409
    assert "Reassign" in resp.text or "system" in resp.text.lower()


# ---------------------------------------------------------------------------
# Cross-team view
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cross_team_view_aggregates(
    async_client: AsyncClient, admin_token: str
) -> None:
    """Exercise the aggregated cross-team stats endpoint."""
    for name in ("ct-alpha", "ct-beta"):
        r = await async_client.post(
            "/admin/teams",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"name": name},
        )
        assert r.status_code == 201

    resp = await async_client.get(
        "/admin/teams/cross-view",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    names = {row["team_name"] for row in data}
    assert {"ct-alpha", "ct-beta"} <= names
    for row in data:
        assert row["systems_count"] == 0
        assert row["runs_count"] == 0
        assert row["members_count"] == 0


# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_and_remove_member(
    async_client: AsyncClient, admin_token: str, seed_user: str
) -> None:
    create = await async_client.post(
        "/admin/teams",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "member-team"},
    )
    team_id = create.json()["data"]["id"]

    add = await async_client.post(
        f"/admin/teams/{team_id}/members",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"user_id": seed_user, "role": "operator"},
    )
    assert add.status_code == 201, add.text
    assert add.json()["data"]["role"] == "operator"
    assert add.json()["data"]["user_id"] == seed_user

    # Duplicate add -> 409
    dup = await async_client.post(
        f"/admin/teams/{team_id}/members",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"user_id": seed_user, "role": "reader"},
    )
    assert dup.status_code == 409

    # Remove
    remove = await async_client.delete(
        f"/admin/teams/{team_id}/members/{seed_user}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert remove.status_code == 200
    assert remove.json()["data"]["removed"] == seed_user

    # Remove again -> 404
    remove2 = await async_client.delete(
        f"/admin/teams/{team_id}/members/{seed_user}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert remove2.status_code == 404


@pytest.mark.asyncio
async def test_add_member_unknown_user(
    async_client: AsyncClient, admin_token: str
) -> None:
    create = await async_client.post(
        "/admin/teams",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "missing-user-team"},
    )
    team_id = create.json()["data"]["id"]

    fake_user = str(uuid4())
    resp = await async_client.post(
        f"/admin/teams/{team_id}/members",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"user_id": fake_user, "role": "operator"},
    )
    assert resp.status_code == 404
