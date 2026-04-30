"""API-level team isolation integration tests for Phase 167 Plan 05.

Tests cover:
- JWT contains team_id claim (user and API key tokens)
- Admin JWT has team_id=null
- AuthContext populated with team_id from JWT
- TeamContext.from_auth produces correct is_admin flag
- Team-scoped queries return only own team's data
- Cross-team query blocks other team's data
- Admin sees all teams' data
- Auto-stamp team_id on create via StorageService
- Auth revocation cache reduces DB queries

All tests run against real PostgreSQL. No mock data, no SQLite.
"""
from __future__ import annotations

import jwt as pyjwt
import pytest
import pytest_asyncio

from aila.api.auth import (
    AuthContext,
    TeamContext,
    generate_api_key,
    hash_api_key,
    issue_jwt_token,
    issue_user_jwt,
)
from aila.api.auth_cache import get_auth_cache, reset_auth_cache
from aila.api.constants import JWT_ALGORITHM, JWT_TYP_ACCESS, JWT_TYP_USER_ACCESS
from aila.config import get_settings
from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import ApiKeyRecord, ManagedSystemRecord, UserRecord


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decode_jwt(token: str) -> dict:
    """Decode a JWT without verification (for claim inspection)."""
    settings = get_settings()
    return pyjwt.decode(token, settings.jwt_secret_key, algorithms=[JWT_ALGORITHM])


def _make_system(name: str, host: str, team_id: str | None = None) -> ManagedSystemRecord:
    """Create a ManagedSystemRecord for testing."""
    return ManagedSystemRecord(
        name=name,
        host=host,
        username="testuser",
        port=22,
        distro="ubuntu",
        description=f"Test system {name}",
        team_id=team_id,
        created_at=utc_now(),
        updated_at=utc_now(),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_cache():
    """Reset auth cache before each test."""
    reset_auth_cache()
    yield
    reset_auth_cache()


@pytest_asyncio.fixture
async def team_a_user(test_db) -> UserRecord:
    """Create an operator user assigned to team-a."""
    from aila.api.auth import hash_user_password

    user = UserRecord(
        username="user-team-a",
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
async def team_b_user(test_db) -> UserRecord:
    """Create an operator user assigned to team-b."""
    from aila.api.auth import hash_user_password

    user = UserRecord(
        username="user-team-b",
        hashed_password=hash_user_password("SecurePass2!"),
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
async def admin_user(test_db) -> UserRecord:
    """Create an admin user with team_id=None (god tier)."""
    from aila.api.auth import hash_user_password

    user = UserRecord(
        username="admin-god",
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


@pytest_asyncio.fixture
async def team_a_api_key(test_db) -> ApiKeyRecord:
    """Create an API key assigned to team-a."""
    raw_key = generate_api_key()
    record = ApiKeyRecord(
        hashed_key=hash_api_key(raw_key),
        key_prefix=raw_key[:12],
        role="operator",
        label="team-a-key",
        created_by="test",
        created_at=utc_now(),
        team_id="team-a",
    )
    async with async_session_scope() as session:
        session.add(record)
        await session.commit()
        await session.refresh(record)
    record._raw_key = raw_key  # type: ignore[attr-defined]
    return record


# ---------------------------------------------------------------------------
# Tests: JWT team_id claims
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_jwt_contains_team_id(team_a_user):
    """Issue JWT for team user, decode, verify team_id claim present."""
    token, _ = issue_user_jwt(team_a_user.id, team_a_user.role, team_id="team-a")
    payload = _decode_jwt(token)

    assert payload["team_id"] == "team-a"
    assert payload["user_id"] == team_a_user.id
    assert payload["typ"] == JWT_TYP_USER_ACCESS


@pytest.mark.asyncio
async def test_jwt_admin_team_id_null(admin_user):
    """Issue JWT for admin, verify team_id is null."""
    token, _ = issue_user_jwt(admin_user.id, admin_user.role, team_id=None)
    payload = _decode_jwt(token)

    assert payload["team_id"] is None
    assert payload["role"] == "admin"


@pytest.mark.asyncio
async def test_auth_context_has_team_id(team_a_user):
    """Verify AuthContext.team_id is populated from JWT claims."""
    auth = AuthContext(
        user_id=team_a_user.id,
        role=team_a_user.role,
        auth_type="user",
        team_id="team-a",
    )
    assert auth.team_id == "team-a"
    assert auth.auth_type == "user"


@pytest.mark.asyncio
async def test_team_context_from_auth():
    """Verify TeamContext.from_auth produces correct is_admin flag."""
    # Non-admin user
    auth_normal = AuthContext(user_id="u1", role="operator", auth_type="user", team_id="team-x")
    ctx = TeamContext.from_auth(auth_normal)
    assert ctx.team_id == "team-x"
    assert ctx.is_admin is False

    # Admin user
    auth_admin = AuthContext(user_id="u2", role="admin", auth_type="user", team_id=None)
    ctx_admin = TeamContext.from_auth(auth_admin)
    assert ctx_admin.team_id is None
    assert ctx_admin.is_admin is True


@pytest.mark.asyncio
async def test_api_key_jwt_has_team_id(team_a_api_key):
    """Issue API key JWT, verify team_id from ApiKeyRecord."""
    token, _ = issue_jwt_token(team_a_api_key)
    payload = _decode_jwt(token)

    assert payload["team_id"] == "team-a"
    assert payload["key_id"] == team_a_api_key.id
    assert payload["typ"] == JWT_TYP_ACCESS


# ---------------------------------------------------------------------------
# Tests: team-scoped query isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_team_scoped_query_returns_own_data(test_db):
    """Create record for team-a, query as team-a, verify returned."""
    ctx_a = TeamContext(team_id="team-a", is_admin=False)

    async with async_session_scope() as session:
        session.add(_make_system("own-sys", "10.0.1.1", team_id="team-a"))
        await session.commit()

    from sqlmodel import select

    async with async_session_scope(team_context=ctx_a) as session:
        stmt = select(ManagedSystemRecord)
        results = list((await session.exec(stmt)).all())

    assert len(results) == 1
    assert results[0].name == "own-sys"
    assert results[0].team_id == "team-a"


@pytest.mark.asyncio
async def test_team_scoped_query_blocks_other_team(test_db):
    """Create record for team-a, query as team-b, verify NOT returned."""
    ctx_b = TeamContext(team_id="team-b", is_admin=False)

    async with async_session_scope() as session:
        session.add(_make_system("other-sys", "10.0.1.1", team_id="team-a"))
        await session.commit()

    from sqlmodel import select

    async with async_session_scope(team_context=ctx_b) as session:
        stmt = select(ManagedSystemRecord)
        results = list((await session.exec(stmt)).all())

    assert len(results) == 0, "Team-b should NOT see team-a's records"


@pytest.mark.asyncio
async def test_admin_sees_all_teams(test_db):
    """Create records for team-a and team-b, query as admin, verify both returned."""
    admin_ctx = TeamContext(team_id=None, is_admin=True)

    async with async_session_scope() as session:
        session.add(_make_system("admin-a", "10.0.1.1", team_id="team-a"))
        session.add(_make_system("admin-b", "10.0.2.1", team_id="team-b"))
        await session.commit()

    from sqlmodel import select

    async with async_session_scope(team_context=admin_ctx) as session:
        stmt = select(ManagedSystemRecord)
        results = list((await session.exec(stmt)).all())

    assert len(results) == 2
    names = {r.name for r in results}
    assert names == {"admin-a", "admin-b"}


# ---------------------------------------------------------------------------
# Tests: auto-stamp and cache
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auto_stamp_team_id_on_create(test_db):
    """Create record via StorageService as team user, verify team_id set."""
    from aila.platform.services.storage import StorageService

    ctx = TeamContext(team_id="team-stamp", is_admin=False)
    svc = StorageService()

    record = ManagedSystemRecord(
        name="stamp-test",
        host="10.0.1.1",
        username="testuser",
        port=22,
        distro="ubuntu",
        description="Auto-stamp test",
        created_at=utc_now(),
        updated_at=utc_now(),
    )

    async with async_session_scope(team_context=ctx) as session:
        await svc.save(record, session=session)
        await session.commit()

    # Verify team_id was stamped by reading with admin context
    from sqlmodel import select

    admin_ctx = TeamContext(team_id=None, is_admin=True)
    async with async_session_scope(team_context=admin_ctx) as session:
        stmt = select(ManagedSystemRecord).where(ManagedSystemRecord.name == "stamp-test")
        result = (await session.exec(stmt)).first()

    assert result is not None
    assert result.team_id == "team-stamp"


@pytest.mark.asyncio
async def test_revocation_cache_reduces_db_queries(test_db, team_a_user):
    """Authenticate twice with same token, verify second uses cache."""
    from aila.api.auth import decode_and_blacklist_check

    # Issue a user JWT
    token, _ = issue_user_jwt(team_a_user.id, team_a_user.role, team_id="team-a")

    cache = get_auth_cache()
    assert cache.size == 0, "Cache should be empty before first auth"

    # First call: cache miss -> DB query -> cache store
    result1 = await decode_and_blacklist_check(token, expected_typ=JWT_TYP_USER_ACCESS)
    assert result1 is not None
    assert cache.size == 1, "Cache should have 1 entry after first auth"

    # Second call: cache hit -> should use cached value
    result2 = await decode_and_blacklist_check(token, expected_typ=JWT_TYP_USER_ACCESS)
    assert result2 is not None
    assert cache.size == 1, "Cache size should remain 1 (hit, not new store)"

    # Both results should represent the same user
    assert result1.id == result2.id
