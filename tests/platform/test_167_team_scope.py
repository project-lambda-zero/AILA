"""Team scope unit tests for Phase 167 Plan 05.

Tests cover:
- do_orm_execute listener auto-filtering SELECT queries by team_id
- Admin bypass (team_id=None, is_admin=True sees all)
- No TeamContext = no filtering (backward compat)
- Global models are not filtered even with TeamContext set
- _stamp_team_id auto-stamping behavior for non-admin and admin
- team_id spoofing prevention
- Cross-team isolation at the ORM level

All tests run against real PostgreSQL via AILA_TEST_DATABASE_URL.
No mock data, no SQLite.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlmodel import select

from aila.api.auth import TeamContext
from aila.platform.services.storage import _stamp_team_id
from aila.storage.database import async_session_scope
from aila.storage.db_models import ConfigEntryRecord, ManagedSystemRecord


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_system(name: str, host: str, team_id: str | None = None) -> ManagedSystemRecord:
    """Create a ManagedSystemRecord with the given team_id."""
    from aila.platform.contracts._common import utc_now

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


def _make_config(namespace: str, key: str, value: str) -> ConfigEntryRecord:
    """Create a ConfigEntryRecord (global model -- no team_id)."""
    from aila.platform.contracts._common import utc_now

    return ConfigEntryRecord(
        namespace=namespace,
        key=key,
        value=value,
        value_type="str",
        updated_at=utc_now(),
    )


# ---------------------------------------------------------------------------
# Tests: do_orm_execute filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_team_scope_filter_select(test_db):
    """Set team_context on session, query team-scoped model, verify only matching rows."""
    ctx = TeamContext(team_id="team-alpha", is_admin=False)

    # Seed records for two teams
    async with async_session_scope() as session:
        session.add(_make_system("sys-alpha-1", "10.0.1.1", team_id="team-alpha"))
        session.add(_make_system("sys-beta-1", "10.0.2.1", team_id="team-beta"))
        await session.commit()

    # Query with team-alpha context -- should only see team-alpha records
    async with async_session_scope(team_context=ctx) as session:
        stmt = select(ManagedSystemRecord)
        results = list((await session.exec(stmt)).all())

    assert len(results) == 1
    assert results[0].name == "sys-alpha-1"
    assert results[0].team_id == "team-alpha"


@pytest.mark.asyncio
async def test_team_scope_admin_bypass(test_db):
    """Admin team_context (is_admin=True) should see all teams' records."""
    admin_ctx = TeamContext(team_id=None, is_admin=True)

    # Seed records for two teams
    async with async_session_scope() as session:
        session.add(_make_system("sys-a", "10.0.1.1", team_id="team-alpha"))
        session.add(_make_system("sys-b", "10.0.2.1", team_id="team-beta"))
        await session.commit()

    # Query with admin context -- should see all records
    async with async_session_scope(team_context=admin_ctx) as session:
        stmt = select(ManagedSystemRecord)
        results = list((await session.exec(stmt)).all())

    assert len(results) == 2
    names = {r.name for r in results}
    assert names == {"sys-a", "sys-b"}


@pytest.mark.asyncio
async def test_team_scope_no_context(test_db):
    """No team_context on session should return all rows (backward compat)."""
    # Seed records for two teams
    async with async_session_scope() as session:
        session.add(_make_system("sys-x", "10.0.1.1", team_id="team-alpha"))
        session.add(_make_system("sys-y", "10.0.2.1", team_id="team-beta"))
        await session.commit()

    # Query with no team_context -- should see all records
    async with async_session_scope() as session:
        stmt = select(ManagedSystemRecord)
        results = list((await session.exec(stmt)).all())

    assert len(results) == 2


@pytest.mark.asyncio
async def test_team_scope_global_model_not_filtered(test_db):
    """Query a global model (ConfigEntryRecord) with team_context set -- no filtering."""
    ctx = TeamContext(team_id="team-alpha", is_admin=False)

    # Seed global config entries
    async with async_session_scope() as session:
        session.add(_make_config("vulnerability", "max_cves", "500"))
        session.add(_make_config("platform", "debug_mode", "false"))
        await session.commit()

    # Query with team context -- global model should NOT be filtered
    async with async_session_scope(team_context=ctx) as session:
        stmt = select(ConfigEntryRecord)
        results = list((await session.exec(stmt)).all())

    assert len(results) == 2


# ---------------------------------------------------------------------------
# Tests: _stamp_team_id auto-stamping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stamp_team_id_non_admin(test_db):
    """Non-admin: _stamp_team_id always sets team_id from context."""
    ctx = TeamContext(team_id="team-alpha", is_admin=False)
    record = _make_system("stamp-test-1", "10.0.1.1")

    async with async_session_scope(team_context=ctx) as session:
        _stamp_team_id(session, record)

    assert record.team_id == "team-alpha"


@pytest.mark.asyncio
async def test_stamp_team_id_admin_no_explicit(test_db):
    """Admin with no explicit team_id: leaves as None."""
    admin_ctx = TeamContext(team_id=None, is_admin=True)
    record = _make_system("stamp-admin-1", "10.0.1.1")
    # Ensure no team_id on the record
    record.team_id = None

    async with async_session_scope(team_context=admin_ctx) as session:
        _stamp_team_id(session, record)

    assert record.team_id is None


@pytest.mark.asyncio
async def test_stamp_team_id_admin_explicit(test_db):
    """Admin with explicit team_id on record: keeps that team_id."""
    admin_ctx = TeamContext(team_id=None, is_admin=True)
    record = _make_system("stamp-admin-2", "10.0.1.1", team_id="team-beta")

    async with async_session_scope(team_context=admin_ctx) as session:
        _stamp_team_id(session, record)

    assert record.team_id == "team-beta"


@pytest.mark.asyncio
async def test_stamp_team_id_spoofing_prevention(test_db):
    """Non-admin sets wrong team_id -- _stamp_team_id overwrites with context team_id."""
    ctx = TeamContext(team_id="team-alpha", is_admin=False)
    record = _make_system("stamp-spoof", "10.0.1.1", team_id="team-evil")

    async with async_session_scope(team_context=ctx) as session:
        _stamp_team_id(session, record)

    # Should be overwritten to the context team_id, not the spoofed one
    assert record.team_id == "team-alpha"


# ---------------------------------------------------------------------------
# Tests: cross-team isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cross_team_isolation(test_db):
    """Create records for team-a and team-b, query with team-a context, verify team-b not returned."""
    ctx_a = TeamContext(team_id="team-a", is_admin=False)
    ctx_b = TeamContext(team_id="team-b", is_admin=False)

    # Seed records for both teams
    async with async_session_scope() as session:
        session.add(_make_system("iso-a-1", "10.0.1.1", team_id="team-a"))
        session.add(_make_system("iso-a-2", "10.0.1.2", team_id="team-a"))
        session.add(_make_system("iso-b-1", "10.0.2.1", team_id="team-b"))
        session.add(_make_system("iso-b-2", "10.0.2.2", team_id="team-b"))
        await session.commit()

    # Team A should only see team-a records
    async with async_session_scope(team_context=ctx_a) as session:
        stmt = select(ManagedSystemRecord)
        results_a = list((await session.exec(stmt)).all())

    assert len(results_a) == 2
    for r in results_a:
        assert r.team_id == "team-a", f"Team-a context returned team_id={r.team_id}"

    # Team B should only see team-b records
    async with async_session_scope(team_context=ctx_b) as session:
        stmt = select(ManagedSystemRecord)
        results_b = list((await session.exec(stmt)).all())

    assert len(results_b) == 2
    for r in results_b:
        assert r.team_id == "team-b", f"Team-b context returned team_id={r.team_id}"

    # Verify no overlap
    names_a = {r.name for r in results_a}
    names_b = {r.name for r in results_b}
    assert names_a.isdisjoint(names_b), "Team A and Team B should see disjoint datasets"
