"""Team-scope enforcement tests for C1 / #36 / #57.

Proves the do_orm_execute listener actually filters team-scoped SELECTs when
a TeamContext is bound to the session, and that owned_or_404 refuses a
cross-team row with 404 (never a 403 existence oracle). Runs against the
Postgres test_db fixture.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from sqlmodel import select

from aila.api.auth import TeamContext
from aila.api.deps import owned_or_404
from aila.platform.llm.cost_record import LLMCostRecord
from aila.storage.database import async_session_scope


async def _seed_two_teams() -> tuple[str, str]:
    # No team_context => admin => unfiltered insert; both rows persist.
    async with async_session_scope() as session:
        a = LLMCostRecord(model_id="m", team_id="team-a", run_id="ra")
        b = LLMCostRecord(model_id="m", team_id="team-b", run_id="rb")
        session.add(a)
        session.add(b)
        await session.commit()
        return a.id, b.id


async def test_listener_filters_selects_by_team(test_db) -> None:
    a_id, b_id = await _seed_two_teams()
    ctx_a = TeamContext(team_id="team-a", is_admin=False)
    async with async_session_scope(team_context=ctx_a) as session:
        ids = {r.id for r in (await session.exec(select(LLMCostRecord))).all()}
    assert a_id in ids
    assert b_id not in ids


async def test_admin_context_sees_all_teams(test_db) -> None:
    a_id, b_id = await _seed_two_teams()
    ctx_admin = TeamContext(team_id=None, is_admin=True)
    async with async_session_scope(team_context=ctx_admin) as session:
        ids = {r.id for r in (await session.exec(select(LLMCostRecord))).all()}
    assert {a_id, b_id} <= ids


async def test_owned_or_404_returns_owned_row(test_db) -> None:
    a_id, _ = await _seed_two_teams()
    ctx_a = TeamContext(team_id="team-a", is_admin=False)
    async with async_session_scope(team_context=ctx_a) as session:
        row = await owned_or_404(session, LLMCostRecord, a_id)
    assert row.id == a_id


async def test_owned_or_404_rejects_cross_team_with_404(test_db) -> None:
    _, b_id = await _seed_two_teams()
    ctx_a = TeamContext(team_id="team-a", is_admin=False)
    async with async_session_scope(team_context=ctx_a) as session:
        with pytest.raises(HTTPException) as exc_info:
            await owned_or_404(session, LLMCostRecord, b_id)
    assert exc_info.value.status_code == 404


async def test_owned_or_404_missing_row_is_404(test_db) -> None:
    await _seed_two_teams()
    ctx_a = TeamContext(team_id="team-a", is_admin=False)
    async with async_session_scope(team_context=ctx_a) as session:
        with pytest.raises(HTTPException) as exc_info:
            await owned_or_404(session, LLMCostRecord, "does-not-exist")
    assert exc_info.value.status_code == 404
