"""#36 -- audit event queries are team-scoped.

AuditEventRecord is team-scoped, but GET /audit/events and
GET /audit/events/{run_id} queried without any team predicate, so any
authenticated principal could read every team's audit trail. Both now
filter by the caller's team; a god-tier admin (team_id=None, TEAM-06)
sees all.

Handlers are invoked directly with an explicit AuthContext (the router-
level require_user_or_api_key is not resolved on direct invocation). The
list handler's Query-default params are passed explicitly so their
sentinel FieldInfo defaults are not mistaken for real values.
"""
from __future__ import annotations

from uuid import uuid4

import pytest

from aila.api.auth import AuthContext
from aila.api.routers.audit import get_run_audit_events, list_audit_events
from aila.storage.database import async_session_scope
from aila.storage.db_models import AuditEventRecord


def _auth(team_id: str | None) -> AuthContext:
    return AuthContext(
        user_id="u-" + (team_id or "god"),
        role="admin" if team_id is None else "operator",
        auth_type="user",
        team_id=team_id,
    )


async def _seed(team_id: str, run_id: str) -> None:
    async with async_session_scope() as s:
        s.add(
            AuditEventRecord(
                run_id=run_id, stage="route", action="dispatch", team_id=team_id
            )
        )
        await s.commit()


async def _list(auth: AuthContext):
    return await list_audit_events(
        run_id=None,
        stage=None,
        action=None,
        status=None,
        user_id=None,
        since=None,
        until=None,
        page=1,
        page_size=250,
        auth=auth,
    )


@pytest.mark.usefixtures("test_db")
async def test_list_scoped_to_team() -> None:
    ra, rb = f"run-a-{uuid4().hex[:6]}", f"run-b-{uuid4().hex[:6]}"
    await _seed("team-a", ra)
    await _seed("team-b", rb)
    resp = await _list(_auth("team-a"))
    run_ids = {i.run_id for i in resp.items}
    assert ra in run_ids
    assert rb not in run_ids


@pytest.mark.usefixtures("test_db")
async def test_god_tier_sees_all_teams() -> None:
    ra, rb = f"run-a-{uuid4().hex[:6]}", f"run-b-{uuid4().hex[:6]}"
    await _seed("team-a", ra)
    await _seed("team-b", rb)
    resp = await _list(_auth(None))
    run_ids = {i.run_id for i in resp.items}
    assert ra in run_ids
    assert rb in run_ids


@pytest.mark.usefixtures("test_db")
async def test_run_trail_cross_team_is_empty() -> None:
    rb = f"run-b-{uuid4().hex[:6]}"
    await _seed("team-b", rb)
    resp = await get_run_audit_events(run_id=rb, auth=_auth("team-a"))
    assert resp.items == []


@pytest.mark.usefixtures("test_db")
async def test_run_trail_own_team_visible() -> None:
    ra = f"run-a-{uuid4().hex[:6]}"
    await _seed("team-a", ra)
    resp = await get_run_audit_events(run_id=ra, auth=_auth("team-a"))
    assert len(resp.items) == 1
    assert resp.items[0].run_id == ra
