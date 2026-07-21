"""#48-6 -- team-scoped scheduled_report_records CRUD.

ScheduledReportRecord gained team_id (TeamScopedMixin). The CRUD handlers
stamp it from the caller and resolve single resources by a team predicate.
A team-scoped admin sees and mutates only its own team's schedules; a
god-tier admin (team_id=None, TEAM-06) sees all. Cross-team single-resource
access returns 404 so the row's existence does not leak.

Handlers are invoked directly: the slowapi limiter is disabled by the
autouse fixture, and _require_admin is not resolved on direct invocation,
so role='admin' plus the team_id under test is passed explicitly.
"""
from __future__ import annotations

import types

import pytest
from fastapi import HTTPException

from aila.api.auth import AuthContext
from aila.api.routers.scheduled_reports import router as sr_router
from aila.api.schemas.endpoints import (
    ScheduledReportCreate,
    ScheduledReportUpdate,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import ScheduledReportRecord


def _req() -> object:
    return types.SimpleNamespace(
        app=types.SimpleNamespace(state=types.SimpleNamespace(platform=None))
    )


def _auth(team_id: str | None, role: str = "admin") -> AuthContext:
    return AuthContext(
        user_id="u-" + (team_id or "god"),
        role=role,
        auth_type="user",
        team_id=team_id,
    )


def _endpoint(path: str, method: str):
    for route in sr_router.routes:
        if getattr(route, "path", None) == path and method in getattr(
            route, "methods", set()
        ):
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


_BASE = "/scheduled-reports"
_ONE = "/scheduled-reports/{report_id}"
_TRIGGER = "/scheduled-reports/{report_id}/trigger"


async def _create(team_id: str | None, name: str) -> str:
    create = _endpoint(_BASE, "POST")
    env = await create(
        request=_req(),
        body=ScheduledReportCreate(
            name=name, report_type="custom", cron_expression="0 0 * * *"
        ),
        auth=_auth(team_id),
    )
    return env.data.id


@pytest.mark.usefixtures("test_db")
async def test_create_stamps_team_id() -> None:
    rid = await _create("team-a", "A sched")
    async with async_session_scope() as s:
        rec = await s.get(ScheduledReportRecord, rid)
    assert rec is not None
    assert rec.team_id == "team-a"


@pytest.mark.usefixtures("test_db")
async def test_list_scoped_to_team() -> None:
    a = await _create("team-a", "A")
    b = await _create("team-b", "B")
    list_ep = _endpoint(_BASE, "GET")
    env = await list_ep(request=_req(), auth=_auth("team-a"))
    ids = {r.id for r in env.data}
    assert a in ids
    assert b not in ids


@pytest.mark.usefixtures("test_db")
async def test_god_tier_sees_all_teams() -> None:
    a = await _create("team-a", "A")
    b = await _create("team-b", "B")
    list_ep = _endpoint(_BASE, "GET")
    env = await list_ep(request=_req(), auth=_auth(None))
    ids = {r.id for r in env.data}
    assert a in ids
    assert b in ids


@pytest.mark.usefixtures("test_db")
async def test_patch_cross_team_is_404() -> None:
    a = await _create("team-a", "A")
    patch_ep = _endpoint(_ONE, "PATCH")
    with pytest.raises(HTTPException) as exc:
        await patch_ep(
            request=_req(),
            report_id=a,
            body=ScheduledReportUpdate(name="hijacked"),
            auth=_auth("team-b"),
        )
    assert exc.value.status_code == 404
    # The row is untouched.
    async with async_session_scope() as s:
        rec = await s.get(ScheduledReportRecord, a)
    assert rec is not None
    assert rec.name == "A"


@pytest.mark.usefixtures("test_db")
async def test_delete_cross_team_is_404() -> None:
    a = await _create("team-a", "A")
    del_ep = _endpoint(_ONE, "DELETE")
    with pytest.raises(HTTPException) as exc:
        await del_ep(request=_req(), report_id=a, auth=_auth("team-b"))
    assert exc.value.status_code == 404
    async with async_session_scope() as s:
        assert await s.get(ScheduledReportRecord, a) is not None


@pytest.mark.usefixtures("test_db")
async def test_delete_own_team_ok() -> None:
    a = await _create("team-a", "A")
    del_ep = _endpoint(_ONE, "DELETE")
    await del_ep(request=_req(), report_id=a, auth=_auth("team-a"))
    async with async_session_scope() as s:
        assert await s.get(ScheduledReportRecord, a) is None


@pytest.mark.usefixtures("test_db")
async def test_trigger_cross_team_is_404() -> None:
    a = await _create("team-a", "A")
    trig_ep = _endpoint(_TRIGGER, "POST")
    with pytest.raises(HTTPException) as exc:
        await trig_ep(request=_req(), report_id=a, auth=_auth("team-b"))
    assert exc.value.status_code == 404
