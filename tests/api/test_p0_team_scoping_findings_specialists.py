"""P0 team-scoping regression tests for RFC-208 (#99, #100).

Two currently-unscoped surfaces gain a nullable, indexed ``team_id``
column and API-layer filtering. Each test in this file:

1. FAILS on the pre-fix code -- either because the column does not
   exist on the model (AttributeError / column-does-not-exist), or
   because the router bypasses the team predicate and lets a team-A
   caller reach a team-B row.
2. PASSES after migration 120, the router edits, and the registry
   rewrite.

Endpoints are exercised by direct handler invocation (matches the
``tests/api/test_scheduled_report_team_scope.py`` pattern) so the
slowapi ``request``-injection contract is satisfied by a stub Request
namespace. The autouse ``_disable_slowapi_limiter`` fixture (see
``tests/api/conftest.py``) keeps rate limits out of the way.
"""
from __future__ import annotations

import types

import pytest
from fastapi import HTTPException
from sqlmodel import select

from aila.api.auth import AuthContext
from aila.api.routers.findings_workflow import router as fw_router
from aila.api.routers.specialist_agents import router as sp_router
from aila.api.schemas.endpoints import FindingTransitionRequest
from aila.platform.contracts.finding_states import FINDING_STATE_TRANSITIONS
from aila.platform.services.specialist_registry import (
    SpecialistAgentCreate,
    SpecialistAgentRecord,
    SpecialistAgentRegistry,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import FindingWorkflowRecord

# ---------------------------------------------------------------------------
# Test doubles / helpers
# ---------------------------------------------------------------------------


def _req() -> object:
    """Minimal Request stub good enough for the handlers used here.

    The workflow router reads ``request.app.state.platform`` when
    resolving the finding state machine; a ``None`` platform falls
    through to the ``FINDING_STATE_TRANSITIONS`` base map, which
    already accepts ``new -> investigating``, the transition every
    test in this file uses.
    """
    return types.SimpleNamespace(
        app=types.SimpleNamespace(state=types.SimpleNamespace(platform=None))
    )


def _auth(team_id: str | None, *, role: str = "operator") -> AuthContext:
    return AuthContext(
        user_id="u-" + (team_id or "god"),
        role=role,
        auth_type="user",
        team_id=team_id,
    )


def _endpoint(router, path: str, method: str):
    for route in router.routes:
        if getattr(route, "path", None) == path and method in getattr(
            route, "methods", set()
        ):
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


# ---------------------------------------------------------------------------
# Sanity: ``new`` really is transitionable in the base state machine.
# The test transitions below fail loudly if this ever regresses so the
# error blames the state machine, not the team scoping.
# ---------------------------------------------------------------------------


def test_base_state_machine_permits_new_to_investigating() -> None:
    assert "investigating" in FINDING_STATE_TRANSITIONS.get("new", [])


# ---------------------------------------------------------------------------
# #99 finding workflow -- team-scoped reads and transitions
# ---------------------------------------------------------------------------


_FW_HISTORY = "/findings/{finding_id}/workflow"
_FW_TRANSITION = "/findings/{finding_id}/transition"


async def _seed_transition(finding_id: str, team_id: str | None) -> str:
    """Insert one FindingWorkflowRecord for ``finding_id`` owned by ``team_id``.

    Bypasses the API layer so we can seed rows for BOTH teams without
    the router refusing on cross-team writes.
    """
    async with async_session_scope() as session:
        record = FindingWorkflowRecord(
            finding_id=finding_id,
            module_id="platform",
            current_state="investigating",
            previous_state="new",
            transitioned_by="seed",
            notes="",
            team_id=team_id,
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)
        return record.id


@pytest.mark.usefixtures("test_db")
async def test_fw_get_own_team_returns_history() -> None:
    """team-a operator sees the history row it owns."""
    await _seed_transition("F-OWNED", "team-a")
    get_ep = _endpoint(fw_router, _FW_HISTORY, "GET")
    env = await get_ep(
        request=_req(), finding_id="F-OWNED", auth=_auth("team-a"),
    )
    assert env.data.current_state == "investigating"
    assert len(env.data.history) == 1
    assert env.data.history[0].finding_id == "F-OWNED"


@pytest.mark.usefixtures("test_db")
async def test_fw_get_cross_team_is_404() -> None:
    """team-a operator hitting team-b's finding row gets 404, not 200."""
    await _seed_transition("F-B-ONLY", "team-b")
    get_ep = _endpoint(fw_router, _FW_HISTORY, "GET")
    with pytest.raises(HTTPException) as exc:
        await get_ep(
            request=_req(), finding_id="F-B-ONLY", auth=_auth("team-a"),
        )
    assert exc.value.status_code == 404


@pytest.mark.usefixtures("test_db")
async def test_fw_admin_sees_all_teams() -> None:
    """A god-tier admin (team_id=None) reads any team's history."""
    await _seed_transition("F-B-ONLY-ADMIN", "team-b")
    get_ep = _endpoint(fw_router, _FW_HISTORY, "GET")
    env = await get_ep(
        request=_req(), finding_id="F-B-ONLY-ADMIN",
        auth=_auth(None, role="admin"),
    )
    assert env.data.current_state == "investigating"
    assert len(env.data.history) == 1


@pytest.mark.usefixtures("test_db")
async def test_fw_transition_stamps_team_id() -> None:
    """A team-scoped transition stamps ``team_id`` on the new row."""
    trans_ep = _endpoint(fw_router, _FW_TRANSITION, "POST")
    env = await trans_ep(
        request=_req(),
        finding_id="F-STAMP",
        body=FindingTransitionRequest(target_state="investigating"),
        auth=_auth("team-a"),
    )
    assert env.data.current_state == "investigating"
    async with async_session_scope() as session:
        rows = (await session.exec(
            select(FindingWorkflowRecord)
            .where(FindingWorkflowRecord.finding_id == "F-STAMP")
        )).all()
    assert len(rows) == 1
    assert rows[0].team_id == "team-a"


@pytest.mark.usefixtures("test_db")
async def test_fw_transition_cross_team_is_404() -> None:
    """team-a cannot append onto team-b's existing history.

    Seeding a team-b row for ``F-CROSS`` and then trying to transition
    as team-a must 404 instead of silently forking a new chain.
    """
    await _seed_transition("F-CROSS", "team-b")
    trans_ep = _endpoint(fw_router, _FW_TRANSITION, "POST")
    with pytest.raises(HTTPException) as exc:
        await trans_ep(
            request=_req(),
            finding_id="F-CROSS",
            body=FindingTransitionRequest(target_state="investigating"),
            auth=_auth("team-a"),
        )
    assert exc.value.status_code == 404
    # And the underlying row is untouched: still exactly one row, owned
    # by team-b.
    async with async_session_scope() as session:
        rows = (await session.exec(
            select(FindingWorkflowRecord)
            .where(FindingWorkflowRecord.finding_id == "F-CROSS")
        )).all()
    assert len(rows) == 1
    assert rows[0].team_id == "team-b"


# ---------------------------------------------------------------------------
# #100 specialist agents -- team-scoped CRUD with global built-in visibility
# ---------------------------------------------------------------------------


_SP_LIST = ""
_SP_UPSERT = ""
_SP_DELETE = "/{module_id}/{name}"


def _sp_endpoint(path: str, method: str):
    # Router mounts at prefix ``/agents/specialists``; the routes above
    # are the tail paths. The helper takes the full path.
    full = "/agents/specialists" + path
    return _endpoint(sp_router, full, method)


async def _seed_global_builtin(module_id: str, name: str, capability: str) -> str:
    """Insert a NULL-team built-in row via the registry admin path."""
    reg = SpecialistAgentRegistry()
    summary = await reg.upsert(
        SpecialistAgentCreate(
            module_id=module_id, name=name, capability=capability,
            description=f"builtin {name}",
        ),
        team_id=None,
        is_admin=True,
    )
    assert summary.team_id is None
    return summary.id


async def _seed_team_specialist(
    module_id: str, name: str, capability: str, team_id: str,
) -> str:
    """Insert a team-owned specialist via the registry."""
    reg = SpecialistAgentRegistry()
    summary = await reg.upsert(
        SpecialistAgentCreate(
            module_id=module_id, name=name, capability=capability,
            description=f"{team_id} {name}",
        ),
        team_id=team_id,
        is_admin=False,
    )
    assert summary.team_id == team_id
    return summary.id


@pytest.mark.usefixtures("test_db")
async def test_sp_list_hides_other_teams_but_shows_globals() -> None:
    """team-a sees its own row + NULL-team globals, never team-b's."""
    await _seed_global_builtin("vr", "global-x", "binary-audit")
    await _seed_team_specialist("vr", "a-secret", "kernel-audit", "team-a")
    await _seed_team_specialist("vr", "b-secret", "exploit-dev", "team-b")

    list_ep = _sp_endpoint(_SP_LIST, "GET")
    env = await list_ep(
        request=_req(), module_id="vr", enabled_only=False,
        auth=_auth("team-a"),
    )
    names = {row.name for row in env.data}
    assert "global-x" in names, "team-a must see NULL-team built-in"
    assert "a-secret" in names, "team-a must see its own row"
    assert "b-secret" not in names, "team-a must NOT see team-b's row"


@pytest.mark.usefixtures("test_db")
async def test_sp_list_admin_sees_every_team() -> None:
    """A god-tier admin (team_id=None) sees all teams' specialists."""
    await _seed_global_builtin("vr", "global-y", "binary-audit")
    await _seed_team_specialist("vr", "a-only", "kernel-audit", "team-a")
    await _seed_team_specialist("vr", "b-only", "exploit-dev", "team-b")

    list_ep = _sp_endpoint(_SP_LIST, "GET")
    env = await list_ep(
        request=_req(), module_id="vr", enabled_only=False,
        auth=_auth(None, role="admin"),
    )
    names = {row.name for row in env.data}
    assert {"global-y", "a-only", "b-only"} <= names


@pytest.mark.usefixtures("test_db")
async def test_sp_delete_own_team_ok() -> None:
    """A team-scoped operator may delete its own specialist."""
    await _seed_team_specialist("vr", "a-drop", "kernel-audit", "team-a")
    del_ep = _sp_endpoint(_SP_DELETE, "DELETE")
    env = await del_ep(
        request=_req(), module_id="vr", name="a-drop",
        auth=_auth("team-a"),
    )
    assert env.data["deleted"] is True


@pytest.mark.usefixtures("test_db")
async def test_sp_delete_cross_team_reports_not_deleted() -> None:
    """team-a asking to delete team-b's row is a no-op (not deleted).

    The router returns ``{"deleted": False}`` -- same envelope shape as
    the "already gone" case -- so no existence oracle leaks. The
    underlying row survives.
    """
    await _seed_team_specialist("vr", "b-locked", "exploit-dev", "team-b")
    del_ep = _sp_endpoint(_SP_DELETE, "DELETE")
    env = await del_ep(
        request=_req(), module_id="vr", name="b-locked",
        auth=_auth("team-a"),
    )
    assert env.data["deleted"] is False

    # Row must still be there.
    async with async_session_scope() as session:
        rows = (await session.exec(
            select(SpecialistAgentRecord).where(
                SpecialistAgentRecord.module_id == "vr",
            )
        )).all()
    names = {r.name for r in rows}
    assert "b-locked" in names


@pytest.mark.usefixtures("test_db")
async def test_sp_delete_global_builtin_by_non_admin_is_no_op() -> None:
    """A team-scoped operator cannot delete a NULL-team built-in."""
    await _seed_global_builtin("vr", "global-keep", "binary-audit")
    del_ep = _sp_endpoint(_SP_DELETE, "DELETE")
    env = await del_ep(
        request=_req(), module_id="vr", name="global-keep",
        auth=_auth("team-a"),
    )
    assert env.data["deleted"] is False

    # And an admin can still delete it.
    env2 = await del_ep(
        request=_req(), module_id="vr", name="global-keep",
        auth=_auth(None, role="admin"),
    )
    assert env2.data["deleted"] is True


@pytest.mark.usefixtures("test_db")
async def test_sp_upsert_stamps_caller_team() -> None:
    """A team-scoped operator's new specialist is stamped with its team."""
    upsert_ep = _sp_endpoint(_SP_UPSERT, "POST")
    env = await upsert_ep(
        request=_req(),
        body=SpecialistAgentCreate(
            module_id="vr", name="a-fresh", capability="kernel-audit",
            description="team-a fresh",
        ),
        auth=_auth("team-a"),
    )
    assert env.data.team_id == "team-a"
