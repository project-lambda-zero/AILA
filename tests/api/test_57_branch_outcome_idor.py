"""#57 IDOR guard for the VR + malware branch/outcome single-resource routes.

Before this fix, several sub-investigation endpoints in both module routers
loaded a client-supplied branch_id / outcome_id via ``session.get`` (which
bypasses the ``do_orm_execute`` team filter) or via a bare ``select().where``
with no team predicate, and then either returned or mutated the row without
verifying the caller's team owned the parent investigation.

These tests exercise the real router endpoints from ``create_vr_router`` /
``create_malware_router`` against the Postgres ``test_db`` fixture with a
non-admin team-A identity and assert:

- a cross-team caller receives HTTP 404 (never the row, never a 403 that
  would leak existence);
- the owning team still resolves the resource;
- a god-tier admin token (team_id=None, TEAM-06) still resolves any team's
  resource.

Scope: one branch endpoint plus one outcome endpoint per module router, per
the #57 acceptance criteria. The slowapi limiter is disabled process-wide
by the ``_disable_slowapi_limiter`` autouse fixture in
``tests/api/conftest.py``, so the endpoints run their inner closures
directly.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import APIRouter, HTTPException
from sqlmodel import select

from aila.api.auth import AuthContext
from aila.modules.malware.api_router import MalwareOutcomePatch, create_malware_router
from aila.modules.malware.db_models.branch import MalwareInvestigationBranchRecord
from aila.modules.malware.db_models.investigation import MalwareInvestigationRecord
from aila.modules.malware.db_models.outcome import MalwareInvestigationOutcomeRecord
from aila.modules.malware.db_models.target import MalwareTargetRecord
from aila.modules.malware.db_models.workspace import MalwareWorkspaceRecord
from aila.modules.vr.api_router import _BranchOpBody, create_vr_router
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.storage.database import async_session_scope


class _Req:
    """Stand-in Request: the handlers ``del request`` immediately."""


def _endpoint(router: APIRouter, path: str, method: str):
    for route in router.routes:
        if (
            getattr(route, "path", None) == path
            and method in getattr(route, "methods", set())
        ):
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered on {router!r}")


def _auth(team_id: str | None, *, role: str = "analyst") -> AuthContext:
    return AuthContext(
        user_id=f"u-{team_id or 'admin'}",
        role=role,
        auth_type="user",
        team_id=team_id,
    )


# ---------------------------------------------------------------------------
# Malware fixtures + tests
# ---------------------------------------------------------------------------


async def _seed_malware() -> tuple[str, str, str, str]:
    """Seed a team-A investigation+branch+outcome and a team-B one.

    Returns (team_a, team_b, team_b_branch_id, team_b_outcome_id).
    Team-A rows exist so admin-visibility tests have a comparison row and
    so cross-team probes cannot accidentally match by row absence.
    """
    suffix = uuid4().hex[:8]
    team_a = f"team-a-{suffix}"
    team_b = f"team-b-{suffix}"
    async with async_session_scope() as session:  # admin => unfiltered
        wa = MalwareWorkspaceRecord(team_id=team_a, name="A", slug=f"a-{suffix}")
        wb = MalwareWorkspaceRecord(team_id=team_b, name="B", slug=f"b-{suffix}")
        session.add_all([wa, wb])
        await session.flush()
        ta = MalwareTargetRecord(
            team_id=team_a, workspace_id=wa.id, display_name="ta", kind="elf_sample",
        )
        tb = MalwareTargetRecord(
            team_id=team_b, workspace_id=wb.id, display_name="tb", kind="elf_sample",
        )
        session.add_all([ta, tb])
        await session.flush()
        inv_a = MalwareInvestigationRecord(
            team_id=team_a, target_id=ta.id, title="inv-a",
            strategy_family="default",
        )
        inv_b = MalwareInvestigationRecord(
            team_id=team_b, target_id=tb.id, title="inv-b",
            strategy_family="default",
        )
        session.add_all([inv_a, inv_b])
        await session.flush()
        br_b = MalwareInvestigationBranchRecord(investigation_id=inv_b.id)
        session.add(br_b)
        await session.flush()
        oc_b = MalwareInvestigationOutcomeRecord(
            investigation_id=inv_b.id,
            branch_id=br_b.id,
            outcome_kind="analysis_report",
            confidence="strong",
        )
        session.add(oc_b)
        await session.commit()
        return team_a, team_b, br_b.id, oc_b.id


async def test_malware_get_branch_cross_team_is_404(test_db) -> None:
    team_a, _team_b, tb_branch_id, _oc_id = await _seed_malware()
    get_branch = _endpoint(create_malware_router(), "/branches/{branch_id}", "GET")
    with pytest.raises(HTTPException) as exc:
        await get_branch(request=_Req(), branch_id=tb_branch_id, auth=_auth(team_a))
    assert exc.value.status_code == 404


async def test_malware_get_branch_own_team_ok(test_db) -> None:
    _team_a, team_b, tb_branch_id, _oc_id = await _seed_malware()
    get_branch = _endpoint(create_malware_router(), "/branches/{branch_id}", "GET")
    envelope = await get_branch(
        request=_Req(), branch_id=tb_branch_id, auth=_auth(team_b),
    )
    assert envelope.data.id == tb_branch_id


async def test_malware_get_branch_admin_bypass_ok(test_db) -> None:
    _team_a, _team_b, tb_branch_id, _oc_id = await _seed_malware()
    get_branch = _endpoint(create_malware_router(), "/branches/{branch_id}", "GET")
    envelope = await get_branch(
        request=_Req(), branch_id=tb_branch_id, auth=_auth(None, role="admin"),
    )
    assert envelope.data.id == tb_branch_id


async def test_malware_promote_branch_cross_team_is_404_no_mutation(test_db) -> None:
    team_a, _team_b, tb_branch_id, _oc_id = await _seed_malware()
    promote = _endpoint(
        create_malware_router(), "/branches/{branch_id}/promote", "POST",
    )
    with pytest.raises(HTTPException) as exc:
        await promote(request=_Req(), branch_id=tb_branch_id, auth=_auth(team_a))
    assert exc.value.status_code == 404
    async with async_session_scope() as session:
        row = await session.get(MalwareInvestigationBranchRecord, tb_branch_id)
    assert row is not None
    # Cross-team promote must not have flipped the promoted flag.
    assert row.promoted is False


async def test_malware_get_outcome_cross_team_is_404(test_db) -> None:
    team_a, _team_b, _tb_branch_id, tb_outcome_id = await _seed_malware()
    get_outcome = _endpoint(
        create_malware_router(), "/outcomes/{outcome_id}", "GET",
    )
    with pytest.raises(HTTPException) as exc:
        await get_outcome(
            request=_Req(), outcome_id=tb_outcome_id, auth=_auth(team_a),
        )
    assert exc.value.status_code == 404


async def test_malware_get_outcome_own_team_ok(test_db) -> None:
    _team_a, team_b, _tb_branch_id, tb_outcome_id = await _seed_malware()
    get_outcome = _endpoint(
        create_malware_router(), "/outcomes/{outcome_id}", "GET",
    )
    envelope = await get_outcome(
        request=_Req(), outcome_id=tb_outcome_id, auth=_auth(team_b),
    )
    assert envelope.data.id == tb_outcome_id


async def test_malware_get_outcome_admin_bypass_ok(test_db) -> None:
    _team_a, _team_b, _tb_branch_id, tb_outcome_id = await _seed_malware()
    get_outcome = _endpoint(
        create_malware_router(), "/outcomes/{outcome_id}", "GET",
    )
    envelope = await get_outcome(
        request=_Req(),
        outcome_id=tb_outcome_id,
        auth=_auth(None, role="admin"),
    )
    assert envelope.data.id == tb_outcome_id


async def test_malware_patch_outcome_cross_team_is_404_no_mutation(test_db) -> None:
    team_a, _team_b, _tb_branch_id, tb_outcome_id = await _seed_malware()
    patch = _endpoint(
        create_malware_router(), "/outcomes/{outcome_id}", "PATCH",
    )
    body = MalwareOutcomePatch(accepted_by_operator=True)
    with pytest.raises(HTTPException) as exc:
        await patch(
            request=_Req(),
            outcome_id=tb_outcome_id,
            body=body,
            auth=_auth(team_a),
        )
    assert exc.value.status_code == 404
    async with async_session_scope() as session:
        row = await session.get(MalwareInvestigationOutcomeRecord, tb_outcome_id)
    assert row is not None
    # Cross-team patch must not have accepted the outcome.
    assert row.accepted_by_operator is False


# ---------------------------------------------------------------------------
# VR fixtures + tests
# ---------------------------------------------------------------------------


async def _seed_vr() -> tuple[str, str, str, str, str]:
    """Seed a team-A + team-B pair with an investigation, branch, and outcome.

    Returns (team_a, team_b, tb_investigation_id, tb_branch_id, tb_outcome_id).
    """
    suffix = uuid4().hex[:8]
    team_a = f"team-a-{suffix}"
    team_b = f"team-b-{suffix}"
    async with async_session_scope() as session:  # admin => unfiltered
        wa = VRWorkspaceRecord(team_id=team_a, name="A", slug=f"a-{suffix}")
        wb = VRWorkspaceRecord(team_id=team_b, name="B", slug=f"b-{suffix}")
        session.add_all([wa, wb])
        await session.flush()
        ta = VRTargetRecord(
            team_id=team_a, workspace_id=wa.id, display_name="ta",
            kind="native_binary",
        )
        tb = VRTargetRecord(
            team_id=team_b, workspace_id=wb.id, display_name="tb",
            kind="native_binary",
        )
        session.add_all([ta, tb])
        await session.flush()
        inv_a = VRInvestigationRecord(
            team_id=team_a, target_id=ta.id, title="inv-a",
        )
        inv_b = VRInvestigationRecord(
            team_id=team_b, target_id=tb.id, title="inv-b",
        )
        session.add_all([inv_a, inv_b])
        await session.flush()
        br_b = VRInvestigationBranchRecord(investigation_id=inv_b.id)
        session.add(br_b)
        await session.flush()
        oc_b = VRInvestigationOutcomeRecord(
            investigation_id=inv_b.id,
            branch_id=br_b.id,
            outcome_kind="direct_finding",
            confidence="high",
        )
        session.add(oc_b)
        await session.commit()
        return team_a, team_b, inv_b.id, br_b.id, oc_b.id


async def test_vr_branch_pause_cross_team_is_404_no_mutation(test_db) -> None:
    """A branch endpoint scoped through the investigation URL must 404 for
    a cross-team caller. VR's ``_load_branch_or_404`` loads the parent
    investigation with the team filter before touching the branch, so the
    request never reaches the mutation. The branch's status stays untouched.
    """
    team_a, _team_b, tb_inv_id, tb_branch_id, _oc_id = await _seed_vr()
    pause = _endpoint(
        create_vr_router(),
        "/investigations/{investigation_id}/branches/{branch_id}/pause",
        "POST",
    )
    with pytest.raises(HTTPException) as exc:
        await pause(
            request=_Req(),
            investigation_id=tb_inv_id,
            branch_id=tb_branch_id,
            body=_BranchOpBody(reason="unauthorized"),
            auth=_auth(team_a),
        )
    assert exc.value.status_code == 404
    async with async_session_scope() as session:
        row = await session.get(VRInvestigationBranchRecord, tb_branch_id)
    assert row is not None
    assert row.status != "paused"


async def test_vr_branch_pause_own_team_reaches_manager(test_db) -> None:
    """The owning team clears the ownership gate; the BranchManager then
    resolves the branch state itself. We assert only that the ownership
    guard passed by expecting either a manager-raised 409 (branch state
    machine refused the transition) or the manager's DataEnvelope on
    success. A 404 here would prove the guard is still blocking the caller.
    """
    _team_a, team_b, tb_inv_id, tb_branch_id, _oc_id = await _seed_vr()
    pause = _endpoint(
        create_vr_router(),
        "/investigations/{investigation_id}/branches/{branch_id}/pause",
        "POST",
    )
    try:
        await pause(
            request=_Req(),
            investigation_id=tb_inv_id,
            branch_id=tb_branch_id,
            body=_BranchOpBody(reason="own-team-ok"),
            auth=_auth(team_b),
        )
    except HTTPException as exc:
        # Anything other than 404 means the ownership guard passed and the
        # BranchManager itself decided the outcome (e.g. 409 for a
        # branch that lacks the expected cursor state to pause). 404 =
        # the guard is still incorrectly blocking the owning team.
        assert exc.status_code != 404, (
            "owning team must clear the guard; a 404 here would be a "
            "regression of the same #57 shape the fix is closing."
        )


async def test_vr_branch_pause_admin_bypass_reaches_manager(test_db) -> None:
    """God-tier admin (team_id=None, TEAM-06) sees every team's rows.

    Same 404-vs-anything-else contract as the owning-team test above:
    the guard must not reject an admin token.
    """
    _team_a, _team_b, tb_inv_id, tb_branch_id, _oc_id = await _seed_vr()
    pause = _endpoint(
        create_vr_router(),
        "/investigations/{investigation_id}/branches/{branch_id}/pause",
        "POST",
    )
    try:
        await pause(
            request=_Req(),
            investigation_id=tb_inv_id,
            branch_id=tb_branch_id,
            body=_BranchOpBody(reason="admin-visibility"),
            auth=_auth(None, role="admin"),
        )
    except HTTPException as exc:
        assert exc.status_code != 404, (
            "admin bypass must clear the guard; a 404 here would prove "
            "the team filter accidentally excludes admin."
        )


async def test_vr_outcome_reviews_list_cross_team_is_404(test_db) -> None:
    """Even when the caller supplies their OWN investigation_id in the URL,
    a foreign outcome_id must 404 -- the fix cross-checks that the outcome
    row's ``investigation_id`` matches the URL segment before returning
    reviews. Without this the URL would only prove ownership of one
    investigation while the outcome could point at another team's row.
    """
    team_a, _team_b, tb_inv_id, _tb_branch_id, tb_outcome_id = await _seed_vr()
    # Team-A also needs an owned investigation so the URL segment resolves
    # for the caller before the outcome cross-check gets a chance to fire.
    async with async_session_scope() as session:
        inv_a = (await session.exec(  # type: ignore[attr-defined]
            _tenant_agnostic_select_first_team_investigation(team_a),
        )).first()
        assert inv_a is not None, "team-A investigation not seeded"
        ta_inv_id = inv_a.id
    reviews = _endpoint(
        create_vr_router(),
        "/investigations/{investigation_id}/outcomes/{outcome_id}/reviews",
        "GET",
    )
    # Case 1: caller supplies team-A's investigation + team-B's outcome.
    with pytest.raises(HTTPException) as exc:
        await reviews(
            request=_Req(),
            investigation_id=ta_inv_id,
            outcome_id=tb_outcome_id,
            auth=_auth(team_a),
        )
    assert exc.value.status_code == 404
    # Case 2: caller supplies team-B's investigation + team-B's outcome
    # (foreign investigation guard runs first).
    with pytest.raises(HTTPException) as exc:
        await reviews(
            request=_Req(),
            investigation_id=tb_inv_id,
            outcome_id=tb_outcome_id,
            auth=_auth(team_a),
        )
    assert exc.value.status_code == 404
    # Suppress unused import warning: tb_inv_id has been used above.
    _ = tb_inv_id


async def test_vr_outcome_reviews_list_own_team_ok(test_db) -> None:
    _team_a, team_b, tb_inv_id, _tb_branch_id, tb_outcome_id = await _seed_vr()
    reviews = _endpoint(
        create_vr_router(),
        "/investigations/{investigation_id}/outcomes/{outcome_id}/reviews",
        "GET",
    )
    envelope = await reviews(
        request=_Req(),
        investigation_id=tb_inv_id,
        outcome_id=tb_outcome_id,
        auth=_auth(team_b),
    )
    # No reviews seeded; the fix returned an empty list rather than 404.
    assert envelope.data == []


async def test_vr_outcome_reviews_list_admin_bypass_ok(test_db) -> None:
    _team_a, _team_b, tb_inv_id, _tb_branch_id, tb_outcome_id = await _seed_vr()
    reviews = _endpoint(
        create_vr_router(),
        "/investigations/{investigation_id}/outcomes/{outcome_id}/reviews",
        "GET",
    )
    envelope = await reviews(
        request=_Req(),
        investigation_id=tb_inv_id,
        outcome_id=tb_outcome_id,
        auth=_auth(None, role="admin"),
    )
    assert envelope.data == []


def _tenant_agnostic_select_first_team_investigation(team_id: str):
    """Small helper: fetch one investigation belonging to ``team_id`` via
    an admin session so tests don't have to re-thread the team_id back out
    of the seed helper. The select is done from an admin session_scope so
    no team_context filter interferes.
    """
    return (
        select(VRInvestigationRecord)
        .where(VRInvestigationRecord.team_id == team_id)
        .limit(1)
    )
