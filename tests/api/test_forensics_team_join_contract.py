"""#59 -- forensics team-isolation join contract completeness + enforcement.

The audit's PARTIAL residual on ``child tables carry team_id or a
documented join contract`` is closed here. As of migration
``109_forensics_child_team_id``, four child tables
(``forensics_investigations``, ``forensics_agent_steps``,
``forensics_writeups``, ``forensics_answer_candidates``) carry a
denormalised ``team_id`` column stamped from the parent project on
every write path. The remaining project-scoped child tables (analyst
directives, finding suppressions, solid evidence, artifacts, leads,
project evidence) still have NO ``team_id`` column and inherit their
tenant transitively through the parent
:class:`ForensicsProjectRecord.team_id` via a project-ownership check
that MUST run before any child-table read.

The formal contract lives in
``src/aila/modules/forensics/db_models/team_scope.py`` and exposes:

* :data:`PROJECT_SCOPED_CHILDREN` -- enumeration of every child model
  and the FK column joining back to the parent.
* :data:`TEAM_SCOPED_PARENT` -- the sole team-scoped root.
* :func:`require_project_ownership` -- pure sync guard on an already
  loaded parent row.
* :func:`load_project_for_team` -- async load-then-guard for the
  common endpoint case.

These tests pin:

1. Contract completeness -- every ``project_id``-bearing SQLModel in
   the forensics db_models package is in the contract (so adding a new
   child without adding it to the contract fails the test).
2. The sync guard's precise semantics: same-team pass, admin pass,
   cross-team 403, project-owned-by-None rejected by team callers.
3. The async loader's precise semantics: 404 on missing project,
   403 on team mismatch, row returned on match / admin.
4. End-to-end: ``list_investigations`` returns 403 when the caller's
   team does not own the project, proving the contract is enforced at
   the router layer for a representative child-table read.

Runs against ``AILA_TEST_DATABASE_URL`` via the shared ``test_db``
fixture (see ``tests/api/conftest.py``).
"""
from __future__ import annotations

import inspect
from uuid import uuid4

import pytest
from fastapi import HTTPException, status

from aila.api.auth import AuthContext
from aila.modules.forensics import db_models as _forensics_models
from aila.modules.forensics.api_router import create_forensics_router
from aila.modules.forensics.api_router import limiter as _forensics_limiter
from aila.modules.forensics.db_models import (
    PROJECT_ID_COLUMN,
    PROJECT_SCOPED_CHILDREN,
    TEAM_ID_COLUMN,
    TEAM_SCOPED_PARENT,
    ForensicsProjectRecord,
    InvestigationRunRecord,
    load_project_for_team,
    require_project_ownership,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord

# --------------------------------------------------------------------------
# Shared fixtures + helpers
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _disable_forensics_limiter():
    """Disable the module-local slowapi limiter for direct-invocation tests."""
    prev = _forensics_limiter.enabled
    _forensics_limiter.enabled = False
    yield
    _forensics_limiter.enabled = prev


class _Req:
    """Minimal stand-in for FastAPI ``Request`` (``del request`` early)."""


def _endpoint(path: str, method: str):
    """Look up a route handler by path + method on a fresh router."""
    for route in create_forensics_router().routes:
        methods = getattr(route, "methods", set()) or set()
        if getattr(route, "path", None) == path and method in methods:
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


def _auth(team_id: str | None, role: str = "operator") -> AuthContext:
    return AuthContext(
        user_id=f"u-{team_id or 'admin'}",
        role=role,
        auth_type="user",
        team_id=team_id,
    )


async def _seed_project(suffix: str, team_id: str | None) -> str:
    async with async_session_scope() as session:
        sys_rec = ManagedSystemRecord(
            name=f"sys-{suffix}", host="10.0.0.1", username="u",
        )
        session.add(sys_rec)
        await session.flush()
        proj = ForensicsProjectRecord(
            name=f"proj-{suffix}",
            system_id=sys_rec.id,
            team_id=team_id,
            evidence_directory=f"/tmp/{suffix}",
        )
        session.add(proj)
        await session.flush()
        pid = proj.id
        await session.commit()
    return pid


# --------------------------------------------------------------------------
# Contract completeness
# --------------------------------------------------------------------------


def _forensics_child_models_with_project_id() -> set[type]:
    """Every SQLModel table in the forensics db_models pkg with a
    ``project_id`` field, excluding the team-scoped parent itself."""
    found: set[type] = set()
    for name in _forensics_models.__all__:
        obj = getattr(_forensics_models, name)
        if not inspect.isclass(obj):
            continue
        # SQLModel table classes carry model_fields.
        if not hasattr(obj, "model_fields"):
            continue
        # The parent table is NOT a child; its team scope is intrinsic.
        if obj is TEAM_SCOPED_PARENT:
            continue
        if PROJECT_ID_COLUMN in obj.model_fields:
            found.add(obj)
    return found


def test_contract_covers_every_project_scoped_child_model() -> None:
    """PROJECT_SCOPED_CHILDREN enumerates every child with a project_id.

    A new child table added without an entry here fails this test --
    the module owner MUST either denormalise ``team_id`` onto the new
    table OR extend the contract mapping (the second option keeps the
    schema tidy and requires no migration).
    """
    declared_children = set(PROJECT_SCOPED_CHILDREN.keys())
    discovered_children = _forensics_child_models_with_project_id()
    missing = discovered_children - declared_children
    assert not missing, (
        "PROJECT_SCOPED_CHILDREN is missing forensics child model(s): "
        f"{sorted(m.__name__ for m in missing)}. Add them to the "
        "contract in aila.modules.forensics.db_models.team_scope."
    )


def test_team_scoped_parent_carries_team_id_column() -> None:
    """TEAM_SCOPED_PARENT must actually declare TEAM_ID_COLUMN."""
    assert TEAM_SCOPED_PARENT is ForensicsProjectRecord
    assert TEAM_ID_COLUMN in TEAM_SCOPED_PARENT.model_fields, (
        f"{TEAM_SCOPED_PARENT.__name__} is declared as the team-scoped "
        f"root but has no {TEAM_ID_COLUMN!r} field."
    )


def test_contract_never_lists_parent_as_child() -> None:
    """The parent is not a child of itself -- guards against a footgun
    where the closure loop would try to enforce ownership on the row it
    is already gating."""
    assert TEAM_SCOPED_PARENT not in PROJECT_SCOPED_CHILDREN


def test_contract_fk_columns_are_real_fields() -> None:
    """Every mapping value must name a real field on the mapped model."""
    for model, fk_column in PROJECT_SCOPED_CHILDREN.items():
        assert fk_column in model.model_fields, (
            f"PROJECT_SCOPED_CHILDREN[{model.__name__}] = {fk_column!r} "
            f"but that field does not exist on the model."
        )


# --------------------------------------------------------------------------
# require_project_ownership pure semantics
# --------------------------------------------------------------------------


def test_require_project_ownership_same_team_passes() -> None:
    proj = ForensicsProjectRecord(
        name="p", system_id=1, evidence_directory="/tmp/x", team_id="team-a",
    )
    require_project_ownership(proj, "team-a")


def test_require_project_ownership_admin_passes_for_any_team() -> None:
    """auth_team_id=None is the admin god-tier: no rejection ever."""
    proj_a = ForensicsProjectRecord(
        name="a", system_id=1, evidence_directory="/tmp/a", team_id="team-a",
    )
    proj_b = ForensicsProjectRecord(
        name="b", system_id=1, evidence_directory="/tmp/b", team_id=None,
    )
    require_project_ownership(proj_a, None)
    require_project_ownership(proj_b, None)


def test_require_project_ownership_cross_team_raises_403() -> None:
    proj = ForensicsProjectRecord(
        name="p", system_id=1, evidence_directory="/tmp/x", team_id="team-a",
    )
    with pytest.raises(HTTPException) as info:
        require_project_ownership(proj, "team-b")
    assert info.value.status_code == status.HTTP_403_FORBIDDEN


def test_require_project_ownership_null_team_project_rejected_by_team_caller() -> None:
    """A row whose team_id is None is admin-owned and MUST reject any
    team-scoped caller. This mirrors the ``WHERE team_id == :caller``
    filter used by ``_team_filter`` in the router (which excludes
    NULL-team rows for team callers)."""
    proj = ForensicsProjectRecord(
        name="p", system_id=1, evidence_directory="/tmp/x", team_id=None,
    )
    with pytest.raises(HTTPException) as info:
        require_project_ownership(proj, "team-a")
    assert info.value.status_code == status.HTTP_403_FORBIDDEN


# --------------------------------------------------------------------------
# load_project_for_team async semantics
# --------------------------------------------------------------------------


async def test_load_project_for_team_returns_row_on_match(test_db) -> None:
    suffix = uuid4().hex[:8]
    pid = await _seed_project(suffix, team_id="team-a")
    async with async_session_scope() as session:
        row = await load_project_for_team(session, pid, "team-a")
    assert row is not None
    assert row.id == pid
    assert row.team_id == "team-a"


async def test_load_project_for_team_admin_bypasses_gate(test_db) -> None:
    suffix = uuid4().hex[:8]
    pid = await _seed_project(suffix, team_id="team-a")
    async with async_session_scope() as session:
        row = await load_project_for_team(session, pid, None)
    assert row.id == pid


async def test_load_project_for_team_missing_raises_404(test_db) -> None:
    async with async_session_scope() as session:
        with pytest.raises(HTTPException) as info:
            await load_project_for_team(session, "does-not-exist", "team-a")
    assert info.value.status_code == status.HTTP_404_NOT_FOUND


async def test_load_project_for_team_mismatch_raises_403(test_db) -> None:
    suffix = uuid4().hex[:8]
    pid = await _seed_project(suffix, team_id="team-a")
    async with async_session_scope() as session:
        with pytest.raises(HTTPException) as info:
            await load_project_for_team(session, pid, "team-b")
    assert info.value.status_code == status.HTTP_403_FORBIDDEN


# --------------------------------------------------------------------------
# End-to-end: router enforces the contract on a representative child read
# --------------------------------------------------------------------------


async def test_list_investigations_rejects_cross_team_reader(test_db) -> None:
    """A caller from team-b MUST get 403 when reading investigations
    on a project owned by team-a. Since migration 109 the child rows
    also carry a denormalised ``team_id`` column, but the router still
    fails-fast on the project-ownership guard before the child query
    runs -- proving the transitive join contract is enforced end-to-end
    at the router boundary regardless of any listener-injected filter."""
    suffix = uuid4().hex[:8]
    pid = await _seed_project(suffix, team_id="team-a")
    async with async_session_scope() as session:
        session.add(InvestigationRunRecord(project_id=pid, question="q1"))
        session.add(InvestigationRunRecord(project_id=pid, question="q2"))
        await session.commit()

    list_investigations = _endpoint(
        "/projects/{project_id}/investigations", "GET",
    )

    # team-a: sees both rows.
    envelope_a = await list_investigations(
        request=_Req(),
        project_id=pid,
        auth=_auth("team-a"),
        page=1,
        page_size=10,
    )
    assert len(envelope_a.data) == 2

    # team-b: rejected by the join contract.
    with pytest.raises(HTTPException) as info:
        await list_investigations(
            request=_Req(),
            project_id=pid,
            auth=_auth("team-b"),
            page=1,
            page_size=10,
        )
    assert info.value.status_code == status.HTTP_403_FORBIDDEN, (
        "list_investigations MUST reject a cross-team caller with 403; "
        "the child table has no team_id column so the guard runs on the "
        "parent project. See docs in "
        "aila.modules.forensics.db_models.team_scope."
    )
