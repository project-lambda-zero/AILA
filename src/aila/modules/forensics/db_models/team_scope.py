"""Formal team-isolation join contract for the forensics module.

Background
----------

The forensics module scopes rows to a tenant (team) through a single
root table:

    ``forensics_projects`` (:class:`ForensicsProjectRecord`)
        The row that owns the tenant assignment. Every child row
        derives its tenant from this parent via the ``project_id``
        foreign key.

As of migration ``109_forensics_child_team_id`` (#59), four of the
child tables also carry a redundant ``team_id`` column:

    ``forensics_investigations``    (:class:`InvestigationRunRecord`)
    ``forensics_agent_steps``       (:class:`AgentStepRecord`)
    ``forensics_writeups``          (:class:`WriteUpRecord`)
    ``forensics_answer_candidates`` (:class:`AnswerCandidateRecord`)

Every write path stamps that column from the parent project's
``team_id`` at insert time so the platform ``do_orm_execute`` team-scope
listener (see :mod:`aila.platform.services.team_scope`) can auto-inject
``WHERE team_id = :caller`` on reads without a two-hop parent join.
The project-ownership guard (:func:`require_project_ownership` /
:func:`load_project_for_team`) still runs on the parent row and is now
a defense-in-depth check rather than the sole barrier.

The remaining project-scoped children -- analyst directives, finding
suppressions, solid evidence, artifacts, leads, project evidence --
have NO ``team_id`` column. They are still project-scoped: their tenant
is derived transitively through the ``project_id`` join and every
reader MUST resolve the parent project first and reject the request
when it does not match the caller's ``AuthContext.team_id``. Skipping
that step leaks cross-tenant data silently.

This module formalises the rule as a single source of truth so:

* The router calls :func:`require_project_ownership` in exactly one
  place (via the closure in ``api_router.create_forensics_router``)
  rather than reimplementing the check per endpoint.
* A test can enumerate :data:`PROJECT_SCOPED_CHILDREN` and assert
  contract completeness -- adding a new child table without adding
  it to the contract fails the test.
* A future honesty-audit rule can grep for ``select(<child>)`` calls
  in the module and require a preceding ``require_project_ownership``
  or ``load_project_for_team`` call in the same handler.

Contract
--------

* :data:`TEAM_SCOPED_PARENT` -- the sole row carrying ``team_id``.
* :data:`TEAM_ID_COLUMN` / :data:`PROJECT_ID_COLUMN` -- the canonical
  column names, so downstream tooling does not hard-code strings.
* :data:`PROJECT_SCOPED_CHILDREN` -- every child SQLModel plus the
  name of the FK column back to :data:`TEAM_SCOPED_PARENT` (currently
  ``"project_id"`` for all of them).
* :func:`require_project_ownership` -- pure sync guard on an already
  loaded parent row.
* :func:`load_project_for_team` -- async load + guard for the common
  case in an endpoint (load parent, 404 if missing, 403 if the
  caller's team does not own it).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import HTTPException, status
from sqlmodel import select

from .artifact import ArtifactRecord, LeadRecord
from .directive import AnalystDirectiveRecord
from .finding_suppression import FindingSuppressionRecord
from .investigation import AgentStepRecord, InvestigationRunRecord, WriteUpRecord
from .project import ForensicsProjectRecord, ProjectEvidenceRecord
from .question import AnswerCandidateRecord
from .solid_evidence import SolidEvidenceRecord

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

__all__ = [
    "PROJECT_ID_COLUMN",
    "PROJECT_SCOPED_CHILDREN",
    "TEAM_ID_COLUMN",
    "TEAM_SCOPED_PARENT",
    "load_project_for_team",
    "require_project_ownership",
]


# The single team-scoped root row: every other forensics table joins
# back to this via ``project_id``.
TEAM_SCOPED_PARENT: type[Any] = ForensicsProjectRecord

# Canonical column names, exported so tests and audits do not hard-code
# string literals.
TEAM_ID_COLUMN: str = "team_id"
PROJECT_ID_COLUMN: str = "project_id"


# Every project-scoped child table plus the FK column that joins back
# to :data:`TEAM_SCOPED_PARENT`. The FK is currently uniform
# (``project_id``) but the mapping is kept explicit so a future schema
# change surfaces in the contract, not in a silent grep-and-fix pass.
#
# Test invariants (asserted in tests/api/test_forensics_team_join_contract.py):
#   * Every SQLModel in :mod:`aila.modules.forensics.db_models` that
#     declares a ``project_id`` field appears here.
#   * :data:`TEAM_SCOPED_PARENT` is NOT present in this mapping.
#   * Every mapping value names a real field on the mapped model.
PROJECT_SCOPED_CHILDREN: dict[type[Any], str] = {
    InvestigationRunRecord: PROJECT_ID_COLUMN,
    AgentStepRecord: "investigation_id",  # joins via investigations.project_id
    WriteUpRecord: PROJECT_ID_COLUMN,
    AnswerCandidateRecord: PROJECT_ID_COLUMN,
    AnalystDirectiveRecord: PROJECT_ID_COLUMN,
    FindingSuppressionRecord: PROJECT_ID_COLUMN,
    SolidEvidenceRecord: PROJECT_ID_COLUMN,
    ArtifactRecord: PROJECT_ID_COLUMN,
    LeadRecord: PROJECT_ID_COLUMN,
    ProjectEvidenceRecord: PROJECT_ID_COLUMN,
}


def require_project_ownership(project: Any, auth_team_id: str | None) -> None:
    """Guard: raise HTTP 403 if ``project`` is not owned by ``auth_team_id``.

    ``auth_team_id`` follows the platform convention (see
    :class:`aila.api.auth.AuthContext`):

    * ``None`` -- admin / god-tier caller; every project passes.
    * non-``None`` -- caller MUST match ``project.team_id`` exactly.

    A project row whose ``team_id`` is ``None`` (created before team
    isolation existed, or admin-owned) is treated as unowned and
    accessible ONLY by an admin caller: a team-scoped caller trying to
    read it is rejected. This matches the behaviour of
    ``_team_filter`` in ``api_router.py`` (``WHERE team_id == <caller>``
    excludes NULL-team rows for team callers), keeping the two paths
    consistent.
    """
    if auth_team_id is None:
        return
    record_team = getattr(project, TEAM_ID_COLUMN, None)
    if record_team != auth_team_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Project is not owned by your team.",
        )


async def load_project_for_team(
    session: AsyncSession,
    project_id: str,
    auth_team_id: str | None,
) -> Any:
    """Load and return the project row after enforcing team ownership.

    Raises:
        HTTPException 404 -- project row does not exist.
        HTTPException 403 -- project belongs to a different team.

    The returned row is a :class:`ForensicsProjectRecord` (typed as
    ``Any`` to avoid circular import concerns at type-check time).
    """
    project = (
        await session.exec(
            select(TEAM_SCOPED_PARENT).where(TEAM_SCOPED_PARENT.id == project_id)  # type: ignore[attr-defined]
        )
    ).first()
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found.",
        )
    require_project_ownership(project, auth_team_id)
    return project
