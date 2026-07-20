"""#59 delete_project must purge every project child table (no orphans).

delete_project deleted investigations, agent steps, writeups, artifacts, leads,
and project evidence, but left answer candidates, analyst directives, finding
suppressions, and solid-evidence rows orphaned. All four are now swept.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlmodel import func as sa_func
from sqlmodel import select

from aila.api.auth import AuthContext
from aila.modules.forensics.api_router import create_forensics_router
from aila.modules.forensics.api_router import limiter as _forensics_limiter
from aila.modules.forensics.db_models import (
    AnalystDirectiveRecord,
    AnswerCandidateRecord,
    FindingSuppressionRecord,
    ForensicsProjectRecord,
    InvestigationRunRecord,
    SolidEvidenceRecord,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord


@pytest.fixture(autouse=True)
def _disable_forensics_limiter():
    # The forensics router owns a module-local Limiter that the shared
    # api-limiter fixture does not touch; disable it so the endpoint can be
    # driven with a stand-in request.
    prev = _forensics_limiter.enabled
    _forensics_limiter.enabled = False
    yield
    _forensics_limiter.enabled = prev


class _Req:
    """delete_project immediately does `del request`."""


def _endpoint(path: str, method: str):
    for route in create_forensics_router().routes:
        if getattr(route, "path", None) == path and method in getattr(route, "methods", set()):
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


def _admin() -> AuthContext:
    return AuthContext(user_id="admin", role="admin", auth_type="user", team_id=None)


async def _count(model, project_id: str) -> int:
    async with async_session_scope() as session:
        return int(
            (
                await session.exec(
                    select(sa_func.count()).select_from(model).where(
                        model.project_id == project_id
                    )
                )
            ).one()
        )


async def test_delete_project_purges_all_child_tables(test_db) -> None:
    suffix = uuid4().hex[:8]
    async with async_session_scope() as session:  # admin => unfiltered
        sys_rec = ManagedSystemRecord(name=f"sys-{suffix}", host="10.0.0.1", username="u")
        session.add(sys_rec)
        await session.flush()
        proj = ForensicsProjectRecord(name=f"proj-{suffix}", system_id=sys_rec.id)
        session.add(proj)
        await session.flush()
        pid = proj.id
        inv = InvestigationRunRecord(project_id=pid, question="q")
        session.add(inv)
        await session.flush()
        session.add(AnswerCandidateRecord(project_id=pid, investigation_id=inv.id))
        session.add(AnalystDirectiveRecord(project_id=pid))
        session.add(FindingSuppressionRecord(project_id=pid, fingerprint="fp-1"))
        session.add(SolidEvidenceRecord(project_id=pid, verdict="confirmed"))
        await session.commit()

    # Precondition: every child row exists.
    assert await _count(AnswerCandidateRecord, pid) == 1
    assert await _count(AnalystDirectiveRecord, pid) == 1
    assert await _count(FindingSuppressionRecord, pid) == 1
    assert await _count(SolidEvidenceRecord, pid) == 1

    delete_project = _endpoint("/projects/{project_id}", "DELETE")
    await delete_project(request=_Req(), project_id=pid, auth=_admin())

    # Postcondition: no orphans, project gone.
    assert await _count(AnswerCandidateRecord, pid) == 0
    assert await _count(AnalystDirectiveRecord, pid) == 0
    assert await _count(FindingSuppressionRecord, pid) == 0
    assert await _count(SolidEvidenceRecord, pid) == 0
    async with async_session_scope() as session:
        gone = (
            await session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == pid)
            )
        ).first()
    assert gone is None
