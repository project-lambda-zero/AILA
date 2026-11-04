"""N-day investigation staging for the VR investigation hub.

``InvestigationKind.N_DAY`` investigations run through the canonical hub task
``run_vr_investigate``. This module stages the investigation row and its
primary branch and builds the operator question the hub reads. The hub
resolves everything else (target, patched binary via
``investigation.project_id -> VRProjectRecord.patched_target_id``, and the
analysis workstation) from the persisted rows, so no task kwargs are built
here.

Both the project endpoint (``POST /vr/projects``) and the outcome dispatcher
call :func:`create_nday_investigation`, so the investigation row, its primary
branch, and its strategy default cannot drift between entry points.

The helpers only stage rows inside the caller's session; the caller owns
commit and task submission.
"""
from __future__ import annotations

from sqlmodel.ext.asyncio.session import AsyncSession

from aila.modules.vr.contracts import (
    BranchStatus,
    InvestigationKind,
    InvestigationStatus,
    PersonaVoice,
)
from aila.modules.vr.db_models import VRInvestigationBranchRecord, VRInvestigationRecord

__all__ = [
    "NDAY_DEFAULT_BUDGET_USD",
    "NDAY_STRATEGY_FAMILY",
    "build_nday_question",
    "create_nday_investigation",
]

NDAY_STRATEGY_FAMILY = "vulnerability_research.nday"
# Budget for an N-day investigation created from a project (no operator
# budget field exists on the project endpoint). Matches the investigation
# column default.
NDAY_DEFAULT_BUDGET_USD = 50.0


def build_nday_question(cve_id: str | None, context_notes: str | None) -> str:
    """Return the hub question: the CVE identifier followed by operator notes.

    The hub extracts CVE ids from this text, so the identifier leads when
    present. Returns an empty string when neither part is supplied.
    """
    parts = [part.strip() for part in (cve_id, context_notes) if part and part.strip()]
    return "\n\n".join(parts)


async def create_nday_investigation(
    session: AsyncSession,
    *,
    target_id: str,
    project_id: str | None,
    team_id: str | None,
    title: str,
    initial_question: str,
    cost_budget_usd: float,
    auto_pilot: bool,
    parent_investigation_id: str | None = None,
) -> VRInvestigationRecord:
    """Stage an N-day investigation and its primary branch in ``session``.

    Returns the flushed investigation record (its ``id`` is populated).
    The caller commits.
    """
    record = VRInvestigationRecord(
        target_id=target_id,
        project_id=project_id,
        team_id=team_id,
        parent_investigation_id=parent_investigation_id,
        kind=InvestigationKind.N_DAY.value,
        title=title,
        initial_question=initial_question,
        status=InvestigationStatus.CREATED.value,
        auto_pilot=auto_pilot,
        strategy_family=NDAY_STRATEGY_FAMILY,
        cost_budget_usd=cost_budget_usd,
    )
    session.add(record)
    await session.flush()

    session.add(VRInvestigationBranchRecord(
        investigation_id=record.id,
        status=BranchStatus.ACTIVE.value,
        fork_reason="primary",
        persona_voice=PersonaVoice.HALVAR.value,
    ))
    return record
