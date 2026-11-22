"""Read-only projection of every stage and detector in a SAST batch."""
from __future__ import annotations

import json

from sqlmodel import select

from aila.modules.vr.contracts import InvestigationKind
from aila.modules.vr.db_models import VRInvestigationOutcomeRecord, VRInvestigationRecord
from aila.modules.vr.sast._refs import skill_id
from aila.modules.vr.sast.catalog import SAST_CATALOG_VERSION, SAST_SKILLS, SAST_UPSTREAM_COMMIT
from aila.modules.vr.sast.contracts import SastAuditAggregate, SastSkillResult
from aila.platform.uow import UnitOfWork

__all__ = ["collect_sast_audit"]


def _summary(outcome: VRInvestigationOutcomeRecord | None) -> str | None:
    if outcome is None:
        return None
    payload = json.loads(outcome.payload_json or "{}")
    if not isinstance(payload, dict):
        return None
    for key in ("summary", "title", "description", "objective"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


async def collect_sast_audit(parent_id: str) -> SastAuditAggregate:
    """Return actual child state and primary outcomes in catalog order."""
    async with UnitOfWork() as uow:
        parent = (await uow.session.exec(
            select(VRInvestigationRecord).where(VRInvestigationRecord.id == parent_id),
        )).first()
        if parent is None:
            raise ValueError(f"SAST audit parent {parent_id!r} not found")
        if parent.kind != InvestigationKind.SAST_AUDIT.value:
            raise ValueError(f"Investigation {parent_id!r} is not a SAST audit parent")
        children = list((await uow.session.exec(
            select(VRInvestigationRecord).where(VRInvestigationRecord.parent_investigation_id == parent_id),
        )).all())
        by_skill = {skill_id(child): child for child in children}
        outcome_ids = [child.primary_outcome_id for child in children if child.primary_outcome_id]
        outcomes = {}
        if outcome_ids:
            rows = (await uow.session.exec(
                select(VRInvestigationOutcomeRecord).where(VRInvestigationOutcomeRecord.id.in_(outcome_ids)),
            )).all()
            outcomes = {outcome.id: outcome for outcome in rows}

    results: list[SastSkillResult] = []
    for skill in SAST_SKILLS:
        child = by_skill.get(skill.id)
        if child is None:
            continue
        outcome = outcomes.get(child.primary_outcome_id)
        results.append(SastSkillResult(
            skill_id=skill.id,
            title=skill.title,
            phase=skill.phase,
            investigation_id=child.id,
            status=child.status,
            outcome_kind=outcome.outcome_kind if outcome else None,
            confidence=outcome.confidence if outcome else None,
            summary=_summary(outcome),
        ))
    status_counts: dict[str, int] = {}
    for result in results:
        status_counts[result.status] = status_counts.get(result.status, 0) + 1
    return SastAuditAggregate(
        parent_investigation_id=parent.id,
        target_id=parent.target_id,
        parent_status=parent.status,
        sast_spec_version=SAST_CATALOG_VERSION,
        upstream_commit=SAST_UPSTREAM_COMMIT,
        results=results,
        status_counts=status_counts,
    )
