"""Advance SAST batches through the exact upstream three-stage sequence."""
from __future__ import annotations

import json
import logging

from sqlmodel import select

from aila.modules.vr._task_queue import default_task_queue
from aila.modules.vr.contracts import InvestigationKind, InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.modules.vr.sast._refs import skill_id
from aila.modules.vr.sast.catalog import SAST_SKILLS
from aila.modules.vr.sast.seed import SastSeedBuilder
from aila.modules.vr.workflow.task import run_vr_investigate
from aila.platform.contracts import utc_now
from aila.platform.uow import UnitOfWork

__all__ = ["advance_sast_batches"]

_log = logging.getLogger(__name__)
_TERMINAL = frozenset({
    InvestigationStatus.COMPLETED.value,
    InvestigationStatus.FAILED.value,
    InvestigationStatus.ABANDONED.value,
})


def _render_outcome(title: str, outcome: VRInvestigationOutcomeRecord | None) -> str:
    if outcome is None:
        return f"## {title}\n\nNo primary outcome was persisted."
    try:
        payload = json.loads(outcome.payload_json or "{}")
        evidence = json.loads(outcome.evidence_refs_json or "[]")
    except (TypeError, ValueError):
        payload = {"unparseable_payload": outcome.payload_json}
        evidence = []
    return (
        f"## {title}\n\n"
        + json.dumps(
            {"outcome_kind": outcome.outcome_kind, "payload": payload, "evidence_refs": evidence},
            indent=2,
            ensure_ascii=False,
        )
    )


async def _enqueue(child_id: str) -> bool:
    try:
        await default_task_queue().submit(
            track="vr",
            fn=run_vr_investigate,
            kwargs={"investigation_id": child_id},
            user_id="system",
            group_id="system",
            team_id=None,
        )
    except (OSError, RuntimeError, ValueError, TypeError, TimeoutError) as exc:
        _log.warning("SAST stage child %s enqueue failed: %s", child_id, exc, exc_info=True)
        return False
    return True


def _abandon_downstream(children: list[VRInvestigationRecord]) -> None:
    now = utc_now()
    for child in children:
        if child.status == InvestigationStatus.CREATED.value:
            child.status = InvestigationStatus.ABANDONED.value
            child.stopped_at = now
            child.updated_at = now


async def advance_sast_batches(uow: UnitOfWork) -> int:
    """Release detectors after analysis and the report after all detectors.

    Every child is persisted at dispatch, which keeps the generic parent
    roll-up from completing early. Only stage transitions enqueue work.
    """
    parents = list((await uow.session.exec(
        select(VRInvestigationRecord).where(
            VRInvestigationRecord.kind == InvestigationKind.SAST_AUDIT.value,
            VRInvestigationRecord.parent_investigation_id.is_(None),
            VRInvestigationRecord.status.in_([
                InvestigationStatus.CREATED.value,
                InvestigationStatus.RUNNING.value,
            ]),
        ),
    )).all())
    if not parents:
        return 0

    catalog = {skill.id: skill for skill in SAST_SKILLS}
    enqueued = 0
    for parent in parents:
        children = list((await uow.session.exec(
            select(VRInvestigationRecord)
            .where(VRInvestigationRecord.parent_investigation_id == parent.id)
            .order_by(VRInvestigationRecord.created_at),
        )).all())
        by_id = {skill_id(child): child for child in children}
        analysis = by_id.get("sast-analysis")
        report = by_id.get("sast-report")
        detectors = [child for child in children if skill_id(child) not in {None, "sast-analysis", "sast-report"}]
        if analysis is None or report is None or len(detectors) != 14:
            _log.error("SAST parent %s has an incomplete staged child set", parent.id)
            continue

        child_ids = [child.id for child in children]
        queued_ids = await default_task_queue().enqueued_investigation_ids(child_ids)
        outcome_ids = [child.primary_outcome_id for child in children if child.primary_outcome_id]
        outcomes = {}
        if outcome_ids:
            outcome_rows = (await uow.session.exec(
                select(VRInvestigationOutcomeRecord).where(VRInvestigationOutcomeRecord.id.in_(outcome_ids)),
            )).all()
            outcomes = {outcome.id: outcome for outcome in outcome_rows}

        architecture = _render_outcome("Architecture and threat model", outcomes.get(analysis.primary_outcome_id))
        if analysis.status in _TERMINAL:
            if analysis.status != InvestigationStatus.COMPLETED.value or analysis.primary_outcome_id not in outcomes:
                _abandon_downstream([*detectors, report])
                for child in [*detectors, report]:
                    uow.session.add(child)
                await uow.commit()
                continue
            changed = False
            pending = [child for child in detectors if child.status == InvestigationStatus.CREATED.value and child.id not in queued_ids]
            for child in pending:
                skill = catalog.get(skill_id(child) or "")
                if skill is None:
                    continue
                child.initial_question = SastSeedBuilder.build(skill, architecture)
                child.updated_at = utc_now()
                uow.session.add(child)
                changed = True
            if changed:
                await uow.commit()
            for child in pending:
                if await _enqueue(child.id):
                    enqueued += 1

        if (
            detectors
            and all(child.status in _TERMINAL for child in detectors)
            and report.status == InvestigationStatus.CREATED.value
            and report.id not in queued_ids
            and analysis.primary_outcome_id in outcomes
        ):
            result_blocks = [architecture]
            for child in detectors:
                result_blocks.append(_render_outcome(child.title, outcomes.get(child.primary_outcome_id)))
            report.initial_question = SastSeedBuilder.build(catalog["sast-report"], "\n\n".join(result_blocks))
            report.updated_at = utc_now()
            uow.session.add(report)
            await uow.commit()
            if await _enqueue(report.id):
                enqueued += 1
    return enqueued
