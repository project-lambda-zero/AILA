"""Record an approved forensics panel answer on the investigation.

When sibling review approves the panel's canonical outcome, the answer is
written where a free-flow answer lands: ``final_answer`` and ``confidence``
on the investigation row, an ``AnswerCandidateRecord``, and the
investigator-derived ``ArtifactRecord`` rows. The outcome then moves to
``dispatched`` so a second call (a sibling's vote, the emit state, or the
finalize sweep) is a no-op.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from sqlmodel import select

from aila.modules.forensics.db_models import (
    AnswerCandidateRecord,
    ForensicsInvestigationBranchRecord,
    ForensicsInvestigationOutcomeRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.services.investigation_artifacts import (
    persist_investigation_artifacts,
)
from aila.modules.forensics.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    OUTCOME_STATE_DISPATCHED,
    set_outcome_state,
)
from aila.platform.contracts.enums import OutcomeDispatchStatus
from aila.platform.uow import UnitOfWork

__all__ = ["dispatch_panel_outcome"]

_log = logging.getLogger(__name__)

_FINAL_ANSWER_MAX_CHARS = 2000


@dataclass(frozen=True)
class _RecordedAnswer:
    investigation_id: str
    project_id: str
    question: str
    answer: str
    confidence: str
    provenance: dict[str, Any]
    contract: dict[str, Any]
    observables: dict[str, Any]


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _decode(raw: str | None) -> dict[str, Any]:
    return _as_dict(json.loads(raw or "{}"))


async def dispatch_panel_outcome(outcome_id: str) -> bool:
    """Write an approved outcome's answer onto its investigation.

    Returns True when this call recorded the answer, False when the outcome
    is not in ``approved`` state (still a draft, rejected, or already
    dispatched) or its investigation row is gone.
    """
    async with UnitOfWork() as uow:
        outcome = (await uow.session.exec(
            select(ForensicsInvestigationOutcomeRecord)
            .where(ForensicsInvestigationOutcomeRecord.id == outcome_id)
            .with_for_update(),
        )).first()
        if outcome is None or outcome.state != OUTCOME_STATE_APPROVED:
            return False
        inv = (await uow.session.exec(
            select(InvestigationRunRecord).where(
                InvestigationRunRecord.id == outcome.investigation_id,
            ),
        )).first()
        if inv is None:
            return False
        proposer = (await uow.session.exec(
            select(ForensicsInvestigationBranchRecord).where(
                ForensicsInvestigationBranchRecord.id == outcome.branch_id,
            ),
        )).first()
        payload = _decode(outcome.payload_json)
        case_state = _decode(proposer.case_state_json if proposer is not None else None)
        provenance = _as_dict(payload.get("provenance"))
        contract = _as_dict(payload.get("contract"))
        corroboration = provenance.get("corroboration") or []
        if not isinstance(corroboration, list):
            corroboration = [str(corroboration)]
        answer = str(payload.get("answer") or "")
        recorded = _RecordedAnswer(
            investigation_id=inv.id,
            project_id=inv.project_id,
            question=inv.question,
            answer=answer,
            confidence=outcome.confidence,
            provenance=provenance,
            contract=contract,
            observables=_as_dict(case_state.get("observables")),
        )

        uow.session.add(AnswerCandidateRecord(
            project_id=inv.project_id,
            team_id=inv.team_id,
            investigation_id=inv.id,
            question_text=inv.question,
            answer_text=answer,
            confidence=outcome.confidence,
            primary_artifact_id=str(provenance.get("primary_artifact") or "")[:255] or None,
            corroboration_json=json.dumps([str(x) for x in corroboration])[:4000],
            format_hint=str(contract.get("answer_format") or "")[:255],
        ))
        inv.final_answer = answer[:_FINAL_ANSWER_MAX_CHARS]
        inv.confidence = outcome.confidence
        inv.primary_outcome_id = outcome.id
        uow.session.add(inv)
        outcome.dispatch_status = OutcomeDispatchStatus.DISPATCHED.value
        outcome.dispatch_target = "forensics_investigation"
        set_outcome_state(
            uow, outcome, OUTCOME_STATE_DISPATCHED,
            reason="forensics_panel_answer_recorded",
        )
        await uow.commit()

    await persist_investigation_artifacts(
        project_id=recorded.project_id,
        investigation_id=recorded.investigation_id,
        question=recorded.question,
        answer=recorded.answer,
        confidence=recorded.confidence,
        observables=recorded.observables,
        provenance=recorded.provenance,
        contract=recorded.contract,
        include_summary=True,
    )
    _log.info(
        "forensics panel answer recorded inv=%s outcome=%s confidence=%s",
        recorded.investigation_id, outcome_id, recorded.confidence,
    )
    return True
