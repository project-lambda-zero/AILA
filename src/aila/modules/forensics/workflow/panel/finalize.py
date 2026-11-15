"""Terminal settlement for forensics panel investigations.

A panel branch closes in :mod:`aila.modules.forensics.workflow.panel.emit`
when its loop exits. Once no branch is active or paused, this module settles
the investigation from the canonical outcome and the investigation-wide LLM
spend. Approved answers are dispatched before the investigation completes;
rejected or unfinished deliberations retain an explicit operator-visible
reason instead of a generic terminal status.

The same entry point backs the ``forensics.finalize`` periodic sweep, so a
worker that stopped after closing a branch cannot leave the investigation
running forever. Completed settlements enqueue the ordinary forensics
write-up workflow; the emit state never performs that longer LLM job inline.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select

from aila.modules.forensics._task_queue import default_task_queue
from aila.modules.forensics.contracts.status import InvestigationStatus
from aila.modules.forensics.db_models import (
    AgentStepRecord,
    ForensicsInvestigationBranchRecord,
    ForensicsInvestigationOutcomeRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.services import cost_ceiling
from aila.modules.forensics.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    OUTCOME_STATE_DISPATCHED,
    OUTCOME_STATE_DRAFT,
    OUTCOME_STATE_REJECTED,
    summarize_outcome_for_review,
)
from aila.modules.forensics.services.panel_outcome import dispatch_panel_outcome
from aila.modules.forensics.workflow.panel.writeup import run_forensics_panel_writeup
from aila.platform.contracts import utc_now
from aila.platform.uow import UnitOfWork

__all__ = [
    "PanelFinalizeResult",
    "finalize_panel_investigation",
    "sweep_finalizable_panel_investigations",
]

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PanelFinalizeResult:
    """Observable outcome of one settlement attempt."""

    investigation_id: str
    status: str | None = None
    writeup_task_id: str | None = None

    @property
    def finalized(self) -> bool:
        return self.status is not None


async def _enqueue_writeup(*, investigation_id: str, team_id: str | None) -> str | None:
    """Enqueue the panel write-up workflow with the investigation's tenant."""
    handle = await default_task_queue().submit(
        track="forensics",
        fn=run_forensics_panel_writeup,
        kwargs={"investigation_id": investigation_id},
        user_id="system",
        group_id="forensics_panel_finalize",
        team_id=team_id,
    )
    return handle.task_id


async def finalize_panel_investigation(investigation_id: str) -> PanelFinalizeResult:
    """Settle one running panel investigation when every branch has stopped.

    No-op for free-flow investigations, terminal or operator-paused rows, and
    panels that still have active or paused branches. The investigation row
    lock serializes concurrent branch emits: only the last one can commit the
    terminal status and enqueue the write-up.
    """
    # Dispatch outside the investigation-row lock below: the dispatcher owns
    # a separate transaction that updates this investigation, and calling it
    # while holding that lock would self-deadlock.
    async with UnitOfWork() as uow:
        approved_id = (await uow.session.exec(
            select(ForensicsInvestigationOutcomeRecord.id).where(
                ForensicsInvestigationOutcomeRecord.investigation_id == investigation_id,
                ForensicsInvestigationOutcomeRecord.state == OUTCOME_STATE_APPROVED,
            ),
        )).first()
    if approved_id is not None:
        await dispatch_panel_outcome(str(approved_id))

    terminal_status: str | None = None
    team_id: str | None = None
    has_steps = False
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(InvestigationRunRecord)
            .where(InvestigationRunRecord.id == investigation_id)
            .with_for_update(),
        )).first()
        if inv is None or inv.status != InvestigationStatus.RUNNING.value:
            return PanelFinalizeResult(investigation_id)
        branches = (await uow.session.exec(
            select(ForensicsInvestigationBranchRecord).where(
                ForensicsInvestigationBranchRecord.investigation_id == investigation_id,
            ),
        )).all()
        if not branches or any(b.status in ("active", "paused") for b in branches):
            return PanelFinalizeResult(investigation_id)
        outcomes = (await uow.session.exec(
            select(ForensicsInvestigationOutcomeRecord)
            .where(ForensicsInvestigationOutcomeRecord.investigation_id == investigation_id)
            .order_by(ForensicsInvestigationOutcomeRecord.created_at),
        )).all()
        approved = next(
            (o for o in reversed(outcomes) if o.state in (OUTCOME_STATE_APPROVED, OUTCOME_STATE_DISPATCHED)),
            None,
        )
        latest = outcomes[-1] if outcomes else None
        cap = await cost_ceiling.read_cost_cap_usd()
        spent = await cost_ceiling.actual_cost_usd(investigation_id)
        if approved is not None:
            terminal_status = InvestigationStatus.COMPLETED.value
        elif cost_ceiling.cost_ceiling_exceeded(spent, cap):
            terminal_status = InvestigationStatus.EXHAUSTED.value
            inv.final_answer = (
                f"{cost_ceiling.BUDGET_EXHAUSTED_PREFIX}${spent:.2f}/${cap:.2f}>"
            )
            inv.confidence = "caveated"
        elif latest is not None and latest.state == OUTCOME_STATE_REJECTED and not any(
            o.state == OUTCOME_STATE_DRAFT for o in outcomes
        ):
            terminal_status = InvestigationStatus.FAILED.value
            summary = summarize_outcome_for_review(latest.payload_json)
            inv.final_answer = f"Panel rejected the proposed answer. {summary}"[:2000]
            inv.confidence = "caveated"
        else:
            terminal_status = InvestigationStatus.EXHAUSTED.value
            if latest is not None and latest.state == OUTCOME_STATE_DRAFT:
                inv.final_answer = (
                    "Panel ended before the draft answer reached sibling-review "
                    f"quorum. {summarize_outcome_for_review(latest.payload_json)}"
                )[:2000]
            else:
                inv.final_answer = "Panel ended without submitting an answer."
            inv.confidence = "caveated"
        inv.status = terminal_status
        inv.stopped_at = utc_now()
        inv.updated_at = inv.stopped_at
        team_id = inv.team_id
        uow.session.add(inv)
        has_steps = (await uow.session.exec(
            select(AgentStepRecord.id)
            .where(AgentStepRecord.investigation_id == investigation_id)
            .limit(1),
        )).first() is not None
        await uow.commit()

    result = PanelFinalizeResult(investigation_id, terminal_status)
    if not has_steps:
        return result
    try:
        writeup_task_id = await _enqueue_writeup(
            investigation_id=investigation_id, team_id=team_id,
        )
    except (SQLAlchemyError, OSError, RuntimeError, ValueError) as exc:
        # Settlement remains committed and truthful; the missing write-up is
        # an explicit worker-log failure rather than a silent no-op.
        _log.exception(
            "forensics panel write-up enqueue failed inv=%s status=%s err=%s",
            investigation_id, terminal_status, exc,
        )
        return result
    _log.info(
        "forensics panel finalized inv=%s status=%s writeup_task=%s",
        investigation_id, terminal_status, writeup_task_id,
    )
    return PanelFinalizeResult(investigation_id, terminal_status, writeup_task_id)


async def sweep_finalizable_panel_investigations() -> dict[str, int]:
    """Re-run settlement for every running investigation that has branches."""
    async with UnitOfWork() as uow:
        ids = (await uow.session.exec(
            select(InvestigationRunRecord.id)
            .join(
                ForensicsInvestigationBranchRecord,
                ForensicsInvestigationBranchRecord.investigation_id == InvestigationRunRecord.id,
            )
            .where(InvestigationRunRecord.status == InvestigationStatus.RUNNING.value)
            .distinct(),
        )).all()
    finalized = 0
    errors = 0
    for investigation_id in ids:
        try:
            result = await finalize_panel_investigation(str(investigation_id))
        except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
            errors += 1
            _log.exception(
                "forensics.finalize failed inv=%s err=%s", investigation_id, exc,
            )
            continue
        finalized += int(result.finalized)
    return {"finalized": finalized, "errors": errors}
