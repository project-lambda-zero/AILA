"""Forensics panel emit state (#18).

Runs after every panel branch finishes its loop. Evaluates the platform
sibling-review quorum on every draft outcome for this investigation and
lets the quorum kernel flip each outcome's state to APPROVED or
REJECTED. When the primary branch reaches emit and every submitted
draft has cleared quorum (approved or rejected), the panel is finished
and the InvestigationRunRecord flips to a terminal status:

  * COMPLETED -- at least one approved outcome exists
  * FAILED    -- every submitted outcome was rejected

A sibling branch (non-primary) reaches emit alone -- its emit is a
best-effort quorum tick that does not flip the investigation status;
the primary emit owns the terminal finalization.

The quorum kernel itself lives in
:mod:`aila.platform.services.outcome_review` and is bound to the
forensics record models via
:mod:`aila.modules.forensics.services.outcome_review` -- this state
just drives it.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlmodel import select as _select

from aila.modules.forensics.contracts.status import InvestigationStatus
from aila.modules.forensics.db_models import (
    ForensicsInvestigationBranchRecord,
    ForensicsInvestigationOutcomeRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    OUTCOME_STATE_DRAFT,
    OUTCOME_STATE_REJECTED,
    evaluate_quorum,
)
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import RESERVED_SUCCEEDED, StateResult

__all__ = ["state_forensics_panel_emit"]

_log = logging.getLogger(__name__)


async def _load_draft_outcome_ids(investigation_id: str) -> list[str]:
    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            _select(ForensicsInvestigationOutcomeRecord.id).where(
                ForensicsInvestigationOutcomeRecord.investigation_id == investigation_id,
                ForensicsInvestigationOutcomeRecord.state == OUTCOME_STATE_DRAFT,
            )
        )).all()
    return [str(rid) for rid in rows]


async def _load_outcome_states(investigation_id: str) -> dict[str, int]:
    """Return {state: count} across every outcome on this investigation."""
    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            _select(ForensicsInvestigationOutcomeRecord.state).where(
                ForensicsInvestigationOutcomeRecord.investigation_id == investigation_id,
            )
        )).all()
    counts: dict[str, int] = {}
    for state in rows:
        key = str(state or "")
        counts[key] = counts.get(key, 0) + 1
    return counts


async def _is_primary_branch(branch_id: str) -> bool:
    async with UnitOfWork() as uow:
        branch = (await uow.session.exec(
            _select(ForensicsInvestigationBranchRecord).where(
                ForensicsInvestigationBranchRecord.id == branch_id,
            )
        )).first()
    if branch is None:
        return False
    return (branch.fork_reason or "").startswith("primary")


async def _finalize_investigation_if_ready(investigation_id: str) -> str | None:
    """Flip the InvestigationRunRecord to a terminal status when quorum is done.

    Returns the new status string when a flip happened, ``None`` when
    the run is still open (drafts pending) or already terminal.
    """
    counts = await _load_outcome_states(investigation_id)
    if counts.get(OUTCOME_STATE_DRAFT, 0) > 0:
        # Panel is still deliberating; leave the run as RUNNING.
        return None
    approved = counts.get(OUTCOME_STATE_APPROVED, 0)
    rejected = counts.get(OUTCOME_STATE_REJECTED, 0)
    if approved == 0 and rejected == 0:
        # No panel outcomes at all -- nothing to finalize.
        return None
    new_status = (
        InvestigationStatus.COMPLETED.value
        if approved > 0
        else InvestigationStatus.FAILED.value
    )
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            _select(InvestigationRunRecord).where(
                InvestigationRunRecord.id == investigation_id,
            )
        )).first()
        if inv is None:
            return None
        terminal = {
            InvestigationStatus.COMPLETED.value,
            InvestigationStatus.EXHAUSTED.value,
            InvestigationStatus.FAILED.value,
            InvestigationStatus.CANCELLED.value,
        }
        if inv.status in terminal:
            return None
        inv.status = new_status
        uow.session.add(inv)
        await uow.commit()
    return new_status


async def state_forensics_panel_emit(
    input: dict[str, Any], services: Any,
) -> StateResult:
    """Evaluate panel quorum on every draft outcome + finalize when done."""
    del services  # emit uses only DB primitives; no external services needed
    investigation_id = str(input.get("investigation_id") or "")
    branch_id = str(input.get("branch_id") or "")
    if not investigation_id:
        raise ValueError("forensics_panel_emit: missing investigation_id")

    draft_ids = await _load_draft_outcome_ids(investigation_id)
    for outcome_id in draft_ids:
        try:
            result = await evaluate_quorum(outcome_id)
            _log.info(
                "forensics_panel_emit quorum inv=%s outcome=%s new_state=%s "
                "reason=%s",
                investigation_id, outcome_id, result.new_state,
                result.transition_reason,
            )
        except (RuntimeError, ValueError) as exc:
            _log.warning(
                "forensics_panel_emit quorum FAILED inv=%s outcome=%s err=%s",
                investigation_id, outcome_id, exc, exc_info=True,
            )

    finalized_status: str | None = None
    if branch_id and await _is_primary_branch(branch_id):
        finalized_status = await _finalize_investigation_if_ready(investigation_id)

    _log.info(
        "forensics_panel_emit DONE inv=%s branch=%s evaluated=%d status=%s",
        investigation_id, branch_id, len(draft_ids), finalized_status,
    )
    return StateResult(
        next_state=RESERVED_SUCCEEDED,
        output={
            **input,
            "quorum_evaluated_outcome_ids": draft_ids,
            "investigation_status": finalized_status,
        },
    )
