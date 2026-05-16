"""Investigation emit state (M3.R-7).

Finalizes the investigation row based on the loop's exit reason:
  terminal_submit             → COMPLETED, primary_outcome_id linked
  max_turns                   → COMPLETED (no terminal outcome — operator
                                can re-trigger another loop run, or
                                accept the partial state)
  status_flipped:paused       → PAUSED stays PAUSED (don't overwrite)
  status_flipped:failed       → FAILED stays FAILED
  researcher_error:*          → FAILED, error recorded in observables
                                of the primary branch
"""
from __future__ import annotations

import logging
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.agents.outcome_dispatcher import OutcomeDispatcher
from aila.modules.vr.agents.pattern_extractor import (
    PatternExtractionResult,
    PatternExtractor,
)
from aila.modules.vr.contracts.investigation import InvestigationStatus
from aila.modules.vr.db_models import VRInvestigationRecord
from aila.modules.vr.services.pattern_store import PatternStore
from aila.platform.contracts._common import utc_now
from aila.platform.services.factory import ServiceFactory
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import RESERVED_SUCCEEDED, StateResult

__all__ = ["state_investigation_emit"]

_log = logging.getLogger(__name__)


def _resolve_final_status(exit_reason: str) -> str | None:
    """Pick the final InvestigationStatus given the loop's exit reason.

    Returns None when the status should NOT be touched (operator paused —
    we don't auto-flip back to RUNNING here).
    """
    if exit_reason == "terminal_submit":
        return InvestigationStatus.COMPLETED.value
    if exit_reason == "max_turns":
        return InvestigationStatus.COMPLETED.value
    if exit_reason.startswith("status_flipped:"):
        return None
    if exit_reason.startswith("researcher_error:"):
        return InvestigationStatus.FAILED.value
    return InvestigationStatus.COMPLETED.value


async def state_investigation_emit(input: dict[str, Any], services: Any) -> StateResult:
    """Finalize investigation row + emit terminal payload."""
    del services

    investigation_id = str(input.get("investigation_id") or "")
    exit_reason = str(input.get("exit_reason") or "max_turns")
    outcome_id = input.get("outcome_id")
    final_status = _resolve_final_status(exit_reason)

    if investigation_id:
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == investigation_id,
                )
            )).first()
            if inv is not None:
                now = utc_now()
                if final_status is not None:
                    inv.status = final_status
                if outcome_id and not inv.primary_outcome_id:
                    inv.primary_outcome_id = str(outcome_id)
                inv.stopped_at = now
                inv.updated_at = now
                uow.session.add(inv)
                await uow.commit()

    dispatch_status: str | None = None
    dispatch_target: str | None = None
    dispatch_reason: str | None = None
    if outcome_id and final_status == InvestigationStatus.COMPLETED.value:
        dispatcher = OutcomeDispatcher(knowledge=ServiceFactory().knowledge)
        try:
            dispatch_result = await dispatcher.dispatch(str(outcome_id))
            dispatch_status = dispatch_result.dispatch_status.value
            dispatch_target = dispatch_result.dispatch_target
            dispatch_reason = dispatch_result.reason
            _log.info(
                "investigation_emit DISPATCH outcome_id=%s status=%s target=%s",
                outcome_id, dispatch_status, dispatch_target,
            )
        except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
            dispatch_status = "failed"
            dispatch_reason = f"{type(exc).__name__}: {exc}"
            _log.warning(
                "investigation_emit DISPATCH ERROR outcome_id=%s err=%s",
                outcome_id, exc,
            )

    extraction_count: int | None = None
    extraction_reason: str | None = None
    if outcome_id and final_status == InvestigationStatus.COMPLETED.value:
        try:
            extraction_result = await _run_pattern_extraction(str(outcome_id))
            extraction_count = extraction_result.extracted_count
            extraction_reason = extraction_result.skipped_reason or None
            _log.info(
                "investigation_emit EXTRACT outcome_id=%s count=%d reason=%s",
                outcome_id, extraction_count, extraction_reason,
            )
        except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
            extraction_count = 0
            extraction_reason = f"{type(exc).__name__}: {exc}"
            _log.warning(
                "investigation_emit EXTRACT ERROR outcome_id=%s err=%s",
                outcome_id, exc,
            )

    _log.info(
        "investigation_emit DONE investigation_id=%s exit_reason=%s final_status=%s outcome_id=%s",
        investigation_id, exit_reason, final_status, outcome_id,
    )

    return StateResult(
        next_state=RESERVED_SUCCEEDED,
        output={
            "investigation_id": investigation_id,
            "status": final_status,
            "exit_reason": exit_reason,
            "outcome_id": outcome_id,
            "last_turn_idx": input.get("last_turn_idx"),
            "last_action": input.get("last_action"),
            "dispatch_status": dispatch_status,
            "dispatch_target": dispatch_target,
            "dispatch_reason": dispatch_reason,
            "pattern_extraction_count": extraction_count,
            "pattern_extraction_reason": extraction_reason,
        },
    )


async def _run_pattern_extraction(outcome_id: str) -> PatternExtractionResult:
    """Bridge between investigation_emit and PatternExtractor.

    Resolves team_id from the outcome's investigation row, constructs the
    extractor with platform LLM client + PatternStore, and runs one pass.
    Errors propagate to the caller's try/except for status logging.
    """
    from aila.modules.vr.db_models import VRInvestigationOutcomeRecord  # noqa: PLC0415

    async with UnitOfWork() as uow:
        outcome = (await uow.session.exec(
            _select(VRInvestigationOutcomeRecord).where(
                VRInvestigationOutcomeRecord.id == outcome_id,
            ),
        )).first()
        if outcome is None:
            raise RuntimeError(f"outcome {outcome_id} disappeared before extraction")
        inv = (await uow.session.exec(
            _select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == outcome.investigation_id,
            ),
        )).first()
        team_id = inv.team_id if inv is not None else None

    services = ServiceFactory()
    store = PatternStore(knowledge=services.knowledge)
    extractor = PatternExtractor(
        llm_client=services.llm_client,
        pattern_store=store,
    )
    return await extractor.extract(outcome_id=outcome_id, team_id=team_id)
