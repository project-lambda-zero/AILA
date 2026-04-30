"""Free-flow investigation state handler.

Dispatches to ``HonestInvestigator.investigate()``. The investigator owns
the InvestigationRunRecord lifecycle (running → completed/exhausted).
This handler only touches status on unrecoverable failure, so there is no
double-write race with the investigator's own transitions.
"""
from __future__ import annotations

import logging
from typing import Any

from pydantic import ValidationError
from sqlmodel import select as _select

from aila.modules.forensics.agents.investigator import HonestInvestigator
from aila.modules.forensics.contracts.status import InvestigationStatus
from aila.modules.forensics.db_models import InvestigationRunRecord
from aila.modules.forensics.workflow.inputs import FreeFlowInput
from aila.platform.exceptions import AILAError
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import StateResult

__all__ = ["state_freeflow"]

_log = logging.getLogger(__name__)

state_freeflow_parallel_safe = False
state_freeflow_writes_fields = ["investigation", "steps", "answer"]


async def _mark_investigation_failed(investigation_id: str, reason: str) -> None:
    """Mark the investigation as failed and stash the error in final_answer.

    Called only from the state handler's catch-all path when the agent either
    never ran or crashed before updating the record itself. If the agent
    already finalized the record (completed/exhausted), calling this path
    means something raised *after* that, which is still a failure surface.
    """
    if not investigation_id:
        return
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            _select(InvestigationRunRecord).where(InvestigationRunRecord.id == investigation_id)
        )).first()
        if inv is not None:
            inv.status = InvestigationStatus.FAILED.value
            inv.final_answer = reason[:500]
            uow.session.add(inv)
            await uow.commit()


async def state_freeflow(
    input: dict[str, Any],
    services: Any,
) -> dict[str, Any]:
    """Execute bounded free-flow investigation loop via HonestInvestigator."""
    try:
        data = FreeFlowInput.model_validate({
            **input,
            "integration": input.get("integration") or services.integration,
        })
    except ValidationError as exc:
        pid = input.get("investigation_id", "")
        _log.error("state_freeflow ABORT: invalid input: %s", exc.errors())
        await services.emitter.emit(
            "freeflow",
            f"Freeflow aborted: invalid input {exc.errors()}",
            {"stage": "config_error", "errors": exc.errors()},
        )
        await _mark_investigation_failed(pid, f"invalid input: {exc.errors()!r}")
        raise

    _log.info("state_freeflow START: inv_id=%s, question=%s", data.investigation_id, data.question[:80])
    await services.emitter.emit(
        "freeflow",
        f"Starting free-flow investigation ({data.analyzer_os}): {data.question[:100]}",
    )

    agent = HonestInvestigator(
        settings=services.settings,
        reasoning_engine=services.reasoning_engine,
        reasoning_graphs=services.reasoning_graphs,
        run_id=services.run_id,
        integration=data.integration,
        project_id=data.project_id,
        investigation_id=data.investigation_id,
        analyzer_os=data.analyzer_os,
        parent_investigation_id=data.parent_investigation_id,
    )

    try:
        result = await agent.investigate(
            question=data.question,
            max_attempts=data.max_attempts,
            emitter=services.emitter,
        )
        _log.info(
            "agent.investigate() returned: steps=%d, answer=%s",
            len(result.get("steps", [])), bool(result.get("answer")),
        )
    except (OSError, TimeoutError, RuntimeError, ValueError, KeyError, AILAError) as exc:
        _log.exception("agent.investigate() FAILED: %s", exc)
        await services.emitter.emit(
            "freeflow",
            f"Investigation FAILED: {str(exc)[:200]}",
            {"stage": "agent_failed", "error": str(exc)},
        )
        await _mark_investigation_failed(data.investigation_id, str(exc))
        raise

    # Hard failure surface: if the agent produced zero steps, every turn
    # either crashed before writing or the loop never ran. That must not
    # be treated as "completed successfully" — it's a failure the UI has
    # to reflect so the operator knows to retry / inspect worker logs.
    #
    # Exception: when the analyst cancelled via the Stop button, the
    # investigator may return with zero steps if the cancel arrived
    # between startup and turn 1. That's not a failure.
    steps_list = result.get("steps", []) or []
    cancelled = bool(result.get("cancelled"))
    if not steps_list and not cancelled:
        reason = "agent produced zero steps — see worker log"
        _log.error("state_freeflow zero-step result inv_id=%s — marking FAILED", data.investigation_id)
        await services.emitter.emit(
            "freeflow",
            f"Investigation FAILED: {reason}",
            {"stage": "zero_step_failure", "attempts_used": result.get("attempts_used", 0)},
        )
        await _mark_investigation_failed(data.investigation_id, reason)
        raise RuntimeError(f"freeflow zero-step: {reason}")
    if cancelled:
        _log.info(
            "state_freeflow cancelled-by-analyst inv_id=%s steps=%d",
            data.investigation_id, len(steps_list),
        )

    await services.emitter.emit(
        "freeflow",
        f"Investigation complete. Answer confidence: {result.get('confidence', 'none')}.",
        {"attempts_used": result.get("attempts_used", 0)},
    )

    _log.info("state_freeflow COMPLETE: inv_id=%s", data.investigation_id)
    return StateResult(
        next_state="writeup",
        output={
            "investigation_id": data.investigation_id,
            "project_id": data.project_id,
            "question": data.question,
            "answer": result.get("answer"),
            "confidence": result.get("confidence", "caveated"),
            "attempts_used": result.get("attempts_used", 0),
            "steps": result.get("steps", []),
            "observables": result.get("observables", {}),
            "contract": result.get("contract", {}),
            "hypotheses": result.get("hypotheses", []),
            "rejected": result.get("rejected", []),
            "evidence_directory": input.get("evidence_directory", ""),
            "analyzer_os": input.get("analyzer_os", "linux"),
            "integration": input.get("integration", {}),
        },
    )


state_freeflow.parallel_safe = state_freeflow_parallel_safe  # type: ignore[attr-defined]
state_freeflow.writes_fields = state_freeflow_writes_fields  # type: ignore[attr-defined]
