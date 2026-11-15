"""Free-flow investigation state handler.

Dispatches to ``HonestInvestigator.investigate()``. The investigator owns
the InvestigationRunRecord lifecycle (running \u2192 completed/exhausted).
This handler only touches status on unrecoverable failure, so there is no
double-write race with the investigator's own transitions.

Cost-ceiling enforcement (finding 59-3.6): the operator-tunable
``forensics.freeflow_max_cost_usd`` config field caps cumulative LLM
spend per investigation. The shared monitor in ``services/cost_ceiling.py`` polls
``LLMCostRecord.cost_usd`` summed over ``run_id == investigation_id`` and,
when the cap is crossed, flips the investigation row's status to
``cancelled`` -- which ``HonestInvestigator._stop_status()`` sees at the
top of each turn, terminating the loop by the same code path as the
operator-initiated Stop button. On return the handler overrides the
final status to ``exhausted`` so the UI can distinguish budget cap from
manual cancel. The turn cap (``FORENSICS_HARD_TURN_CAP`` in config_schema.py) and
this cost cap are ANDed: whichever fires first halts the run.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from pydantic import ValidationError
from sqlmodel import select as _select

from aila.modules.forensics.agents.investigator import HonestInvestigator
from aila.modules.forensics.contracts.status import InvestigationStatus
from aila.modules.forensics.db_models import InvestigationRunRecord
from aila.modules.forensics.services.cost_ceiling import (
    BUDGET_EXHAUSTED_PREFIX,
    cost_ceiling_monitor,
    read_cost_cap_usd,
)
from aila.modules.forensics.workflow.inputs import FreeFlowInput
from aila.platform.exceptions import AILAError
from aila.platform.llm.errors import LLMError
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import StateResult

__all__ = [
    "state_freeflow",
]

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

    # Cost-ceiling monitor (finding 59-3.6). Spawn a background task that
    # polls actual cost every COST_MONITOR_POLL_SECONDS. If the cap is
    # crossed it flips the investigation row to ``cancelled``; the
    # investigator halts at the next turn boundary via its existing
    # cancel-check path. We then override the final status to EXHAUSTED
    # to distinguish budget cap from operator Stop.
    cost_cap_usd = await read_cost_cap_usd()
    cost_outcome: dict[str, Any] = {"hit": False, "actual_usd": 0.0}
    stop_event = asyncio.Event()
    monitor_task: asyncio.Task[None] | None = None
    if cost_cap_usd > 0.0:
        monitor_task = asyncio.create_task(
            cost_ceiling_monitor(
                investigation_id=data.investigation_id,
                cap_usd=cost_cap_usd,
                emitter=services.emitter,
                source="freeflow",
                stop_event=stop_event,
                outcome=cost_outcome,
            )
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
    except (OSError, TimeoutError, RuntimeError, ValueError, KeyError, AILAError, LLMError) as exc:
        _log.exception("agent.investigate() FAILED: %s", exc)
        await services.emitter.emit(
            "freeflow",
            f"Investigation FAILED: {str(exc)[:200]}",
            {"stage": "agent_failed", "error": str(exc)},
        )
        await _mark_investigation_failed(data.investigation_id, str(exc))
        raise
    finally:
        # Stop the monitor cleanly. wait_for wakes on the event; if the
        # monitor already exited (ceiling hit) awaiting the task is a
        # no-op that returns instantly.
        stop_event.set()
        if monitor_task is not None:
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
            except (OSError, RuntimeError, AILAError):
                _log.exception("cost ceiling monitor task exit failed for inv %s", data.investigation_id)

    # Hard failure surface: if the agent produced zero steps, every turn
    # either crashed before writing or the loop never ran. That must not
    # be treated as "completed successfully" -- it's a failure the UI has
    # to reflect so the operator knows to retry / inspect worker logs.
    #
    # Exception: when the analyst cancelled via the Stop button, the
    # investigator may return with zero steps if the cancel arrived
    # between startup and turn 1. That's not a failure. The same holds
    # for a paused or terminal stop: the investigator returned at a turn
    # boundary with the persisted status it observed.
    steps_list = result.get("steps", []) or []
    cancelled = bool(result.get("cancelled"))
    # A cancelled stop is preserved like any other stop: the row already
    # holds ``cancelled`` (written by the operator or the cost monitor), so
    # the answer branch below must not overwrite it with ``completed``.
    stopped_status = result.get("stopped_status") or (
        InvestigationStatus.CANCELLED.value if cancelled else None
    )
    if not steps_list and not stopped_status:
        reason = "agent produced zero steps -- see worker log"
        _log.error("state_freeflow zero-step result inv_id=%s -- marking FAILED", data.investigation_id)
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

    # Set investigation status BEFORE returning to downstream states.
    # Previously relied on response_emit terminal state, but if writeup
    # or any downstream state crashes, the investigation stays 'running' forever.
    has_answer = bool(result.get('answer'))
    # Cost ceiling overrides the answer/cancelled/failed branches. A run
    # that produced an answer at the SAME turn the ceiling fires would
    # otherwise be reported as COMPLETED even though the operator's cap
    # was breached -- surface the cap breach explicitly.
    cost_ceiling_hit = bool(cost_outcome.get("hit"))
    if cost_ceiling_hit:
        final_status = InvestigationStatus.EXHAUSTED.value
    elif stopped_status:
        # Paused or terminal stop: the persisted status is authoritative
        # and is left untouched below.
        final_status = stopped_status
    elif has_answer:
        final_status = InvestigationStatus.COMPLETED.value
    else:
        final_status = InvestigationStatus.FAILED.value
    if cost_ceiling_hit or not stopped_status:
        try:
            async with UnitOfWork() as status_uow:
                inv = (await status_uow.session.exec(
                    _select(InvestigationRunRecord).where(
                        InvestigationRunRecord.id == data.investigation_id
                    )
                )).first()
                if inv is not None:
                    inv.status = final_status
                    if cost_ceiling_hit:
                        actual_usd = float(cost_outcome.get("actual_usd", 0.0))
                        inv.final_answer = (
                            f"{BUDGET_EXHAUSTED_PREFIX}"
                            f"${actual_usd:.2f}/${cost_cap_usd:.2f}>"
                        )
                        inv.confidence = "caveated"
                    elif has_answer:
                        inv.final_answer = str(result.get('answer', ''))[:2000]
                        inv.confidence = result.get('confidence', 'caveated')
                    status_uow.session.add(inv)
                    await status_uow.commit()
        except (OSError, RuntimeError, AILAError):
            _log.exception('Failed to set investigation status=%s', final_status)

    await services.emitter.emit(
        'freeflow',
        f'Investigation {final_status}. Answer confidence: {result.get("confidence", "none")}.',
        {'attempts_used': result.get('attempts_used', 0), 'status': final_status},
    )

    _log.info('state_freeflow %s: inv_id=%s', final_status, data.investigation_id)
    return StateResult(
        next_state="promotion",
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
