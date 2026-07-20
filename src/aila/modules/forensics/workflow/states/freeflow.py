"""Free-flow investigation state handler.

Dispatches to ``HonestInvestigator.investigate()``. The investigator owns
the InvestigationRunRecord lifecycle (running \u2192 completed/exhausted).
This handler only touches status on unrecoverable failure, so there is no
double-write race with the investigator's own transitions.

Cost-ceiling enforcement (finding 59-3.6): the operator-tunable
``forensics.freeflow_max_cost_usd`` config field caps cumulative LLM
spend per investigation. A background monitor coroutine polls
``LLMCostRecord.cost_usd`` summed over ``run_id == investigation_id`` and,
when the cap is crossed, flips the investigation row's status to
``cancelled`` -- which ``HonestInvestigator._is_cancelled()`` sees at the
top of each turn, terminating the loop by the same code path as the
operator-initiated Stop button. On return the handler overrides the
final status to ``exhausted`` so the UI can distinguish budget cap from
manual cancel. The turn cap (``_HARD_TURN_CAP=50`` in investigator.py) and
this cost cap are ANDed: whichever fires first halts the run.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func as sa_func
from sqlmodel import select as _select

from aila.modules.forensics.agents.investigator import HonestInvestigator
from aila.modules.forensics.config_schema import ForensicsConfigSchema
from aila.modules.forensics.contracts.status import InvestigationStatus
from aila.modules.forensics.db_models import InvestigationRunRecord
from aila.modules.forensics.workflow.inputs import FreeFlowInput
from aila.platform.exceptions import AILAError
from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import StateResult
from aila.storage.registry import ConfigRegistry

__all__ = [
    "state_freeflow",
]

_log = logging.getLogger(__name__)

state_freeflow_parallel_safe = False
state_freeflow_writes_fields = ["investigation", "steps", "answer"]

# Cost-ceiling monitor poll interval in seconds. Kept coarse because each
# poll opens a new UoW and a SUM query; a run pinned at 50 turns of Opus
# takes many minutes, so a 15-second cadence detects a breach at least
# one turn before the next LLM call fires.
_COST_MONITOR_POLL_SECONDS = 15.0

# Sentinel prefix on ``final_answer`` for a cost-terminated run. The UI
# keys off this to render a distinct "budget exhausted" state instead of
# a generic cancel.
_BUDGET_EXHAUSTED_PREFIX = "<budget_exhausted:"


async def _read_freeflow_max_cost_usd() -> float:
    """Resolve the freeflow_max_cost_usd config value via ConfigRegistry.

    Falls back to the schema default when the registry read fails so a
    transient DB blip never disables the ceiling entirely. Values of
    ``0.0`` (or negative) are treated as "ceiling disabled" downstream.
    """
    default = float(ForensicsConfigSchema.model_fields["freeflow_max_cost_usd"].default)
    try:
        raw = await ConfigRegistry().get("forensics", "freeflow_max_cost_usd")
    except (OSError, RuntimeError, AILAError) as exc:
        _log.warning("freeflow_max_cost_usd registry read failed (%s); using default %.2f", exc, default)
        return default
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        _log.warning("freeflow_max_cost_usd config value %r not coercible to float; using default %.2f", raw, default)
        return default


async def _freeflow_actual_cost_usd(investigation_id: str) -> float:
    """Sum ``LLMCostRecord.cost_usd`` for ``run_id == investigation_id``.

    Uses ``coalesce(sum(...), 0.0)`` so an investigation with zero recorded
    calls returns 0.0, not None. Returns 0.0 for an empty investigation_id
    so callers do not have to guard for the pre-init case.
    """
    if not investigation_id:
        return 0.0
    async with UnitOfWork() as uow:
        result = await uow.session.exec(
            _select(sa_func.coalesce(sa_func.sum(LLMCostRecord.cost_usd), 0.0))
            .where(LLMCostRecord.run_id == investigation_id)
        )
        raw = result.one()
    # coalesce returns 0.0 (not None) so the None branch is defensive only.
    return float(raw) if raw is not None else 0.0


def _freeflow_cost_ceiling_exceeded(actual_usd: float, cap_usd: float) -> bool:
    """Pure check: has cumulative cost reached the configured cap?

    A cap of ``0.0`` (or negative) means "unbounded" -- the ceiling is
    disabled and the check always returns False. A positive cap fires the
    moment ``actual_usd`` meets or exceeds it. Cost is monotonically
    non-decreasing per run so this is safe to poll from a monitor loop.
    """
    if cap_usd <= 0.0:
        return False
    return actual_usd >= cap_usd


async def _flip_investigation_cancelled(investigation_id: str) -> bool:
    """Force the investigation status to ``cancelled``.

    ``HonestInvestigator._is_cancelled()`` polls this column at the top
    of every turn; flipping it here halts the loop at the next turn
    boundary via the same code path as the operator Stop button. Returns
    True when the row was flipped this call (idempotent: a second call
    on an already-cancelled row is a no-op that returns False).
    """
    if not investigation_id:
        return False
    try:
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(InvestigationRunRecord).where(
                    InvestigationRunRecord.id == investigation_id
                )
            )).first()
            if row is None:
                return False
            if row.status == InvestigationStatus.CANCELLED.value:
                return False
            row.status = InvestigationStatus.CANCELLED.value
            uow.session.add(row)
            await uow.commit()
            return True
    except (OSError, RuntimeError, AILAError):
        _log.exception("cost ceiling failed to flip investigation %s to cancelled", investigation_id)
        return False


async def _cost_ceiling_monitor(
    investigation_id: str,
    cap_usd: float,
    emitter: Any,
    stop_event: asyncio.Event,
    outcome: dict[str, Any],
) -> None:
    """Background poller: halt the run when the cost ceiling is crossed.

    Records the breach in ``outcome`` (``hit``, ``actual_usd``) so the
    caller can override the final status to ``exhausted``. Exits when
    ``stop_event`` is set (normal completion) or when it flips the
    investigation status. Errors are logged and skipped -- the monitor
    must never propagate an exception into the state handler.
    """
    if cap_usd <= 0.0 or not investigation_id:
        return
    while not stop_event.is_set():
        try:
            actual = await _freeflow_actual_cost_usd(investigation_id)
        except (OSError, RuntimeError, AILAError) as exc:
            _log.warning("cost monitor query failed for inv %s: %s", investigation_id, exc)
            actual = 0.0
        if _freeflow_cost_ceiling_exceeded(actual, cap_usd):
            outcome["hit"] = True
            outcome["actual_usd"] = actual
            try:
                await emitter.emit(
                    "freeflow",
                    f"Cost ceiling ${cap_usd:.2f} reached at ${actual:.2f} -- halting.",
                    {
                        "stage": "cost_ceiling_reached",
                        "actual_usd": actual,
                        "cap_usd": cap_usd,
                    },
                )
            except (OSError, RuntimeError, AILAError):
                _log.exception("cost ceiling emit failed for inv %s", investigation_id)
            await _flip_investigation_cancelled(investigation_id)
            return
        try:
            await asyncio.wait_for(
                stop_event.wait(), timeout=_COST_MONITOR_POLL_SECONDS,
            )
            # stop_event fired -- normal completion, exit cleanly.
            return
        except TimeoutError:
            # Poll interval elapsed; go around and re-check cost.
            continue


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
    # polls actual cost every _COST_MONITOR_POLL_SECONDS. If the cap is
    # crossed it flips the investigation row to ``cancelled``; the
    # investigator halts at the next turn boundary via its existing
    # cancel-check path. We then override the final status to EXHAUSTED
    # to distinguish budget cap from operator Stop.
    cost_cap_usd = await _read_freeflow_max_cost_usd()
    cost_outcome: dict[str, Any] = {"hit": False, "actual_usd": 0.0}
    stop_event = asyncio.Event()
    monitor_task: asyncio.Task[None] | None = None
    if cost_cap_usd > 0.0:
        monitor_task = asyncio.create_task(
            _cost_ceiling_monitor(
                investigation_id=data.investigation_id,
                cap_usd=cost_cap_usd,
                emitter=services.emitter,
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
    except (OSError, TimeoutError, RuntimeError, ValueError, KeyError, AILAError) as exc:
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
    # between startup and turn 1. That's not a failure.
    steps_list = result.get("steps", []) or []
    cancelled = bool(result.get("cancelled"))
    if not steps_list and not cancelled:
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
    elif has_answer:
        final_status = InvestigationStatus.COMPLETED.value
    elif cancelled:
        final_status = InvestigationStatus.CANCELLED.value
    else:
        final_status = InvestigationStatus.FAILED.value
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
                        f"{_BUDGET_EXHAUSTED_PREFIX}"
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
