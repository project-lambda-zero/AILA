"""Cost-ceiling enforcement shared by forensics investigation loops.

The operator-tunable ``forensics.freeflow_max_cost_usd`` config field caps
cumulative LLM spend per investigation. ``cost_ceiling_monitor`` polls
``LLMCostRecord.cost_usd`` summed over ``run_id == investigation_id``, so
every LLM call attributed to the investigation counts toward the cap. When
the cap is crossed it flips the investigation row's status to ``cancelled``,
which the investigation loop observes at its next turn boundary, and records
the breach in the caller's outcome mapping so the caller can finalize the run
as exhausted.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy import func as sa_func
from sqlmodel import select as _select

from aila.modules.forensics.config_schema import ForensicsConfigSchema
from aila.modules.forensics.contracts.status import InvestigationStatus
from aila.modules.forensics.db_models import InvestigationRunRecord
from aila.platform.exceptions import AILAError
from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.uow import UnitOfWork
from aila.storage.registry import ConfigRegistry

__all__ = [
    "BUDGET_EXHAUSTED_PREFIX",
    "COST_MONITOR_POLL_SECONDS",
    "actual_cost_usd",
    "cost_ceiling_exceeded",
    "cost_ceiling_monitor",
    "read_cost_cap_usd",
]

_log = logging.getLogger(__name__)

# Cost-ceiling monitor poll interval in seconds. Kept coarse because each
# poll opens a new UoW and a SUM query; a run pinned at 50 turns of Opus
# takes many minutes, so a 15-second cadence detects a breach at least
# one turn before the next LLM call fires.
COST_MONITOR_POLL_SECONDS = 15.0

# Sentinel prefix on ``final_answer`` for a cost-terminated run. The UI
# keys off this to render a distinct "budget exhausted" state instead of
# a generic cancel.
BUDGET_EXHAUSTED_PREFIX = "<budget_exhausted:"


async def read_cost_cap_usd() -> float:
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


async def actual_cost_usd(investigation_id: str) -> float:
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


def cost_ceiling_exceeded(actual_usd: float, cap_usd: float) -> bool:
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

    ``HonestInvestigator._stop_status()`` polls this column at the top
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


async def cost_ceiling_monitor(
    *,
    investigation_id: str,
    cap_usd: float,
    emitter: Any,
    source: str,
    stop_event: asyncio.Event,
    outcome: dict[str, Any],
) -> None:
    """Background poller: halt the run when the cost ceiling is crossed.

    ``source`` is the stream label the breach event is emitted under, so
    each loop reports the breach under its own stage name. Records the
    breach in ``outcome`` (``hit``, ``actual_usd``) so the caller can
    override the final status to ``exhausted``. Exits when ``stop_event``
    is set (normal completion) or when it flips the investigation status.
    Errors are logged and skipped -- the monitor must never propagate an
    exception into the state handler.
    """
    if cap_usd <= 0.0 or not investigation_id:
        return
    while not stop_event.is_set():
        try:
            actual = await actual_cost_usd(investigation_id)
        except (OSError, RuntimeError, AILAError) as exc:
            _log.warning("cost monitor query failed for inv %s: %s", investigation_id, exc)
            actual = 0.0
        if cost_ceiling_exceeded(actual, cap_usd):
            outcome["hit"] = True
            outcome["actual_usd"] = actual
            try:
                await emitter.emit(
                    source,
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
                stop_event.wait(), timeout=COST_MONITOR_POLL_SECONDS,
            )
            # stop_event fired -- normal completion, exit cleanly.
            return
        except TimeoutError:
            # Poll interval elapsed; go around and re-check cost.
            continue
