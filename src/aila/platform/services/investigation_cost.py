"""Platform live-cost aggregation for investigations.

Sums :class:`LLMCostRecord.cost_usd` for one investigation. The vr and
malware reasoning engines both thread the investigation id through as the
LLM call ``run_id`` (``malware_researcher`` passes ``run_id=investigation_id``;
the vr turn engine threads it through ``decide_next_turn``), so the live
cost is a direct filter on ``run_id``.

The stored ``cost_actual_usd`` column has no writers, so a summary that
reads it directly always reports 0.0 regardless of actual spend. Callers
pass the value returned here as the ``live_cost_usd`` override instead.
Keeping one aggregator on the platform means both modules report cost the
same way; a per-module copy is how the malware gauge fell to a permanent
zero while VR reported real spend.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func as sa_func
from sqlalchemy import update as sa_update
from sqlmodel import select

from aila.platform.contracts.investigation_base import InvestigationRecordBase
from aila.platform.llm.cost_record import LLMCostRecord

_log = logging.getLogger(__name__)

__all__ = ["accrue_investigation_cost", "compute_live_investigation_cost"]


async def compute_live_investigation_cost(
    uow: Any, investigation_id: str,
) -> float:
    """Sum recorded LLM cost for ``investigation_id``.

    Best-effort: returns 0.0 on any query error so the budget gauge
    degrades to the stored zero rather than crashing the read path.
    """
    try:
        sum_q = select(
            sa_func.coalesce(sa_func.sum(LLMCostRecord.cost_usd), 0.0),
        ).where(LLMCostRecord.run_id == investigation_id)
        total = (await uow.session.exec(sum_q)).one()
        return float(total)
    except (AttributeError, ImportError, ValueError) as exc:
        _log.warning(
            "compute_live_investigation_cost failed reason=%s", exc,
        )
        return 0.0


async def accrue_investigation_cost(
    session: Any, run_id: str, cost_usd: float,
) -> None:
    """Increment the stored cost columns on the investigation owning ``run_id``.

    Option (a) of the cost-materialization RFC (#135): keep
    ``cost_actual_usd`` correct on write so list endpoints and the
    per-investigation budget cap read real spend instead of the permanent
    zero a never-written column reports. Module-agnostic -- issues one
    PK-targeted atomic increment per concrete investigation table; exactly
    one table carries the row and the rest are no-ops. Runs in the caller's
    session so the increment commits atomically with the cost-record insert
    (no drift window). ``run_id`` is the value the reasoning engine threads
    as the investigation id, matching the join in
    :func:`compute_live_investigation_cost`.

    Best-effort: a leaked query error must never fail cost recording, so the
    caller wraps this alongside the record insert in its own guard.
    """
    if not run_id or run_id == "_no_run" or cost_usd <= 0.0:
        return
    for model in InvestigationRecordBase.__subclasses__():
        if not getattr(model, "__tablename__", None):
            continue
        await session.exec(  # type: ignore[call-overload]
            sa_update(model)
            .where(model.id == run_id)
            .values(
                cost_actual_usd=model.cost_actual_usd + cost_usd,
                llm_tokens_cost_usd=model.llm_tokens_cost_usd + cost_usd,
            ),
        )
