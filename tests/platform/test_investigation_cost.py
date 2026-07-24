"""Platform live-cost aggregator.

``compute_live_investigation_cost`` sums ``LLMCostRecord.cost_usd`` for
one investigation, filtered by ``run_id`` (which the vr and malware
reasoning engines thread as the investigation id). This one
implementation backs both modules' budget gauges; it replaced a
per-module copy that had drifted (the malware gauge read the unwritten
``cost_actual_usd`` column and reported a permanent $0).
"""
from __future__ import annotations

import pytest

from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.services.investigation_cost import (
    compute_live_investigation_cost,
)
from aila.platform.uow import UnitOfWork


async def _seed_cost(run_id: str, cost_usd: float) -> None:
    async with UnitOfWork() as uow:
        uow.session.add(
            LLMCostRecord(
                run_id=run_id,
                model_id="test-model",
                cost_usd=cost_usd,
                team_id="admin",
            ),
        )
        await uow.session.commit()


@pytest.mark.usefixtures("test_db")
async def test_sums_only_matching_run_id() -> None:
    """Sum covers every cost row keyed to this investigation and excludes
    rows recorded for other runs."""
    inv_id = "inv-cost-1"
    await _seed_cost(inv_id, 1.25)
    await _seed_cost(inv_id, 0.75)
    await _seed_cost("inv-cost-other", 9.99)

    async with UnitOfWork() as uow:
        total = await compute_live_investigation_cost(uow, inv_id)

    assert total == pytest.approx(2.0)


@pytest.mark.usefixtures("test_db")
async def test_zero_when_no_rows() -> None:
    """An investigation with no cost rows aggregates to 0.0, not an error."""
    async with UnitOfWork() as uow:
        total = await compute_live_investigation_cost(uow, "inv-none")

    assert total == 0.0
