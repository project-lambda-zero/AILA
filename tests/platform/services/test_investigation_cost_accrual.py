"""Regression guard for issue #135 -- accrue_investigation_cost materializes
LLM spend onto the owning investigation row's ``cost_actual_usd`` column so
list views and the per-investigation budget cap read real spend instead of
the permanent zero a never-written column reports.

These fail on the pre-#135 code: before the accrual writeback existed,
``cost_actual_usd`` had no writers and stayed 0.0 regardless of spend.
"""
from __future__ import annotations

from sqlmodel import select

from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.services.investigation_cost import accrue_investigation_cost
from aila.platform.uow import UnitOfWork


async def _seed_investigation(inv: str) -> None:
    """Seed the minimum FK chain (workspace + target + investigation)."""
    ws_id = f"ws-{inv}"
    tgt_id = f"tgt-{inv}"
    async with UnitOfWork() as uow:
        uow.session.add(VRWorkspaceRecord(id=ws_id, name="ws", slug=ws_id))
        await uow.session.flush()
        uow.session.add(
            VRTargetRecord(
                id=tgt_id,
                workspace_id=ws_id,
                display_name="tgt",
                kind="native_binary",
            ),
        )
        await uow.session.flush()
        uow.session.add(
            VRInvestigationRecord(
                id=inv,
                target_id=tgt_id,
                title="seed",
                kind="discovery",
                strategy_family="vulnerability_research.discovery_research",
            ),
        )
        await uow.session.commit()


async def _cost(inv: str) -> tuple[float, float]:
    async with UnitOfWork() as uow:
        row = (
            await uow.session.exec(
                select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == inv,
                ),
            )
        ).one()
        return row.cost_actual_usd, row.llm_tokens_cost_usd


async def test_accrue_increments_and_accumulates(test_db) -> None:
    """Each accrual atomically adds to both the total and the LLM stream."""
    inv = "inv-135-accrue"
    await _seed_investigation(inv)
    assert await _cost(inv) == (0.0, 0.0)

    async with UnitOfWork() as uow:
        await accrue_investigation_cost(uow.session, inv, 1.5)
        await uow.session.commit()
    assert await _cost(inv) == (1.5, 1.5)

    # A second charge accumulates rather than overwriting -- proves the SQL
    # increment reads the prior value (col = col + delta), not a set.
    async with UnitOfWork() as uow:
        await accrue_investigation_cost(uow.session, inv, 2.0)
        await uow.session.commit()
    assert await _cost(inv) == (3.5, 3.5)


async def test_accrue_skips_noop_inputs(test_db) -> None:
    """Zero cost, the sentinel run id, and an empty run id are no-ops."""
    inv = "inv-135-noop"
    await _seed_investigation(inv)
    async with UnitOfWork() as uow:
        await accrue_investigation_cost(uow.session, inv, 0.0)
        await accrue_investigation_cost(uow.session, "_no_run", 5.0)
        await accrue_investigation_cost(uow.session, "", 5.0)
        await uow.session.commit()
    assert await _cost(inv) == (0.0, 0.0)


async def test_accrue_unknown_run_id_touches_nothing(test_db) -> None:
    """A run id that matches no investigation row is a silent no-op (the
    PK-targeted UPDATE affects zero rows), not an error."""
    inv = "inv-135-known"
    await _seed_investigation(inv)
    async with UnitOfWork() as uow:
        await accrue_investigation_cost(uow.session, "inv-135-absent", 9.0)
        await uow.session.commit()
    assert await _cost(inv) == (0.0, 0.0)
