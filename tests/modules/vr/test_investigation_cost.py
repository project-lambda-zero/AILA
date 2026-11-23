"""VR live-cost aggregation keys on run_id == investigation_id (#59/#39).

The reasoning engine now threads the investigation_id as the LLM run_id, so
per-investigation cost is a direct sum of LLMCostRecord.cost_usd filtered by
run_id. Before that threading run_id was empty for investigation calls and the
gauge read $0.00 regardless of real spend.
"""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_compute_live_investigation_cost_sums_by_investigation_id(test_db) -> None:
    from aila.platform.services.investigation_cost import compute_live_investigation_cost as _compute_live_investigation_cost
    from aila.platform.llm.cost_record import LLMCostRecord
    from aila.platform.uow import UnitOfWork
    from aila.storage.database import async_session_scope

    inv_id = "inv-cost-vr-001"
    async with async_session_scope() as session:
        session.add(LLMCostRecord(
            run_id=inv_id, model_id="m", task_type="mobile_research", cost_usd=1.25,
        ))
        session.add(LLMCostRecord(
            run_id=inv_id, model_id="m", task_type="mobile_research", cost_usd=0.75,
        ))
        # A different investigation's spend must not leak into the sum.
        session.add(LLMCostRecord(
            run_id="inv-other-999", model_id="m", task_type="mobile_research", cost_usd=9.0,
        ))
        await session.commit()

    async with UnitOfWork() as uow:
        total = await _compute_live_investigation_cost(uow, inv_id)

    assert total == pytest.approx(2.0)


@pytest.mark.asyncio
async def test_compute_live_investigation_cost_zero_when_no_rows(test_db) -> None:
    from aila.platform.services.investigation_cost import compute_live_investigation_cost as _compute_live_investigation_cost
    from aila.platform.uow import UnitOfWork

    async with UnitOfWork() as uow:
        total = await _compute_live_investigation_cost(uow, "inv-with-no-cost-rows")

    assert total == pytest.approx(0.0)


@pytest.mark.asyncio
async def test_sum_run_cost_usd_team_filter_excludes_other_teams(test_db) -> None:
    from aila.platform.llm.cost_record import LLMCostRecord
    from aila.platform.services.investigation_cost import sum_run_cost_usd
    from aila.storage.database import async_session_scope

    run_id = "run-team-scope-001"
    async with async_session_scope() as session:
        session.add(LLMCostRecord(
            run_id=run_id, team_id="team-a", model_id="m", task_type="t", cost_usd=1.0,
        ))
        session.add(LLMCostRecord(
            run_id=run_id, team_id="team-b", model_id="m", task_type="t", cost_usd=5.0,
        ))
        await session.commit()

    async with async_session_scope() as session:
        assert await sum_run_cost_usd(session, run_id=run_id, team_id="team-a") == pytest.approx(1.0)
        assert await sum_run_cost_usd(session, run_id=run_id) == pytest.approx(6.0)


@pytest.mark.asyncio
async def test_sum_run_cost_usd_propagates_query_errors() -> None:
    from aila.platform.services.investigation_cost import sum_run_cost_usd

    class _FailingSession:
        async def exec(self, _stmt):
            raise RuntimeError("db down")

    with pytest.raises(RuntimeError, match="db down"):
        await sum_run_cost_usd(_FailingSession(), run_id="run-x")


@pytest.mark.asyncio
async def test_compute_live_investigation_cost_zero_on_handled_db_error() -> None:
    from sqlalchemy.exc import SQLAlchemyError

    from aila.platform.services.investigation_cost import compute_live_investigation_cost

    class _FailingSession:
        async def exec(self, _stmt):
            raise SQLAlchemyError("connection lost")

    class _Uow:
        session = _FailingSession()

    assert await compute_live_investigation_cost(_Uow(), "inv-handled-error") == pytest.approx(0.0)
