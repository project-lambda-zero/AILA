"""#39: investigation/branch/turn correlation for observability records.

Unit coverage for the ContextVar plumbing plus a DB round-trip proving a cost
record written inside a correlation scope carries the join keys.
"""
from __future__ import annotations

import pytest

from aila.platform.llm.correlation import correlation_scope, current_join_keys


def test_join_keys_none_by_default() -> None:
    assert current_join_keys() == (None, None, None)


def test_scope_sets_then_resets() -> None:
    with correlation_scope(investigation_id="i", branch_id="b", turn_number=3):
        assert current_join_keys() == ("i", "b", 3)
    assert current_join_keys() == (None, None, None)


def test_nested_scope_restores_outer() -> None:
    with correlation_scope(investigation_id="outer", branch_id="ob", turn_number=1):
        with correlation_scope(investigation_id="inner", branch_id="ib", turn_number=2):
            assert current_join_keys() == ("inner", "ib", 2)
        assert current_join_keys() == ("outer", "ob", 1)
    assert current_join_keys() == (None, None, None)


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_cost_record_carries_correlation() -> None:
    from sqlmodel import select

    from aila.platform.llm.cost import persist_cost_record
    from aila.platform.llm.cost_record import LLMCostRecord
    from aila.platform.uow import UnitOfWork

    run_id = "corr-cost-run"
    with correlation_scope(investigation_id="inv-x", branch_id="br-y", turn_number=4):
        await persist_cost_record(
            run_id=run_id, model_id="m", task_type="t", team_id=None,
            prompt_tokens=1, completion_tokens=1, cost_usd=0.0,
        )
    async with UnitOfWork() as uow:
        rows = (
            await uow.session.exec(select(LLMCostRecord).where(LLMCostRecord.run_id == run_id))
        ).all()
    assert len(rows) == 1
    assert (rows[0].investigation_id, rows[0].branch_id, rows[0].turn_number) == ("inv-x", "br-y", 4)


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_cost_record_none_outside_scope() -> None:
    from sqlmodel import select

    from aila.platform.llm.cost import persist_cost_record
    from aila.platform.llm.cost_record import LLMCostRecord
    from aila.platform.uow import UnitOfWork

    run_id = "no-corr-cost-run"
    await persist_cost_record(
        run_id=run_id, model_id="m", task_type="t", team_id=None,
        prompt_tokens=1, completion_tokens=1, cost_usd=0.0,
    )
    async with UnitOfWork() as uow:
        rows = (
            await uow.session.exec(select(LLMCostRecord).where(LLMCostRecord.run_id == run_id))
        ).all()
    assert len(rows) == 1
    assert (rows[0].investigation_id, rows[0].branch_id, rows[0].turn_number) == (None, None, None)
