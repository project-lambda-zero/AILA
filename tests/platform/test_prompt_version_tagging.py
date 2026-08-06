"""Tests for RFC-09 step 1: LLM cost records are tagged with the resolved
system prompt's content hash via the correlation ContextVar.

The agent turn loop sets prompt_content_hash on correlation_scope; the
cost-record writer reads it so each call is attributable to the exact prompt
content that produced it.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlmodel import select

from aila.platform.llm.correlation import correlation_scope
from aila.platform.llm.cost import persist_cost_record
from aila.platform.llm.cost_record import LLMCostRecord
from aila.storage.database import session_scope


def _read(run_id: str) -> LLMCostRecord:
    with session_scope() as sess:
        row = sess.exec(
            select(LLMCostRecord).where(LLMCostRecord.run_id == run_id)
        ).first()
        assert row is not None
        return row


@pytest.mark.asyncio
async def test_content_hash_tagged_from_correlation(test_db) -> None:
    del test_db
    run_id = f"run-{uuid4().hex[:8]}"
    with correlation_scope(
        investigation_id="inv-1", branch_id="br-1", turn_number=3,
        prompt_content_hash="deadbeefhash",
    ):
        await persist_cost_record(
            run_id=run_id, model_id="m", task_type="scoring", team_id=None,
            prompt_tokens=1, completion_tokens=1, cost_usd=0.0,
        )
    row = _read(run_id)
    assert row.prompt_content_hash == "deadbeefhash"
    assert row.investigation_id == "inv-1"
    assert row.turn_number == 3


@pytest.mark.asyncio
async def test_content_hash_none_without_scope(test_db) -> None:
    del test_db
    run_id = f"run-{uuid4().hex[:8]}"
    await persist_cost_record(
        run_id=run_id, model_id="m", task_type="scoring", team_id=None,
        prompt_tokens=1, completion_tokens=1, cost_usd=0.0,
    )
    row = _read(run_id)
    assert row.prompt_content_hash is None
