"""Tests for structured observability logging in StructuredAgent.run_structured().

Issue #62 migration. The current production agent emits ONE DEBUG record per
call with message ``"agent_run"`` and extras ``agent_name``, ``latency_ms``,
``model`` (see src/aila/platform/routing/agent.py). The removed observability
fields (``cache_hit``, ``retry_count``) went away with the in-agent output
cache and retry loop -- retry / caching relocated into
``AilaLLMClient.chat_structured``. Tests that only asserted those two fields
were dropped; the still-valid latency contract is retained here.
"""
from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock, patch

from pydantic import BaseModel

from aila.platform.routing.agent import StructuredAgent


class _Reply(BaseModel):
    answer: str


def _stub_chat_structured(agent: StructuredAgent, json_str: str) -> None:
    """Attach an AsyncMock chat_structured to the agent's model.

    run_structured awaits ``self.model.chat_structured(task_type, messages,
    model_cls)`` and reads ``.content`` (JSON) + ``.model`` off the returned
    response.
    """
    resp = MagicMock()
    resp.content = json_str
    resp.model = "test-model"
    agent.model.chat_structured = AsyncMock(return_value=resp)


def _make_agent() -> StructuredAgent:
    """Construct a StructuredAgent with a MagicMock model carrying model_id."""
    model = MagicMock()
    model.model_id = "test-model"
    return StructuredAgent(
        model=model,
        name="test_agent",
        response_model=_Reply,
    )


async def test_run_structured_latency_ms_is_nonneg_int(caplog):
    """agent_run DEBUG record carries an integer latency_ms >= 0 that reflects wall time."""
    agent = _make_agent()
    _stub_chat_structured(agent, '{"answer": "timed"}')

    # Simulate 50 ms elapsed by patching aila.platform.routing.agent.time.
    call_count = 0

    def _fake_monotonic():
        nonlocal call_count
        call_count += 1
        # First call (start) returns 0.0, second call (end) returns 0.05
        return 0.0 if call_count == 1 else 0.05

    with patch("aila.platform.routing.agent.time") as mock_time:
        mock_time.monotonic.side_effect = _fake_monotonic
        with caplog.at_level(logging.DEBUG, logger="aila.platform.routing.agent"):
            await agent.run_structured("timing test", response_model=_Reply)

    agent_run_records = [r for r in caplog.records if r.getMessage() == "agent_run"]
    assert agent_run_records, "Expected an 'agent_run' DEBUG record"
    rec = agent_run_records[0]
    assert hasattr(rec, "agent_name")
    assert hasattr(rec, "latency_ms")
    assert isinstance(rec.latency_ms, int)
    assert rec.latency_ms >= 0
    # With the 50 ms mock monotonic, latency_ms MUST be exactly 50.
    assert rec.latency_ms == 50
