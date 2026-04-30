"""Tests for structured observability logging in StructuredAgent.run_structured().

AGENT-07: Every run_structured() call emits a DEBUG log record with
agent_name, latency_ms (int >= 0), cache_hit (bool), retry_count (int).
"""
from __future__ import annotations

import logging
import time
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

from aila.platform.routing.agent import StructuredAgent


class _Reply(BaseModel):
    answer: str


def _make_mock_model(response_json: str = '{"answer":"yes"}') -> MagicMock:
    """Return a MagicMock that satisfies the LLMClient protocol."""
    model = MagicMock()
    model.model_id = "test-model"
    response = MagicMock()
    response.content = response_json
    model.chat_sync.return_value = response
    return model


def _make_agent(model=None) -> StructuredAgent:
    """Construct a StructuredAgent with a mock LLMClient."""
    if model is None:
        model = _make_mock_model()
    return StructuredAgent(
        model=model,
        name="test_agent",
        response_model=_Reply,
    )


def _stub_invoke(agent: StructuredAgent, json_str: str) -> None:
    agent._invoke_model = MagicMock(return_value=json_str)  # type: ignore[method-assign]


# ---------------------------------------------------------------------------
# Test 1: successful first call emits DEBUG record with expected keys
# ---------------------------------------------------------------------------

def test_run_structured_emits_debug_log_on_success(caplog):
    agent = _make_agent()
    _stub_invoke(agent, '{"answer": "yes"}')

    with caplog.at_level(logging.DEBUG, logger="aila.platform.routing.agent"):
        agent.run_structured("What is 1+1?", response_model=_Reply)

    agent_run_records = [r for r in caplog.records if r.getMessage() == "agent_run"]
    assert agent_run_records, "Expected a 'agent_run' DEBUG record"
    rec = agent_run_records[0]
    assert hasattr(rec, "agent_name"), "Missing agent_name in log extra"
    assert hasattr(rec, "latency_ms"), "Missing latency_ms in log extra"
    assert hasattr(rec, "cache_hit"), "Missing cache_hit in log extra"
    assert hasattr(rec, "retry_count"), "Missing retry_count in log extra"
    assert rec.cache_hit is False
    assert rec.retry_count == 0


# ---------------------------------------------------------------------------
# Test 2: cache hit emits cache_hit=True
# ---------------------------------------------------------------------------

def test_run_structured_emits_cache_hit_true(caplog):
    agent = _make_agent()
    _stub_invoke(agent, '{"answer": "yes"}')

    # First call populates cache
    agent.run_structured("What is 1+1?", response_model=_Reply)

    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger="aila.platform.routing.agent"):
        agent.run_structured("What is 1+1?", response_model=_Reply)

    agent_run_records = [r for r in caplog.records if r.getMessage() == "agent_run"]
    assert agent_run_records, "Expected an 'agent_run' DEBUG record on cache hit"
    rec = agent_run_records[0]
    assert rec.cache_hit is True


# ---------------------------------------------------------------------------
# Test 3: retry path emits retry_count=1
# ---------------------------------------------------------------------------

def test_run_structured_emits_retry_count_one_on_retry(caplog):
    agent = _make_agent()
    # First call returns bad JSON, second returns good JSON
    agent._invoke_model = MagicMock(  # type: ignore[method-assign]
        side_effect=["not-json", '{"answer": "recovered"}']
    )

    with caplog.at_level(logging.DEBUG, logger="aila.platform.routing.agent"):
        result = agent.run_structured("retry test", response_model=_Reply)

    assert result.answer == "recovered"
    agent_run_records = [r for r in caplog.records if r.getMessage() == "agent_run"]
    assert agent_run_records
    rec = agent_run_records[0]
    assert rec.retry_count == 1


# ---------------------------------------------------------------------------
# Test 4: latency_ms is int >= 0 and non-zero when time advances
# ---------------------------------------------------------------------------

def test_run_structured_latency_ms_is_nonneg_int(caplog):
    agent = _make_agent()
    _stub_invoke(agent, '{"answer": "timed"}')

    # Simulate 50 ms elapsed by patching time.monotonic
    call_count = 0

    def _fake_monotonic():
        nonlocal call_count
        call_count += 1
        # First call (start) returns 0.0, second call (end) returns 0.05
        return 0.0 if call_count == 1 else 0.05

    with patch("aila.platform.routing.agent.time") as mock_time:
        mock_time.monotonic.side_effect = _fake_monotonic
        with caplog.at_level(logging.DEBUG, logger="aila.platform.routing.agent"):
            agent.run_structured("timing test", response_model=_Reply)

    agent_run_records = [r for r in caplog.records if r.getMessage() == "agent_run"]
    assert agent_run_records
    rec = agent_run_records[0]
    assert isinstance(rec.latency_ms, int)
    assert rec.latency_ms >= 0
    # With 50ms mock, should be 50
    assert rec.latency_ms == 50
