"""Tests for session memory accumulation in StructuredAgent.run_structured().

AGENT-08: After each run_structured() call the result summary is appended to
the SessionMemory. Subsequent calls prepend stored entries to the prompt.
reset_session() clears both session memory and output cache.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel

from aila.platform.routing.agent import StructuredAgent


class _Reply(BaseModel):
    answer: str


def _make_mock_model() -> MagicMock:
    """Return a MagicMock that satisfies the LLMClient protocol."""
    model = MagicMock()
    model.model_id = "test-model"
    return model


def _make_agent() -> StructuredAgent:
    """Construct a StructuredAgent with a mock LLMClient."""
    return StructuredAgent(
        model=_make_mock_model(),
        name="test_agent",
        response_model=_Reply,
    )


# ---------------------------------------------------------------------------
# Test 5: After one successful call, session memory has one entry with model class name
# ---------------------------------------------------------------------------

def test_session_memory_appended_after_one_call():
    agent = _make_agent()
    agent._invoke_model = MagicMock(return_value='{"answer": "hello"}')  # type: ignore[method-assign]

    agent.run_structured("First call", response_model=_Reply)

    assert len(agent._session_memory) == 1
    context = agent._session_memory.get_context()
    assert context is not None
    assert "_Reply" in context


# ---------------------------------------------------------------------------
# Test 6: Second call's effective prompt contains "Prior calls in this session:"
# ---------------------------------------------------------------------------

def test_session_memory_prepended_to_second_call_prompt():
    agent = _make_agent()
    captured_prompts: list[str] = []

    def _fake_invoke(prompt: str, additional_args=None) -> str:
        captured_prompts.append(prompt)
        return '{"answer": "ok"}'

    agent._invoke_model = _fake_invoke  # type: ignore[method-assign]

    agent.run_structured("First call", response_model=_Reply)
    # Cache would return same result; use a different task to avoid cache hit
    agent.run_structured("Second call with different text", response_model=_Reply)

    assert len(captured_prompts) >= 2
    second_prompt = captured_prompts[1]
    assert "Prior calls in this session:" in second_prompt


# ---------------------------------------------------------------------------
# Test 7: Session memory capped at 5 entries (SessionMemory max_entries=5)
# ---------------------------------------------------------------------------

def test_session_memory_capped_at_five_entries_in_prompt():
    agent = _make_agent()
    captured_prompts: list[str] = []
    call_idx = [0]

    def _fake_invoke(prompt: str, additional_args=None) -> str:
        captured_prompts.append(prompt)
        call_idx[0] += 1
        return f'{{"answer": "resp{call_idx[0]}"}}'

    agent._invoke_model = _fake_invoke  # type: ignore[method-assign]

    # Make 10 calls, each with a unique task so no cache hits
    for i in range(10):
        agent.run_structured(f"Call number {i}", response_model=_Reply)

    # SessionMemory(max_entries=5) keeps only the last 5
    assert len(agent._session_memory) == 5

    # The 11th call's prompt should contain at most 5 prior entries
    agent.run_structured("Call number 10", response_model=_Reply)
    last_prompt = captured_prompts[-1]

    # Count occurrences of the prior-calls marker
    assert "Prior calls in this session:" in last_prompt
    # Each memory entry contains "[test_agent]"
    prior_section = last_prompt.split("Prior calls in this session:")[1].split("\n\n")[0]
    entry_count = prior_section.count("[test_agent]")
    assert entry_count == 5, f"Expected 5 prior call entries in prompt, got {entry_count}"


# ---------------------------------------------------------------------------
# Test 8: reset_session() clears both session memory and output cache
# ---------------------------------------------------------------------------

def test_reset_session_clears_memory_and_cache():
    agent = _make_agent()
    agent._invoke_model = MagicMock(return_value='{"answer": "stored"}')  # type: ignore[method-assign]

    agent.run_structured("Fill cache", response_model=_Reply)
    assert len(agent._session_memory) == 1
    assert len(agent._output_cache) == 1

    agent.reset_session()

    assert len(agent._session_memory) == 0
    assert len(agent._output_cache) == 0
