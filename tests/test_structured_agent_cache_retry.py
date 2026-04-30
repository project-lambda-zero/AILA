"""Tests for StructuredAgent output caching and retry-on-failure.

Covers:
- TestAgentOutputCache: in-process dict cache keyed on prompt+model_id+schema hash
- TestAgentRetry: single retry on JSON/schema parse failure with error appended to prompt
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Minimal Pydantic model used across all tests
# ---------------------------------------------------------------------------


class _Out(BaseModel):
    value: str


class _AltOut(BaseModel):
    score: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_model(model_id: str = "test-model", response_json: str = '{"value":"ok"}'):
    """Return a MagicMock that satisfies the LLMClient protocol."""
    model = MagicMock()
    model.model_id = model_id
    response = MagicMock()
    response.content = response_json
    model.chat_sync.return_value = response
    return model


def _make_agent(model=None, instructions: str = "") -> "StructuredAgent":
    """Construct a StructuredAgent with a mock LLMClient."""
    from aila.platform.routing.agent import StructuredAgent

    if model is None:
        model = _make_mock_model()

    return StructuredAgent(
        model=model,
        name="test_agent",
        instructions=instructions,
    )


# ---------------------------------------------------------------------------
# TestAgentOutputCache
# ---------------------------------------------------------------------------


class TestAgentOutputCache:
    def test_cache_hit_on_second_identical_call(self):
        """Second run_structured() with same task returns cached result; model called once."""
        model = _make_mock_model(response_json='{"value":"hello"}')
        agent = _make_agent(model)

        result1 = agent.run_structured("explain risk", response_model=_Out)
        result2 = agent.run_structured("explain risk", response_model=_Out)

        assert result1.value == "hello"
        assert result2.value == "hello"
        assert model.chat_sync.call_count == 1

    def test_different_task_text_causes_new_model_call(self):
        """Different task text produces a different cache key; model is called again."""
        model = _make_mock_model(response_json='{"value":"ok"}')
        agent = _make_agent(model)

        agent.run_structured("task A", response_model=_Out)
        agent.run_structured("task B", response_model=_Out)

        assert model.chat_sync.call_count == 2

    def test_different_model_id_causes_new_model_call(self):
        """Two agents with different model_ids produce different cache keys."""
        model_a = _make_mock_model(model_id="model-a", response_json='{"value":"a"}')
        model_b = _make_mock_model(model_id="model-b", response_json='{"value":"b"}')
        agent_a = _make_agent(model_a)
        agent_b = _make_agent(model_b)

        r_a = agent_a.run_structured("same task", response_model=_Out)
        r_b = agent_b.run_structured("same task", response_model=_Out)

        assert r_a.value == "a"
        assert r_b.value == "b"
        assert model_a.chat_sync.call_count == 1
        assert model_b.chat_sync.call_count == 1

    def test_different_response_model_causes_new_model_call(self):
        """Different Pydantic schema causes different cache key; model called again."""
        model = _make_mock_model(response_json='{"value":"x"}')
        agent = _make_agent(model)

        agent.run_structured("task", response_model=_Out)

        # Now use a different schema -- model must generate again
        model.chat_sync.return_value.content = '{"score":99}'
        agent.run_structured("task", response_model=_AltOut)

        assert model.chat_sync.call_count == 2

    def test_cache_stores_validated_model_instance(self):
        """Cached value is a validated Pydantic instance, returned on second call without generate."""
        model = _make_mock_model(response_json='{"value":"cached"}')
        agent = _make_agent(model)

        first = agent.run_structured("task", response_model=_Out)
        # Sabotage the model to return garbage -- cache should prevent calling it
        model.chat_sync.return_value.content = "NOT JSON"

        second = agent.run_structured("task", response_model=_Out)

        assert isinstance(second, _Out)
        assert second.value == "cached"
        assert model.chat_sync.call_count == 1


# ---------------------------------------------------------------------------
# TestAgentRetry
# ---------------------------------------------------------------------------


class TestAgentRetry:
    def test_retry_succeeds_on_second_attempt(self):
        """First call returns garbage; second (retry) returns valid JSON -- result is returned."""
        model = MagicMock()
        model.model_id = "test-model"
        bad_resp = MagicMock()
        bad_resp.content = "NOT JSON AT ALL"
        good_resp = MagicMock()
        good_resp.content = '{"value":"recovered"}'
        model.chat_sync.side_effect = [bad_resp, good_resp]

        agent = _make_agent(model)
        result = agent.run_structured("task", response_model=_Out)

        assert result.value == "recovered"
        assert model.chat_sync.call_count == 2

    def test_both_attempts_fail_raises_value_error(self):
        """Both attempts return garbage JSON -- ValueError is raised; model called exactly twice."""
        model = MagicMock()
        model.model_id = "test-model"
        bad_resp = MagicMock()
        bad_resp.content = "GARBAGE"
        model.chat_sync.return_value = bad_resp

        agent = _make_agent(model)

        with pytest.raises(ValueError):
            agent.run_structured("task", response_model=_Out)

        assert model.chat_sync.call_count == 2

    def test_no_retry_on_success(self):
        """First call returns valid JSON -- model.chat_sync called exactly once (no retry)."""
        model = _make_mock_model(response_json='{"value":"first"}')
        agent = _make_agent(model)

        result = agent.run_structured("task", response_model=_Out)

        assert result.value == "first"
        assert model.chat_sync.call_count == 1

    def test_retry_prompt_contains_parse_error(self):
        """Retry prompt includes the original prompt and the parse error message."""
        model = MagicMock()
        model.model_id = "test-model"
        bad_resp = MagicMock()
        bad_resp.content = "NOT JSON"
        good_resp = MagicMock()
        good_resp.content = '{"value":"ok"}'
        model.chat_sync.side_effect = [bad_resp, good_resp]

        agent = _make_agent(model)
        agent.run_structured("original task", response_model=_Out)

        # The second chat_sync call is the retry -- inspect its messages tuple
        retry_call_messages = model.chat_sync.call_args_list[1][0][0]  # positional arg 0
        combined_text = " ".join(
            m.content for m in retry_call_messages if m.content
        )
        # Retry prompt must contain the original task text and an error indication
        assert "original task" in combined_text
        assert "failed" in combined_text.lower()

    def test_retry_success_stored_in_cache_under_original_key(self):
        """On retry success, result is cached under the original (first-call) cache key."""
        from aila.platform.llm import cache_key
        import json

        model = MagicMock()
        model.model_id = "test-model"
        bad_resp = MagicMock()
        bad_resp.content = "BAD"
        good_resp = MagicMock()
        good_resp.content = '{"value":"retried"}'
        model.chat_sync.side_effect = [bad_resp, good_resp]

        agent = _make_agent(model)
        agent.run_structured("task X", response_model=_Out)

        schema_json = json.dumps(_Out.model_json_schema(), separators=(",", ":"))
        # Reconstruct the original prompt (no additional_args) to verify cache key
        prompt = (
            "task X\n"
            "Return only valid JSON. Do not wrap it in markdown.\n"
            "The JSON must validate against this schema:\n"
            f"{schema_json}"
        )
        key = cache_key(prompt, "test-model", schema_json)
        assert agent._output_cache.get(key) is not None
        assert agent._output_cache.get(key).value == "retried"
