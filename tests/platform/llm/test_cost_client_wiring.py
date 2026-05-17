"""Tests for Phase 175 cost recording wiring in AilaLLMClient._call_with_retry.

Verifies that the 5-step durable cost recording block runs correctly:
  1. calculate_cost_usd called with correct args
  2. LLM_COST_TOTAL Prometheus counter incremented
  3. LlmCallCompleted domain event emitted via bus
  4. Steps are independent (failure in one does not block others)
  5. Cost recording failure does NOT prevent LLM response from being returned
  6. team_id threaded through all public methods and _call_with_retry
  7. Duration captured via perf_counter and passed to LlmCallCompleted
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _AsyncRegistry:
    """Async ConfigRegistry stub -- returns None for all keys."""

    async def get(self, namespace: str, key: str) -> Any:
        return None

    async def is_disabled(self) -> bool:
        return False


def _make_canned_completion(
    content: str = "test response",
    prompt_tokens: int = 10,
    completion_tokens: int = 5,
) -> MagicMock:
    """Build a minimal OpenAI completion mock."""
    usage_mock = MagicMock()
    usage_mock.prompt_tokens = prompt_tokens
    usage_mock.completion_tokens = completion_tokens
    usage_mock.total_tokens = prompt_tokens + completion_tokens

    message = MagicMock()
    message.content = content
    message.tool_calls = []

    choice = MagicMock()
    choice.message = message
    choice.finish_reason = "stop"

    completion = MagicMock()
    completion.choices = [choice]
    completion.usage = usage_mock
    return completion


def _make_client(registry: Any = None) -> Any:
    """Create an AilaLLMClient with async-capable registry stub."""
    from aila.platform.llm.client import AilaLLMClient

    reg = registry or _AsyncRegistry()
    secret_store = MagicMock()
    secret_store.resolve_provider_secret = AsyncMock(return_value="sk-test-key")

    client = AilaLLMClient(registry=reg, secret_store=secret_store)  # type: ignore[arg-type]
    return client


def _patch_config(client: Any) -> None:
    """Patch LLMConfigProvider to avoid real registry calls."""
    from aila.platform.llm.config import LLMRouting

    routing = LLMRouting(
        model_id="gpt-4o",
        base_url="https://test.example.com",
        api_key="sk-test",
        max_tokens=1000,
        temperature=0.0,
        max_tool_steps=0,
        task_type="scoring",
    )
    client._config.is_disabled = AsyncMock(return_value=False)
    client._config.resolve_routing = AsyncMock(return_value=routing)


# ---------------------------------------------------------------------------
# Test: persist_cost_record called with correct args
# ---------------------------------------------------------------------------


class TestPersistCostRecordWiring:
    """persist_cost_record is called after successful LLM call."""

    @pytest.mark.asyncio
    async def test_persist_called_with_correct_args(self) -> None:
        """After chat(), persist_cost_record is called with model_id, run_id, task_type."""
        client = _make_client()
        _patch_config(client)
        completion = _make_canned_completion(prompt_tokens=100, completion_tokens=50)

        persist_mock = AsyncMock()
        calc_mock = AsyncMock(return_value=(0.0125, True))

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.persist_cost_record", persist_mock):
                with patch("aila.platform.llm.cost.calculate_cost_usd", calc_mock):
                    await client.chat(
                        "scoring",
                        [{"role": "user", "content": "test"}],
                        run_id="run-42",
                        team_id="team-1",
                    )

        persist_mock.assert_awaited_once()
        kwargs = persist_mock.call_args.kwargs
        assert kwargs["run_id"] == "run-42"
        assert kwargs["model_id"] == "gpt-4o"
        assert kwargs["task_type"] == "scoring"
        assert kwargs["team_id"] == "team-1"
        assert kwargs["prompt_tokens"] == 100
        assert kwargs["completion_tokens"] == 50
        assert abs(kwargs["cost_usd"] - 0.0125) < 1e-9

    @pytest.mark.asyncio
    async def test_team_id_flows_through_chat_to_persist(self) -> None:
        """team_id passed to chat() reaches persist_cost_record."""
        client = _make_client()
        _patch_config(client)
        completion = _make_canned_completion()

        persist_mock = AsyncMock()

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.persist_cost_record", persist_mock):
                with patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(return_value=(0.0, False))):
                    with patch("aila.platform.llm.cost.emit_missing_pricing_notification", AsyncMock()):
                        await client.chat(
                            "scoring",
                            [{"role": "user", "content": "test"}],
                            team_id="team-xyz",
                        )

        assert persist_mock.call_args.kwargs["team_id"] == "team-xyz"


# ---------------------------------------------------------------------------
# Test: Prometheus counter incremented
# ---------------------------------------------------------------------------


class TestPrometheusCounterWiring:
    """LLM_COST_TOTAL counter is incremented after successful call."""

    @pytest.mark.asyncio
    async def test_llm_cost_total_incremented(self) -> None:
        """LLM_COST_TOTAL.labels(model=...).inc(cost) is called."""
        client = _make_client()
        _patch_config(client)
        completion = _make_canned_completion()

        mock_counter_labels = MagicMock()
        mock_counter = MagicMock()
        mock_counter.labels = MagicMock(return_value=mock_counter_labels)

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.persist_cost_record", AsyncMock()):
                with patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(return_value=(0.0055, True))):
                    with patch("aila.api.metrics.LLM_COST_TOTAL", mock_counter):
                        await client.chat("scoring", [{"role": "user", "content": "test"}])

        mock_counter.labels.assert_called_with(model="gpt-4o")
        mock_counter_labels.inc.assert_called_once_with(0.0055)


# ---------------------------------------------------------------------------
# Test: LlmCallCompleted domain event emitted
# ---------------------------------------------------------------------------


class TestDomainEventWiring:
    """LlmCallCompleted event is published to bus after successful call."""

    @pytest.mark.asyncio
    async def test_llm_call_completed_published(self) -> None:
        """LlmCallCompleted is published to bus with cost and token data."""
        from aila.platform.events.domain_events import LlmCallCompleted

        client = _make_client()
        _patch_config(client)
        completion = _make_canned_completion(prompt_tokens=20, completion_tokens=10)

        mock_bus = MagicMock()
        client.bus = mock_bus

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.persist_cost_record", AsyncMock()):
                with patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(return_value=(0.003, True))):
                    await client.chat(
                        "scoring",
                        [{"role": "user", "content": "test"}],
                        team_id="team-abc",
                    )

        mock_bus.publish.assert_called_once()
        event = mock_bus.publish.call_args[0][0]
        assert isinstance(event, LlmCallCompleted)
        assert event.payload.model == "gpt-4o"
        assert event.payload.tokens == 30  # 20 + 10
        assert abs(event.payload.cost - 0.003) < 1e-9
        assert event.payload.duration > 0.0
        assert event.team_id == "team-abc"

    @pytest.mark.asyncio
    async def test_no_bus_no_publish(self) -> None:
        """When bus is None (default), no event publishing is attempted."""
        client = _make_client()
        _patch_config(client)
        completion = _make_canned_completion()
        assert client.bus is None

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.persist_cost_record", AsyncMock()):
                with patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(return_value=(0.0, True))):
                    # Should not raise even without a bus
                    response = await client.chat("scoring", [{"role": "user", "content": "test"}])

        assert response.content == "test response"


# ---------------------------------------------------------------------------
# Test: Independent steps (failure in one does not block others)
# ---------------------------------------------------------------------------


class TestIndependentStepExecution:
    """Each step is isolated; failure in one step does not prevent subsequent steps."""

    @pytest.mark.asyncio
    async def test_calculate_cost_failure_still_persists(self) -> None:
        """When calculate_cost_usd raises, persist_cost_record still runs with cost_usd=0.0."""
        client = _make_client()
        _patch_config(client)
        completion = _make_canned_completion()

        persist_mock = AsyncMock()

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.persist_cost_record", persist_mock):
                with patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(side_effect=RuntimeError("calc boom"))):
                    with patch("aila.platform.llm.cost.emit_missing_pricing_notification", AsyncMock()):
                        response = await client.chat("scoring", [{"role": "user", "content": "test"}])

        # Response still returned
        assert response.content == "test response"
        # persist still ran with fallback cost_usd=0.0
        persist_mock.assert_awaited_once()
        assert persist_mock.call_args.kwargs["cost_usd"] == 0.0

    @pytest.mark.asyncio
    async def test_persist_failure_still_increments_prometheus(self) -> None:
        """When persist_cost_record raises, Prometheus counter still fires."""
        client = _make_client()
        _patch_config(client)
        completion = _make_canned_completion()

        mock_counter_labels = MagicMock()
        mock_counter = MagicMock()
        mock_counter.labels = MagicMock(return_value=mock_counter_labels)

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.persist_cost_record", AsyncMock(side_effect=RuntimeError("db boom"))):
                with patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(return_value=(0.002, True))):
                    with patch("aila.api.metrics.LLM_COST_TOTAL", mock_counter):
                        response = await client.chat("scoring", [{"role": "user", "content": "test"}])

        # Response still returned
        assert response.content == "test response"
        # Prometheus still fired
        mock_counter_labels.inc.assert_called_once()

    @pytest.mark.asyncio
    async def test_cost_recording_failure_does_not_block_response(self) -> None:
        """All 5 steps failing still returns the LLM response correctly."""
        client = _make_client()
        _patch_config(client)
        completion = _make_canned_completion(content="important response")

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(side_effect=RuntimeError("calc dead"))):
                with patch("aila.platform.llm.cost.persist_cost_record", AsyncMock(side_effect=RuntimeError("db dead"))):
                    with patch("aila.platform.llm.cost.emit_missing_pricing_notification", AsyncMock(side_effect=RuntimeError("notif dead"))):
                        with patch("aila.api.metrics.LLM_COST_TOTAL", side_effect=RuntimeError("metrics dead")):
                            response = await client.chat("scoring", [{"role": "user", "content": "test"}])

        assert response.content == "important response"

    @pytest.mark.asyncio
    async def test_missing_pricing_notification_called_when_unconfigured(self) -> None:
        """When pricing is not configured, emit_missing_pricing_notification is called."""
        client = _make_client()
        _patch_config(client)
        completion = _make_canned_completion()

        notify_mock = AsyncMock()

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.persist_cost_record", AsyncMock()):
                with patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(return_value=(0.0, False))):
                    with patch("aila.platform.llm.cost.emit_missing_pricing_notification", notify_mock):
                        await client.chat("scoring", [{"role": "user", "content": "test"}])

        notify_mock.assert_awaited_once_with("gpt-4o")

    @pytest.mark.asyncio
    async def test_missing_pricing_notification_NOT_called_when_configured(self) -> None:
        """When pricing IS configured, emit_missing_pricing_notification is NOT called."""
        client = _make_client()
        _patch_config(client)
        completion = _make_canned_completion()

        notify_mock = AsyncMock()

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.persist_cost_record", AsyncMock()):
                with patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(return_value=(0.005, True))):
                    with patch("aila.platform.llm.cost.emit_missing_pricing_notification", notify_mock):
                        await client.chat("scoring", [{"role": "user", "content": "test"}])

        notify_mock.assert_not_awaited()


# ---------------------------------------------------------------------------
# Test: Duration captured from perf_counter
# ---------------------------------------------------------------------------


class TestDurationCapture:
    """_call_duration is measured via perf_counter and passed to LlmCallCompleted."""

    @pytest.mark.asyncio
    async def test_duration_passed_to_event(self) -> None:
        """LlmCallCompleted.payload.duration is a positive float from perf_counter."""
        from aila.platform.events.domain_events import LlmCallCompleted

        client = _make_client()
        _patch_config(client)
        completion = _make_canned_completion()
        mock_bus = MagicMock()
        client.bus = mock_bus

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.persist_cost_record", AsyncMock()):
                with patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(return_value=(0.0, True))):
                    await client.chat("scoring", [{"role": "user", "content": "test"}])

        event = mock_bus.publish.call_args[0][0]
        assert isinstance(event, LlmCallCompleted)
        # duration must be a non-negative float
        assert isinstance(event.payload.duration, float)
        assert event.payload.duration >= 0.0


# ---------------------------------------------------------------------------
# Test: team_id threading
# ---------------------------------------------------------------------------


class TestTeamIdThreading:
    """team_id is threaded through all public chat methods."""

    @pytest.mark.asyncio
    async def test_chat_accepts_team_id(self) -> None:
        """chat() accepts team_id keyword argument."""
        client = _make_client()
        _patch_config(client)
        completion = _make_canned_completion()

        persist_mock = AsyncMock()

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.persist_cost_record", persist_mock):
                with patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(return_value=(0.0, False))):
                    with patch("aila.platform.llm.cost.emit_missing_pricing_notification", AsyncMock()):
                        await client.chat(
                            "scoring",
                            [{"role": "user", "content": "test"}],
                            team_id="team-test",
                        )

        assert persist_mock.call_args.kwargs["team_id"] == "team-test"

    @pytest.mark.asyncio
    async def test_chat_json_accepts_team_id(self) -> None:
        """chat_json() accepts team_id keyword argument."""
        import json
        client = _make_client()
        _patch_config(client)
        completion = _make_canned_completion(content=json.dumps({"score": 5.0}))

        persist_mock = AsyncMock()

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.persist_cost_record", persist_mock):
                with patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(return_value=(0.0, False))):
                    with patch("aila.platform.llm.cost.emit_missing_pricing_notification", AsyncMock()):
                        await client.chat_json(
                            "scoring",
                            [{"role": "user", "content": "test"}],
                            {"type": "object", "properties": {"score": {"type": "number"}}},
                            team_id="team-json",
                        )

        assert persist_mock.call_args.kwargs["team_id"] == "team-json"

    @pytest.mark.asyncio
    async def test_chat_structured_accepts_team_id(self) -> None:
        """chat_structured() accepts team_id keyword argument."""
        import json

        from pydantic import BaseModel as PydanticBaseModel

        class ScoreModel(PydanticBaseModel):
            score: float

        client = _make_client()
        _patch_config(client)
        completion = _make_canned_completion(content=json.dumps({"score": 7.5}))

        persist_mock = AsyncMock()

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.persist_cost_record", persist_mock):
                with patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(return_value=(0.0, False))):
                    with patch("aila.platform.llm.cost.emit_missing_pricing_notification", AsyncMock()):
                        await client.chat_structured(
                            "scoring",
                            [{"role": "user", "content": "test"}],
                            ScoreModel,
                            team_id="team-structured",
                        )

        assert persist_mock.call_args.kwargs["team_id"] == "team-structured"
