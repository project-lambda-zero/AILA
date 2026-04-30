"""Unit tests for aila.platform.llm.gate.

Tests the confidence gating pipeline step: extract_confidence pure function,
_map_confidence_level helper, make_gate_step factory with threshold routing
(HIGH/MEDIUM/LOW/REJECT), consensus retry logic with majority vote,
ConfidenceRejectedError propagation, configurable thresholds, and audit
event emission.

Covers: CONF-01, CONF-02, CONF-03, CONF-04.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from dataclasses import replace

import pytest

from aila.platform.llm.client import LLMResponse
from aila.platform.llm.config import LLMRouting
from aila.platform.llm.errors import ConfidenceRejectedError
from aila.platform.events.event import PlatformEvent


# ---------------------------------------------------------------------------
# Fakes (same patterns as test_validate.py / test_classify.py)
# ---------------------------------------------------------------------------


class FakeEmitter:
    """Captures emitted PlatformEvents for assertion."""

    def __init__(self) -> None:
        self.events: list[PlatformEvent] = []

    def emit(self, event: PlatformEvent) -> None:
        self.events.append(event)


class FakeConfigRegistry:
    """Minimal ConfigRegistry fake for threshold reads."""

    def __init__(self, overrides: dict[str, Any] | None = None) -> None:
        self._data = overrides or {}

    def get(self, namespace: str, key: str) -> Any:
        return self._data.get(key)


class FakeConfigProvider:
    """Wraps FakeConfigRegistry as _registry attribute (mimics LLMConfigProvider)."""

    def __init__(self, overrides: dict[str, Any] | None = None) -> None:
        self._registry = FakeConfigRegistry(overrides)

    def is_step_enabled(self, step: str, task_type: str) -> bool:
        return True

    def resolve_fail_mode(self, step: str, task_type: str) -> str:
        return "open"


class FakeCallFn:
    """Async callable returning a sequence of LLMResponses for consensus tests."""

    def __init__(self, responses: list[LLMResponse]) -> None:
        self._responses = list(responses)
        self._calls: list[dict[str, Any]] = []
        self._index = 0

    async def __call__(
        self,
        *,
        client: Any,
        routing: Any,
        messages: Any,
        response_format: Any = None,
        tools: Any = None,
        tool_executor: Any = None,
    ) -> LLMResponse:
        self._calls.append({"routing": routing, "messages": messages})
        resp = self._responses[self._index % len(self._responses)]
        self._index += 1
        return resp


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def routing() -> LLMRouting:
    return LLMRouting(
        model_id="test-model",
        base_url="http://test",
        api_key="sk-test",
        max_tokens=100,
        temperature=0.0,
        max_tool_steps=0,
        task_type="scoring",
    )


@pytest.fixture()
def default_config() -> FakeConfigProvider:
    """Default thresholds: high=0.8, medium=0.5, reject=0.2."""
    return FakeConfigProvider()


# ---------------------------------------------------------------------------
# CONF-01: extract_confidence tests
# ---------------------------------------------------------------------------


class TestExtractConfidence:
    """Pure function: extract confidence score from response content."""

    def test_json_with_confidence_score(self) -> None:
        from aila.platform.llm.gate import extract_confidence

        content = json.dumps({"confidence_score": 0.95, "answer": "yes"})
        assert extract_confidence(content, "stop") == 0.95

    def test_json_score_zero(self) -> None:
        from aila.platform.llm.gate import extract_confidence

        content = json.dumps({"confidence_score": 0.0})
        assert extract_confidence(content, "stop") == 0.0

    def test_json_score_one(self) -> None:
        from aila.platform.llm.gate import extract_confidence

        content = json.dumps({"confidence_score": 1.0})
        assert extract_confidence(content, "stop") == 1.0

    def test_json_score_out_of_range_falls_to_heuristic(self) -> None:
        from aila.platform.llm.gate import extract_confidence

        content = json.dumps({"confidence_score": 1.5})
        # Out of [0, 1], falls to heuristic: content > 50 chars + stop -> 0.7
        score = extract_confidence(content, "stop")
        assert score != 1.5  # not the out-of-range value

    def test_json_score_not_a_number_falls_to_heuristic(self) -> None:
        from aila.platform.llm.gate import extract_confidence

        content = json.dumps({"confidence_score": "not_a_number"})
        score = extract_confidence(content, "stop")
        # Falls to heuristic since "not_a_number" is not a number
        assert isinstance(score, float)

    def test_json_without_confidence_field_falls_to_heuristic(self) -> None:
        from aila.platform.llm.gate import extract_confidence

        content = json.dumps({"answer": "yes", "reasoning": "because reasons"})
        score = extract_confidence(content, "stop")
        # No confidence_score key => heuristic
        assert isinstance(score, float)

    def test_plain_text_long_stop_returns_0_7(self) -> None:
        from aila.platform.llm.gate import extract_confidence

        content = "This is a normal response with enough text to exceed fifty characters threshold."
        assert extract_confidence(content, "stop") == 0.7

    def test_finish_reason_length_returns_0_4(self) -> None:
        from aila.platform.llm.gate import extract_confidence

        content = "Some content that was truncated"
        assert extract_confidence(content, "length") == 0.4

    def test_empty_content_returns_0_1(self) -> None:
        from aila.platform.llm.gate import extract_confidence

        assert extract_confidence("", "stop") == 0.1

    def test_short_content_stop_returns_0_1(self) -> None:
        from aila.platform.llm.gate import extract_confidence

        assert extract_confidence("short", "stop") == 0.1


# ---------------------------------------------------------------------------
# CONF-01: _map_confidence_level tests
# ---------------------------------------------------------------------------


class TestConfidenceLevel:
    """Mapping from numeric score to HIGH/MEDIUM/LOW/REJECT."""

    def test_high(self) -> None:
        from aila.platform.llm.gate import _map_confidence_level

        assert _map_confidence_level(0.9, 0.8, 0.5, 0.2) == "HIGH"

    def test_high_boundary(self) -> None:
        from aila.platform.llm.gate import _map_confidence_level

        assert _map_confidence_level(0.8, 0.8, 0.5, 0.2) == "HIGH"

    def test_medium(self) -> None:
        from aila.platform.llm.gate import _map_confidence_level

        assert _map_confidence_level(0.6, 0.8, 0.5, 0.2) == "MEDIUM"

    def test_medium_boundary(self) -> None:
        from aila.platform.llm.gate import _map_confidence_level

        assert _map_confidence_level(0.5, 0.8, 0.5, 0.2) == "MEDIUM"

    def test_low(self) -> None:
        from aila.platform.llm.gate import _map_confidence_level

        assert _map_confidence_level(0.3, 0.8, 0.5, 0.2) == "LOW"

    def test_low_boundary(self) -> None:
        from aila.platform.llm.gate import _map_confidence_level

        assert _map_confidence_level(0.2, 0.8, 0.5, 0.2) == "LOW"

    def test_reject(self) -> None:
        from aila.platform.llm.gate import _map_confidence_level

        assert _map_confidence_level(0.1, 0.8, 0.5, 0.2) == "REJECT"

    def test_reject_zero(self) -> None:
        from aila.platform.llm.gate import _map_confidence_level

        assert _map_confidence_level(0.0, 0.8, 0.5, 0.2) == "REJECT"


# ---------------------------------------------------------------------------
# CONF-02: Gate routing tests -- HIGH
# ---------------------------------------------------------------------------


class TestGateRoutingHigh:
    """HIGH confidence: auto-accept, response passes through unchanged."""

    @pytest.mark.asyncio
    async def test_high_auto_accept(self, routing: LLMRouting, default_config: FakeConfigProvider) -> None:
        from aila.platform.llm.gate import make_gate_step

        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.95, "answer": "yes"}),
            model="test-model",
            finish_reason="stop",
        )
        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}

        call_fn = FakeCallFn([])
        step = make_gate_step(default_config, call_fn, emitter=None)
        await step(ctx, [], routing)

        assert ctx["confidence"] == "HIGH"
        assert ctx["response"] is response  # not replaced

    @pytest.mark.asyncio
    async def test_high_no_flagged(self, routing: LLMRouting, default_config: FakeConfigProvider) -> None:
        from aila.platform.llm.gate import make_gate_step

        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.85}),
            model="test-model",
            finish_reason="stop",
        )
        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}

        call_fn = FakeCallFn([])
        step = make_gate_step(default_config, call_fn, emitter=None)
        await step(ctx, [], routing)

        assert ctx.get("confidence_flagged") is None


# ---------------------------------------------------------------------------
# CONF-02: Gate routing tests -- MEDIUM
# ---------------------------------------------------------------------------


class TestGateRoutingMedium:
    """MEDIUM confidence: flagged, response passes through."""

    @pytest.mark.asyncio
    async def test_medium_flagged(self, routing: LLMRouting, default_config: FakeConfigProvider) -> None:
        from aila.platform.llm.gate import make_gate_step

        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.6}),
            model="test-model",
            finish_reason="stop",
        )
        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}

        call_fn = FakeCallFn([])
        step = make_gate_step(default_config, call_fn, emitter=None)
        await step(ctx, [], routing)

        assert ctx["confidence"] == "MEDIUM"
        assert ctx["confidence_flagged"] is True
        assert ctx["response"] is response  # not replaced


# ---------------------------------------------------------------------------
# CONF-02: Gate routing tests -- LOW (triggers consensus)
# ---------------------------------------------------------------------------


class TestGateRoutingLow:
    """LOW confidence: triggers consensus retry round."""

    @pytest.mark.asyncio
    async def test_low_triggers_consensus(self, routing: LLMRouting) -> None:
        from aila.platform.llm.gate import make_gate_step

        # Original response: LOW confidence (0.3)
        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.3}),
            model="test-model",
            finish_reason="stop",
        )
        # Consensus retries all return LOW too -- majority vote fails
        retry_response = LLMResponse(
            content=json.dumps({"confidence_score": 0.3}),
            model="test-model",
            finish_reason="stop",
        )
        config = FakeConfigProvider({
            "llm_pipeline_gate_consensus_retries_scoring": 2,
        })
        call_fn = FakeCallFn([retry_response, retry_response])

        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}
        step = make_gate_step(config, call_fn, emitter=None)
        await step(ctx, [], routing)

        # Consensus attempted but did not improve
        assert ctx.get("consensus_attempted") is True
        assert len(call_fn._calls) == 2  # 2 retries


# ---------------------------------------------------------------------------
# CONF-02: Gate routing tests -- REJECT
# ---------------------------------------------------------------------------


class TestGateRoutingReject:
    """REJECT confidence: raises ConfidenceRejectedError."""

    @pytest.mark.asyncio
    async def test_reject_raises(self, routing: LLMRouting, default_config: FakeConfigProvider) -> None:
        from aila.platform.llm.gate import make_gate_step

        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.1}),
            model="test-model",
            finish_reason="stop",
        )
        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}

        call_fn = FakeCallFn([])
        step = make_gate_step(default_config, call_fn, emitter=None)

        with pytest.raises(ConfidenceRejectedError, match="below threshold"):
            await step(ctx, [], routing)


# ---------------------------------------------------------------------------
# CONF-02: ConfidenceRejectedError propagation through pipeline
# ---------------------------------------------------------------------------


class TestRejectPropagation:
    """ConfidenceRejectedError bypasses pipeline fail-open mode."""

    @pytest.mark.asyncio
    async def test_reject_propagates_in_fail_open(self, routing: LLMRouting) -> None:
        from aila.platform.llm.pipeline import PipelineRunner
        from aila.platform.llm.gate import make_gate_step

        # Config with fail-open for gate step
        config = FakeConfigProvider()
        runner = PipelineRunner(config_provider=config)

        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.05}),
            model="test-model",
            finish_reason="stop",
        )
        call_fn = FakeCallFn([])

        gate_step = make_gate_step(config, call_fn, emitter=None)
        runner.register("gate", gate_step)

        async def fake_api_call(**kwargs: Any) -> LLMResponse:
            return response

        with pytest.raises(ConfidenceRejectedError):
            await runner.run(
                task_type="scoring",
                messages=[],
                routing=routing,
                call_fn=fake_api_call,
                call_kwargs={},
            )


# ---------------------------------------------------------------------------
# CONF-03: Threshold configuration
# ---------------------------------------------------------------------------


class TestThresholdConfig:
    """Custom thresholds from ConfigRegistry override defaults."""

    @pytest.mark.asyncio
    async def test_custom_thresholds(self, routing: LLMRouting) -> None:
        from aila.platform.llm.gate import make_gate_step

        # Custom thresholds: high=0.9, medium=0.7, reject=0.4
        config = FakeConfigProvider({
            "llm_pipeline_gate_high_threshold_scoring": 0.9,
            "llm_pipeline_gate_medium_threshold_scoring": 0.7,
            "llm_pipeline_gate_reject_threshold_scoring": 0.4,
        })

        # Score 0.85: with defaults would be HIGH, with custom should be MEDIUM
        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.85}),
            model="test-model",
            finish_reason="stop",
        )
        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}

        call_fn = FakeCallFn([])
        step = make_gate_step(config, call_fn, emitter=None)
        await step(ctx, [], routing)

        assert ctx["confidence"] == "MEDIUM"

    @pytest.mark.asyncio
    async def test_default_thresholds_when_missing(self, routing: LLMRouting, default_config: FakeConfigProvider) -> None:
        from aila.platform.llm.gate import make_gate_step

        # Score 0.85: with defaults (0.8/0.5/0.2) should be HIGH
        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.85}),
            model="test-model",
            finish_reason="stop",
        )
        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}

        call_fn = FakeCallFn([])
        step = make_gate_step(default_config, call_fn, emitter=None)
        await step(ctx, [], routing)

        assert ctx["confidence"] == "HIGH"


# ---------------------------------------------------------------------------
# CONF-04: Consensus -- same_model_high_temp
# ---------------------------------------------------------------------------


class TestConsensusSameModel:
    """same_model_high_temp strategy: re-call with temperature=1.0."""

    @pytest.mark.asyncio
    async def test_same_model_uses_high_temp(self, routing: LLMRouting) -> None:
        from aila.platform.llm.gate import make_gate_step

        # Original: LOW (0.3)
        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.3}),
            model="test-model",
            finish_reason="stop",
        )
        # Retry responses: all LOW
        retry = LLMResponse(
            content=json.dumps({"confidence_score": 0.3}),
            model="test-model",
            finish_reason="stop",
        )
        config = FakeConfigProvider({
            "llm_pipeline_gate_consensus_retries_scoring": 1,
        })
        call_fn = FakeCallFn([retry])

        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}
        step = make_gate_step(config, call_fn, emitter=None)
        await step(ctx, [], routing)

        # Verify the call used temperature=1.0
        assert len(call_fn._calls) == 1
        call_routing = call_fn._calls[0]["routing"]
        assert call_routing.temperature == 1.0
        assert call_routing.model_id == "test-model"  # same model


# ---------------------------------------------------------------------------
# CONF-04: Consensus -- cross_model
# ---------------------------------------------------------------------------


class TestConsensusCrossModel:
    """cross_model strategy: call different model_id from config."""

    @pytest.mark.asyncio
    async def test_cross_model_uses_different_model(self, routing: LLMRouting) -> None:
        from aila.platform.llm.gate import make_gate_step

        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.3}),
            model="test-model",
            finish_reason="stop",
        )
        retry = LLMResponse(
            content=json.dumps({"confidence_score": 0.3}),
            model="other-model",
            finish_reason="stop",
        )
        config = FakeConfigProvider({
            "llm_pipeline_gate_consensus_strategy_scoring": "cross_model",
            "llm_pipeline_gate_consensus_model_scoring": "other-model",
            "llm_pipeline_gate_consensus_retries_scoring": 1,
        })
        call_fn = FakeCallFn([retry])

        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}
        step = make_gate_step(config, call_fn, emitter=None)
        await step(ctx, [], routing)

        assert len(call_fn._calls) == 1
        call_routing = call_fn._calls[0]["routing"]
        assert call_routing.model_id == "other-model"


# ---------------------------------------------------------------------------
# CONF-04: Majority vote
# ---------------------------------------------------------------------------


class TestMajorityVote:
    """Majority vote calculation: >50% of (original + retries) >= medium."""

    @pytest.mark.asyncio
    async def test_majority_passing_replaces_response(self, routing: LLMRouting) -> None:
        from aila.platform.llm.gate import make_gate_step

        # Original: LOW (0.3). 3 retries: 0.6, 0.7, 0.35
        # Total votes: 4. Passing (>= 0.5): 0.6, 0.7 = 2. Not passing: 0.3, 0.35 = 2.
        # 2 > 4/2 = 2 -> NOT majority (need strictly > 50%)
        # So try: 0.6, 0.7, 0.55 -> passing = 3/4 > 2 -> majority passes
        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.3}),
            model="test-model",
            finish_reason="stop",
        )
        r1 = LLMResponse(
            content=json.dumps({"confidence_score": 0.6}),
            model="test-model",
            finish_reason="stop",
        )
        r2 = LLMResponse(
            content=json.dumps({"confidence_score": 0.7}),
            model="test-model",
            finish_reason="stop",
        )
        r3 = LLMResponse(
            content=json.dumps({"confidence_score": 0.55}),
            model="test-model",
            finish_reason="stop",
        )
        config = FakeConfigProvider({
            "llm_pipeline_gate_consensus_retries_scoring": 3,
        })
        call_fn = FakeCallFn([r1, r2, r3])

        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}
        step = make_gate_step(config, call_fn, emitter=None)
        await step(ctx, [], routing)

        # Majority passed, highest confidence (0.7) should win
        assert ctx["response"] is not response  # replaced
        assert ctx.get("consensus_attempted") is True

    @pytest.mark.asyncio
    async def test_majority_failing_keeps_original(self, routing: LLMRouting) -> None:
        from aila.platform.llm.gate import make_gate_step

        # Original: LOW (0.3). 3 retries all LOW (0.3)
        # Total: 4. Passing: 0. -> no majority
        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.3}),
            model="test-model",
            finish_reason="stop",
        )
        retry = LLMResponse(
            content=json.dumps({"confidence_score": 0.3}),
            model="test-model",
            finish_reason="stop",
        )
        config = FakeConfigProvider({
            "llm_pipeline_gate_consensus_retries_scoring": 3,
        })
        call_fn = FakeCallFn([retry, retry, retry])

        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}
        step = make_gate_step(config, call_fn, emitter=None)
        await step(ctx, [], routing)

        # No improvement -- original stays
        assert ctx["response"] is response
        assert ctx.get("consensus_attempted") is True


# ---------------------------------------------------------------------------
# CONF-04: Consensus winner replaces ctx["response"]
# ---------------------------------------------------------------------------


class TestConsensusResponseReplacement:
    """When consensus improves confidence, winner replaces ctx['response']."""

    @pytest.mark.asyncio
    async def test_winner_replaces_response(self, routing: LLMRouting) -> None:
        from aila.platform.llm.gate import make_gate_step

        # Original: LOW (0.3). 2 retries: 0.9 (HIGH), 0.85 (HIGH)
        # Total: 3. Passing: 2. > 3/2 = 1.5 -> majority
        # Highest: 0.9 -> that response wins
        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.3}),
            model="test-model",
            finish_reason="stop",
        )
        winner = LLMResponse(
            content=json.dumps({"confidence_score": 0.9, "answer": "winner"}),
            model="test-model",
            finish_reason="stop",
        )
        other = LLMResponse(
            content=json.dumps({"confidence_score": 0.85}),
            model="test-model",
            finish_reason="stop",
        )
        config = FakeConfigProvider({
            "llm_pipeline_gate_consensus_retries_scoring": 2,
        })
        call_fn = FakeCallFn([winner, other])

        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}
        step = make_gate_step(config, call_fn, emitter=None)
        await step(ctx, [], routing)

        assert ctx["response"] is winner
        assert ctx.get("consensus_winner_score") == 0.9

    @pytest.mark.asyncio
    async def test_consensus_retry_count_from_config(self, routing: LLMRouting) -> None:
        from aila.platform.llm.gate import make_gate_step

        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.3}),
            model="test-model",
            finish_reason="stop",
        )
        retry = LLMResponse(
            content=json.dumps({"confidence_score": 0.3}),
            model="test-model",
            finish_reason="stop",
        )
        config = FakeConfigProvider({
            "llm_pipeline_gate_consensus_retries_scoring": 5,
        })
        call_fn = FakeCallFn([retry] * 5)

        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}
        step = make_gate_step(config, call_fn, emitter=None)
        await step(ctx, [], routing)

        assert len(call_fn._calls) == 5


# ---------------------------------------------------------------------------
# Audit event emission (D-17, D-18)
# ---------------------------------------------------------------------------


class TestAuditEvent:
    """llm_confidence_gating event emitted with correct fields."""

    @pytest.mark.asyncio
    async def test_event_emitted_on_high(self, routing: LLMRouting, default_config: FakeConfigProvider) -> None:
        from aila.platform.llm.gate import make_gate_step

        emitter = FakeEmitter()
        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.95}),
            model="test-model",
            finish_reason="stop",
        )
        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}

        call_fn = FakeCallFn([])
        step = make_gate_step(default_config, call_fn, emitter=emitter)
        await step(ctx, [], routing)

        assert len(emitter.events) == 1
        event = emitter.events[0]
        assert event.stage == "llm_confidence_gating"
        assert event.details["confidence_score"] == 0.95
        assert event.details["confidence_level"] == "HIGH"
        assert event.details["flagged"] is False
        assert event.details["consensus_attempted"] is False

    @pytest.mark.asyncio
    async def test_event_emitted_on_reject(self, routing: LLMRouting, default_config: FakeConfigProvider) -> None:
        from aila.platform.llm.gate import make_gate_step

        emitter = FakeEmitter()
        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.05}),
            model="test-model",
            finish_reason="stop",
        )
        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}

        call_fn = FakeCallFn([])
        step = make_gate_step(default_config, call_fn, emitter=emitter)

        with pytest.raises(ConfidenceRejectedError):
            await step(ctx, [], routing)

        # Audit event emitted before raising
        assert len(emitter.events) == 1
        event = emitter.events[0]
        assert event.details["confidence_level"] == "REJECT"

    @pytest.mark.asyncio
    async def test_event_fields_complete(self, routing: LLMRouting) -> None:
        from aila.platform.llm.gate import make_gate_step

        emitter = FakeEmitter()
        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.6}),
            model="test-model",
            finish_reason="stop",
        )
        config = FakeConfigProvider()
        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}

        call_fn = FakeCallFn([])
        step = make_gate_step(config, call_fn, emitter=emitter)
        await step(ctx, [], routing)

        event = emitter.events[0]
        details = event.details
        required_fields = [
            "task_type", "model_id", "confidence_score", "confidence_level",
            "flagged", "consensus_attempted", "consensus_retries",
            "consensus_strategy", "consensus_winner_score",
        ]
        for f in required_fields:
            assert f in details, f"Missing field: {f}"


# ---------------------------------------------------------------------------
# Edge case: no response in ctx
# ---------------------------------------------------------------------------


class TestGateGuard:
    """Gate step returns immediately when no response in ctx."""

    @pytest.mark.asyncio
    async def test_no_response_noop(self, routing: LLMRouting, default_config: FakeConfigProvider) -> None:
        from aila.platform.llm.gate import make_gate_step

        ctx: dict[str, Any] = {"task_type": "scoring"}
        call_fn = FakeCallFn([])
        step = make_gate_step(default_config, call_fn, emitter=None)
        await step(ctx, [], routing)

        assert "confidence" not in ctx


# ---------------------------------------------------------------------------
# Pipeline integration tests (Plan 02)
# ---------------------------------------------------------------------------


class FakeDisableableConfigProvider:
    """Config provider where gate step can be toggled on/off per task_type."""

    def __init__(
        self,
        overrides: dict[str, Any] | None = None,
        disabled_steps: dict[str, bool] | None = None,
    ) -> None:
        self._registry = FakeConfigRegistry(overrides)
        self._disabled_steps = disabled_steps or {}

    def is_step_enabled(self, step: str, task_type: str) -> bool:
        key = f"{step}_{task_type}"
        if key in self._disabled_steps:
            return not self._disabled_steps[key]
        return True

    def resolve_fail_mode(self, step: str, task_type: str) -> str:
        return "open"


class TestGatePipelineIntegration:
    """Integration tests: gate step running inside PipelineRunner.

    These tests exercise the gate step through the actual PipelineRunner,
    proving end-to-end behavior including the response re-read fix (D-15)
    and _enrich_response propagation.
    """

    @pytest.mark.asyncio
    async def test_high_confidence_passes_through_pipeline(self, routing: LLMRouting) -> None:
        """HIGH response passes through pipeline with confidence=HIGH in enriched LLMResponse."""
        from aila.platform.llm.pipeline import PipelineRunner
        from aila.platform.llm.gate import make_gate_step
        from aila.platform.llm.client import _enrich_response

        config = FakeConfigProvider()
        runner = PipelineRunner(config_provider=config)

        primary_response = LLMResponse(
            content=json.dumps({"result": "ok", "confidence_score": 0.95}),
            model="test-model",
            finish_reason="stop",
        )

        # Gate step's consensus call_fn (unused for HIGH)
        consensus_call_fn = FakeCallFn([])
        gate_step = make_gate_step(config, consensus_call_fn, emitter=None)
        runner.register("gate", gate_step)

        # Primary call_fn for pipeline.run()
        async def primary_call_fn(**kwargs: Any) -> LLMResponse:
            return primary_response

        response, ctx = await runner.run(
            task_type="scoring",
            messages=[{"role": "user", "content": "score this"}],
            routing=routing,
            call_fn=primary_call_fn,
            call_kwargs={},
        )

        # Pipeline returns the response
        assert response.content == primary_response.content
        assert ctx["confidence"] == "HIGH"

        # Enrich to verify confidence flows to LLMResponse
        enriched = _enrich_response(response, ctx)
        assert enriched.confidence == "HIGH"

    @pytest.mark.asyncio
    async def test_reject_propagates_through_pipeline(self, routing: LLMRouting) -> None:
        """REJECT response raises ConfidenceRejectedError through pipeline (NOT swallowed by fail-open)."""
        from aila.platform.llm.pipeline import PipelineRunner
        from aila.platform.llm.gate import make_gate_step

        config = FakeConfigProvider()
        runner = PipelineRunner(config_provider=config)

        # Empty content -> heuristic score 0.1 -> REJECT with default thresholds (reject=0.2)
        primary_response = LLMResponse(
            content="",
            model="test-model",
            finish_reason="stop",
        )

        consensus_call_fn = FakeCallFn([])
        gate_step = make_gate_step(config, consensus_call_fn, emitter=None)
        runner.register("gate", gate_step)

        async def primary_call_fn(**kwargs: Any) -> LLMResponse:
            return primary_response

        with pytest.raises(ConfidenceRejectedError, match="below threshold"):
            await runner.run(
                task_type="scoring",
                messages=[],
                routing=routing,
                call_fn=primary_call_fn,
                call_kwargs={},
            )

    @pytest.mark.asyncio
    async def test_gate_response_replacement_flows_through(self, routing: LLMRouting) -> None:
        """Consensus replaces ctx['response'] and pipeline returns the new response (D-15 fix)."""
        from aila.platform.llm.pipeline import PipelineRunner
        from aila.platform.llm.gate import make_gate_step

        # Thresholds: reject=0.1, medium=0.6, high=0.9
        config = FakeConfigProvider({
            "llm_pipeline_gate_reject_threshold_scoring": 0.1,
            "llm_pipeline_gate_medium_threshold_scoring": 0.6,
            "llm_pipeline_gate_high_threshold_scoring": 0.9,
            "llm_pipeline_gate_consensus_retries_scoring": 2,
        })
        runner = PipelineRunner(config_provider=config)

        # Primary response: score 0.3 -> LOW (between reject=0.1 and medium=0.6)
        primary_response = LLMResponse(
            content=json.dumps({"text": "low quality", "confidence_score": 0.3}),
            model="test-model",
            finish_reason="stop",
        )

        # Consensus calls return HIGH quality responses
        consensus_winner = LLMResponse(
            content=json.dumps({"text": "high quality", "confidence_score": 0.8}),
            model="test-model",
            finish_reason="stop",
        )
        consensus_call_fn = FakeCallFn([consensus_winner, consensus_winner])

        gate_step = make_gate_step(config, consensus_call_fn, emitter=None)
        runner.register("gate", gate_step)

        async def primary_call_fn(**kwargs: Any) -> LLMResponse:
            return primary_response

        response, ctx = await runner.run(
            task_type="scoring",
            messages=[{"role": "user", "content": "score this"}],
            routing=routing,
            call_fn=primary_call_fn,
            call_kwargs={},
        )

        # Pipeline should return the consensus winner, NOT the original
        assert response is not primary_response
        assert response is consensus_winner
        assert "high quality" in response.content

    @pytest.mark.asyncio
    async def test_medium_flagged_enriches_response(self, routing: LLMRouting) -> None:
        """MEDIUM response is flagged correctly and enriched into LLMResponse."""
        from aila.platform.llm.pipeline import PipelineRunner
        from aila.platform.llm.gate import make_gate_step
        from aila.platform.llm.client import _enrich_response

        config = FakeConfigProvider()
        runner = PipelineRunner(config_provider=config)

        # Score 0.65 -> MEDIUM with default thresholds (medium=0.5, high=0.8)
        primary_response = LLMResponse(
            content=json.dumps({"result": "ok", "confidence_score": 0.65}),
            model="test-model",
            finish_reason="stop",
        )

        consensus_call_fn = FakeCallFn([])
        gate_step = make_gate_step(config, consensus_call_fn, emitter=None)
        runner.register("gate", gate_step)

        async def primary_call_fn(**kwargs: Any) -> LLMResponse:
            return primary_response

        response, ctx = await runner.run(
            task_type="scoring",
            messages=[],
            routing=routing,
            call_fn=primary_call_fn,
            call_kwargs={},
        )

        assert ctx["confidence"] == "MEDIUM"
        assert ctx["confidence_flagged"] is True

        # Enrich and verify
        enriched = _enrich_response(response, ctx)
        assert enriched.confidence == "MEDIUM"
        assert enriched.pipeline_metadata is not None
        assert enriched.pipeline_metadata["confidence_gating"]["flagged"] is True

    @pytest.mark.asyncio
    async def test_gate_disabled_via_config_skips(self, routing: LLMRouting) -> None:
        """Gate step disabled via config: step skipped, no confidence in ctx."""
        from aila.platform.llm.pipeline import PipelineRunner
        from aila.platform.llm.gate import make_gate_step

        config = FakeDisableableConfigProvider(
            disabled_steps={"gate_scoring": True},
        )
        runner = PipelineRunner(config_provider=config)

        # Low confidence content that would be REJECT if gate ran
        primary_response = LLMResponse(
            content="",
            model="test-model",
            finish_reason="stop",
        )

        consensus_call_fn = FakeCallFn([])
        gate_step = make_gate_step(config, consensus_call_fn, emitter=None)
        runner.register("gate", gate_step)

        async def primary_call_fn(**kwargs: Any) -> LLMResponse:
            return primary_response

        response, ctx = await runner.run(
            task_type="scoring",
            messages=[],
            routing=routing,
            call_fn=primary_call_fn,
            call_kwargs={},
        )

        # Gate was skipped -- no confidence key
        assert "confidence" not in ctx
        # Response passes through unchanged
        assert response.content == ""
