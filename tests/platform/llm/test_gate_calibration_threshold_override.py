"""Acceptance test for issue #104 (P1) -- the confidence gate must
consume the promoted calibration threshold that
``aila.api.routers.admin_eval.promote_calibration_proposal`` writes
under ``platform.calibration_threshold_{outcome_kind}`` (or, as the
key-shape alignment for callers that only carry a task_type, under
``platform.calibration_threshold_{task_type}``).

Before this wiring, the gate resolved ``reject`` only from the
``llm_pipeline_gate_reject_threshold_{task_type}`` key: the promote
route wrote a value nothing ever read. After the wiring the gate
takes the calibration key when present, preserves the pre-write
behavior when absent, and prefers a per-call ``outcome_kind`` (from
``ctx["outcome_kind"]``) over the task-type fallback.

The tests exercise :func:`aila.platform.llm.gate._resolve_thresholds`
directly (deterministic; no LLM plumbing) plus one end-to-end
:func:`aila.platform.llm.gate.make_gate_step` invocation that shows
the ``REJECT`` verdict switches on a score that was ``LOW`` under the
default reject floor once the calibration override is promoted.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from aila.platform.llm.client import LLMResponse
from aila.platform.llm.config import LLMRouting
from aila.platform.llm.errors import ConfidenceRejectedError
from aila.platform.llm.gate import _resolve_thresholds, make_gate_step


# --------------------------------------------------------------------- #
#  Fakes (mirror ``test_gate.py`` -- same registry / provider seams).   #
# --------------------------------------------------------------------- #


class _FakeConfigRegistry:
    """Minimal ConfigRegistry stand-in.

    ``get`` is async to match the real ConfigRegistry -- both the
    gate's ``_resolve_thresholds`` and ``_resolve_consensus_config``
    await it.
    """

    def __init__(self, overrides: dict[str, Any] | None = None) -> None:
        self._data = dict(overrides or {})

    async def get(self, namespace: str, key: str) -> Any:
        del namespace
        return self._data.get(key)


class _FakeConfigProvider:
    """Wraps :class:`_FakeConfigRegistry` as ``_registry`` attribute."""

    def __init__(self, overrides: dict[str, Any] | None = None) -> None:
        self._registry = _FakeConfigRegistry(overrides)

    async def is_step_enabled(self, step: str, task_type: str) -> bool:
        del step, task_type
        return True

    async def resolve_fail_mode(self, step: str, task_type: str) -> str:
        del step, task_type
        return "open"


class _FakeCallFn:
    """Async call-fn stub -- the acceptance tests never trigger consensus."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(
        self,
        *,
        routing: Any,
        messages: Any,
        response_format: Any = None,
        tools: Any = None,
        tool_executor: Any = None,
        run_id: Any = None,
        team_id: Any = None,
    ) -> LLMResponse:
        self.calls.append(
            {"routing": routing, "run_id": run_id, "team_id": team_id},
        )
        raise AssertionError(
            "consensus path unexpectedly triggered in calibration-override "
            "acceptance test; the fixtures should keep scores in HIGH or "
            "REJECT bands only",
        )


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


# --------------------------------------------------------------------- #
#  _resolve_thresholds -- direct unit tests                             #
# --------------------------------------------------------------------- #


class TestResolveThresholdsCalibrationOverride:
    """The calibration key is read as an override of the reject floor."""

    @pytest.mark.asyncio
    async def test_absent_key_preserves_defaults(self) -> None:
        """When neither key is set the gate must be byte-identical to
        the pre-wiring shape: default (0.8, 0.5, 0.2)."""
        provider = _FakeConfigProvider()
        high, medium, reject = await _resolve_thresholds(provider, "scoring")
        assert (high, medium, reject) == (0.8, 0.5, 0.2)

    @pytest.mark.asyncio
    async def test_task_type_key_overrides_reject(self) -> None:
        """A promoted calibration threshold keyed by task_type wins."""
        provider = _FakeConfigProvider({
            "calibration_threshold_scoring": 0.55,
        })
        high, medium, reject = await _resolve_thresholds(provider, "scoring")
        # reject_threshold override lands; medium was 0.5 which is below
        # the new floor, so the helper raises medium to keep the map
        # LOW-band non-empty above reject and MEDIUM well-ordered.
        assert reject == pytest.approx(0.55)
        assert medium >= reject
        assert high >= medium

    @pytest.mark.asyncio
    async def test_outcome_kind_key_preferred_over_task_type(self) -> None:
        """The per-call outcome_kind key wins over the task_type key."""
        provider = _FakeConfigProvider({
            "calibration_threshold_scoring": 0.4,       # task_type fallback
            "calibration_threshold_direct_finding": 0.7,  # per-call preferred
        })
        high, medium, reject = await _resolve_thresholds(
            provider, "scoring", outcome_kind="direct_finding",
        )
        assert reject == pytest.approx(0.7)
        assert medium >= reject
        assert high >= medium

    @pytest.mark.asyncio
    async def test_outcome_kind_missing_falls_back_to_task_type(self) -> None:
        """A caller may pass outcome_kind and still resolve to the
        task_type key when the per-outcome key is not set."""
        provider = _FakeConfigProvider({
            "calibration_threshold_scoring": 0.45,
        })
        _, _, reject = await _resolve_thresholds(
            provider, "scoring", outcome_kind="direct_finding",
        )
        assert reject == pytest.approx(0.45)

    @pytest.mark.asyncio
    async def test_out_of_range_value_ignored(self) -> None:
        """A malformed / out-of-range value falls back to the default."""
        provider = _FakeConfigProvider({
            "calibration_threshold_scoring": 1.5,  # invalid
        })
        _, _, reject = await _resolve_thresholds(provider, "scoring")
        assert reject == 0.2  # default preserved

    @pytest.mark.asyncio
    async def test_non_numeric_value_ignored(self) -> None:
        """Non-parsable value falls back to the default."""
        provider = _FakeConfigProvider({
            "calibration_threshold_scoring": "not-a-float",
        })
        _, _, reject = await _resolve_thresholds(provider, "scoring")
        assert reject == 0.2


# --------------------------------------------------------------------- #
#  make_gate_step -- end-to-end override actually flips REJECT.         #
# --------------------------------------------------------------------- #


class TestGateStepUsesCalibrationOverride:
    """The wired gate step feeds the override into the reject decision."""

    @pytest.mark.asyncio
    async def test_score_below_calibration_reject_raises(
        self, routing: LLMRouting,
    ) -> None:
        """A score that is HIGH under the default reject floor (0.2)
        becomes REJECT under a promoted calibration threshold of
        0.9. This proves the override is load-bearing on the
        reject/accept decision."""
        provider = _FakeConfigProvider({
            "calibration_threshold_scoring": 0.9,
        })
        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.85}),
            model="test-model",
            finish_reason="stop",
        )
        ctx: dict[str, Any] = {"task_type": "scoring", "response": response}
        step = make_gate_step(provider, _FakeCallFn(), emitter=None)
        with pytest.raises(ConfidenceRejectedError, match="below threshold"):
            await step(ctx, [], routing)

    @pytest.mark.asyncio
    async def test_absent_key_does_not_reject(
        self, routing: LLMRouting,
    ) -> None:
        """Without the calibration key, the same 0.85 score is HIGH.

        The score is corroborated (``corroboration_confirmed``) so it
        stays in the HIGH band under Contract E1; an uncorroborated HIGH
        would be downgraded to the flag path and re-sampled, which the
        raising ``_FakeCallFn`` would catch. This test isolates the
        calibration override's effect on the reject floor, not E1.
        """
        provider = _FakeConfigProvider()  # no override
        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.85}),
            model="test-model",
            finish_reason="stop",
        )
        ctx: dict[str, Any] = {
            "task_type": "scoring",
            "response": response,
            "corroboration_confirmed": True,
        }
        step = make_gate_step(provider, _FakeCallFn(), emitter=None)
        await step(ctx, [], routing)
        assert ctx["confidence"] == "HIGH"

    @pytest.mark.asyncio
    async def test_ctx_outcome_kind_wins_over_task_type_key(
        self, routing: LLMRouting,
    ) -> None:
        """When ``ctx["outcome_kind"]`` is set the gate prefers the
        per-outcome key. Here the task_type key would leave 0.85 in
        HIGH; the outcome_kind key raises reject to 0.9 and turns the
        same score into REJECT."""
        provider = _FakeConfigProvider({
            "calibration_threshold_scoring": 0.3,           # task_type fallback
            "calibration_threshold_direct_finding": 0.9,    # per-outcome wins
        })
        response = LLMResponse(
            content=json.dumps({"confidence_score": 0.85}),
            model="test-model",
            finish_reason="stop",
        )
        ctx: dict[str, Any] = {
            "task_type": "scoring",
            "response": response,
            "outcome_kind": "direct_finding",
        }
        step = make_gate_step(provider, _FakeCallFn(), emitter=None)
        with pytest.raises(ConfidenceRejectedError, match="below threshold"):
            await step(ctx, [], routing)
