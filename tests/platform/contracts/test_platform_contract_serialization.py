"""Pure-unit contract coverage the #62 audit called out as missing.

Three thin surfaces the audit surfaced with zero direct tests:

* ``RunState`` / ``PlatformResponse`` / ``RouteDecision`` JSON round-trip via
  ``model_dump(mode="json") -> model_validate(...)``. Both records are
  handed off across task-queue and API boundaries as JSON; a subtle field
  that fails ``mode="json"`` serialization would silently break every
  downstream deserializer.
* ``ReasoningCaseState.observables`` non-JSON rejection at construction --
  the guard exists but only had one datetime-shaped test in the existing
  suite, so a regression that widened acceptance would slip through. This
  file pins the full set of non-JSON types the guard MUST reject.

No DB, no IO. Every test is a pure structural check on the contract types.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest
from pydantic import ValidationError

from aila.platform.contracts.platform import (
    RouteCandidate,
    RouteDecision,
)
from aila.platform.contracts.reasoning import (
    ReasoningCaseState,
    ReasoningTurnDecision,
)
from aila.platform.contracts.runtime import (
    PlatformResponse,
    RunState,
    WorkflowEvent,
)


# ---------------------------------------------------------------------------
# RunState / PlatformResponse / RouteDecision JSON round-trip
# ---------------------------------------------------------------------------


class TestRuntimeJsonRoundTrip:
    """``model_dump(mode="json")`` -> ``model_validate(dumped)`` is a fixed point."""

    @staticmethod
    def _route_decision() -> RouteDecision:
        return RouteDecision(
            action_id="vulnerability.count",
            selected_module="vulnerability",
            confidence=0.87,
            rationale="user asked for a count",
            decision_source="model",
            candidates=[
                RouteCandidate(
                    module_id="vulnerability",
                    action_id="vulnerability.count",
                    score=0.87,
                    tools=["counter"],
                ),
                RouteCandidate(
                    module_id="vulnerability",
                    action_id="vulnerability.explain",
                    score=0.42,
                    tools=[],
                ),
            ],
        )

    def test_route_decision_round_trip(self) -> None:
        original = self._route_decision()
        dumped = original.model_dump(mode="json")
        restored = RouteDecision.model_validate(dumped)
        assert restored == original

    def test_run_state_round_trip_with_route_and_events(self) -> None:
        original = RunState(
            run_id="run-json-a",
            query="count my CVEs",
            route=self._route_decision(),
            events=[
                WorkflowEvent(
                    state="analysis_start",
                    note="collecting inventory",
                    occurred_at=datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc),
                ),
                WorkflowEvent(
                    state="scoring_complete",
                    note="42 findings ranked",
                    occurred_at=datetime(2026, 5, 1, 12, 5, tzinfo=timezone.utc),
                ),
            ],
            artifacts={"report": "17", "summary": "18"},
        )
        dumped = original.model_dump(mode="json")
        # datetime fields must land as ISO strings under mode="json" so they
        # survive JSON encoding on the task-queue boundary.
        assert isinstance(dumped["events"][0]["occurred_at"], str)
        restored = RunState.model_validate(dumped)
        assert restored == original

    def test_platform_response_round_trip_preserves_route_and_artifacts(self) -> None:
        original = PlatformResponse(
            run_id="run-json-b",
            action_id="vulnerability.summary",
            message="ran the summary path",
            route=self._route_decision(),
            module_payload={"query_mode": "summary", "notes": "ok"},
            artifacts={"report": "42"},
            state_history=[
                WorkflowEvent(
                    state="report_written",
                    note="artifact 42",
                    occurred_at=datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc),
                ),
            ],
        )
        dumped = original.model_dump(mode="json")
        restored = PlatformResponse.model_validate(dumped)
        assert restored == original
        # The route sub-object must round-trip byte-identically -- Pydantic
        # equality only guarantees value equality, so pin the important
        # scalar fields explicitly to protect against silent field drift.
        assert restored.route is not None
        assert restored.route.action_id == "vulnerability.count"
        assert restored.route.confidence == 0.87
        assert restored.artifacts == {"report": "42"}


# ---------------------------------------------------------------------------
# ReasoningCaseState.observables non-JSON rejection
# ---------------------------------------------------------------------------


class TestReasoningCaseStateObservablesJsonGuard:
    """observables MUST reject values that json.dumps cannot encode.

    Rejecting the value at construction time is the whole point of the guard:
    once a bad observable lands on ``ReasoningCaseState``, it survives every
    in-process mutation and only crashes far away, at
    ``model_dump(mode="json")`` in the workflow engine or at
    ``TaskQueue.submit`` when the payload gets JSON-encoded on the way to
    ARQ. That's exactly the reason the audit called the guard out as a
    "before the task queue" invariant (#62).
    """

    @pytest.mark.parametrize(
        "bad_value, label",
        [
            (datetime(2026, 7, 20, tzinfo=timezone.utc), "aware datetime"),
            (datetime(2026, 7, 20), "naive datetime"),
            (b"\x00\x01\x02", "bytes"),
            ({1, 2, 3}, "set"),
            (frozenset({1, 2}), "frozenset"),
            (object(), "arbitrary object"),
            (Decimal("1.5"), "Decimal"),
        ],
    )
    def test_case_state_rejects_non_json_observable(
        self, bad_value: object, label: str,
    ) -> None:
        with pytest.raises(ValidationError, match="JSON-serializable"):
            ReasoningCaseState(observables={"k": bad_value})
        # The parametrize label helps failing runs pinpoint the offending shape.
        assert label

    def test_case_state_rejects_non_json_nested(self) -> None:
        """Nested non-JSON values are caught, not just top-level ones.

        Guards against a naive `json.dumps` skip that would only walk the top
        level of the dict; the observable is stored as ``dict[str, Any]`` so
        any depth of nesting must be validated.
        """
        with pytest.raises(ValidationError, match="JSON-serializable"):
            ReasoningCaseState(
                observables={
                    "outer": {"inner": {"bad": b"\x00\x01"}},
                },
            )

    def test_case_state_accepts_deep_json(self) -> None:
        """Regression guard: legitimate deep JSON still constructs."""
        cs = ReasoningCaseState(
            observables={
                "a": {"b": {"c": [1, 2, {"d": None, "e": "ok"}]}},
                "arr": [1, 2, 3],
                "n": 4,
                "s": "hi",
                "flag": True,
                "empty": None,
            },
        )
        # Round-trip is the ultimate acceptance: if the guard let bad values
        # through, ``model_dump(mode='json')`` would surface it here.
        assert cs.model_dump(mode="json")["observables"]["n"] == 4

    def test_turn_decision_rejects_non_json_observable(self) -> None:
        """Same guard applies to ReasoningTurnDecision (turn-level payloads).

        Turn decisions ride into the same JSON-encoded task-queue kwargs, so
        the same rejection contract is enforced.
        """
        with pytest.raises(ValidationError, match="JSON-serializable"):
            ReasoningTurnDecision(
                reasoning="x", observables={"blob": b"\x00\x01"},
            )
