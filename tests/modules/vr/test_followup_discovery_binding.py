"""VR binding of the follow-up-discovery take-over.

Verifies :mod:`aila.modules.vr.services.followup_discovery` wires the
platform primitive with the right VR-side identity (record models +
polarity fn + recommendations extractor + enqueue closure + strategy
family + kind), and that the recommendations extractor mirrors the
``payload['panel_summary']['recommended_next_actions']`` shape the VR
SynthesisAgent persists.
"""
from __future__ import annotations

from typing import Any

import pytest

from aila.modules.vr.contracts.investigation import InvestigationKind
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.modules.vr.services.followup_discovery import (
    extract_vr_recommendations,
    maybe_spawn_vr_followup,
)
from aila.modules.vr.services.outcome_polarity import derive_outcome_polarity


class TestExtractVRRecommendations:
    """The extractor reads the exact shape the VR SynthesisAgent writes."""

    def test_returns_the_recommended_next_actions_list(self) -> None:
        payload = {
            "panel_summary": {
                "recommended_next_actions": [
                    "Audit parser.c bounds check",
                    "Re-run fuzzer with wider corpus",
                ],
            },
        }
        assert extract_vr_recommendations(payload) == [
            "Audit parser.c bounds check",
            "Re-run fuzzer with wider corpus",
        ]

    def test_returns_empty_when_panel_summary_absent(self) -> None:
        assert extract_vr_recommendations({}) == []

    def test_returns_empty_when_panel_summary_is_not_a_dict(self) -> None:
        assert extract_vr_recommendations({"panel_summary": "narrative-string"}) == []

    def test_returns_empty_when_recommended_next_actions_absent(self) -> None:
        assert extract_vr_recommendations({"panel_summary": {}}) == []

    def test_returns_empty_when_recommended_next_actions_is_not_a_list(
        self,
    ) -> None:
        assert extract_vr_recommendations(
            {"panel_summary": {"recommended_next_actions": "oops"}},
        ) == []

    def test_coerces_non_string_entries_to_strings(self) -> None:
        # Robustness: an LLM parse could stray to non-string entries;
        # the extractor must still hand the primitive a clean list of
        # strings for the mandate body.
        payload = {"panel_summary": {"recommended_next_actions": ["a", 7]}}
        assert extract_vr_recommendations(payload) == ["a", "7"]


class TestBindingComposition:
    """The wrapper composes the platform primitive with VR identity."""

    @pytest.mark.asyncio
    async def test_wrapper_forwards_to_the_platform_primitive_with_vr_bindings(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A single call to ``maybe_spawn_vr_followup`` forwards to the
        platform primitive with every VR-side binding bolted on:
        VR record models, VR polarity reducer, VR recommendations
        extractor, the VR discovery kind + strategy family, and a
        VR-side enqueue closure. The test captures the kwargs the
        platform primitive was called with and asserts each is the
        expected VR-side object.
        """
        captured: dict[str, Any] = {}

        async def _fake_platform_primitive(
            investigation_id: str,
            **kwargs: Any,
        ) -> dict[str, Any]:
            captured["investigation_id"] = investigation_id
            captured.update(kwargs)
            return {"status": "skipped", "reason": "captured_by_test"}

        monkeypatch.setattr(
            "aila.modules.vr.services.followup_discovery.maybe_spawn_followup_discovery",
            _fake_platform_primitive,
        )

        result = await maybe_spawn_vr_followup("inv-abc")

        assert result == {"status": "skipped", "reason": "captured_by_test"}
        assert captured["investigation_id"] == "inv-abc"
        # VR record models
        assert captured["investigation_model"] is VRInvestigationRecord
        assert captured["branch_model"] is VRInvestigationBranchRecord
        assert captured["outcome_model"] is VRInvestigationOutcomeRecord
        # VR kind + strategy_family
        assert captured["discovery_kind"] == InvestigationKind.DISCOVERY.value
        assert (
            captured["strategy_family"]
            == "vulnerability_research.discovery_research"
        )
        # VR polarity reducer + extractor
        assert captured["derive_polarity"] is derive_outcome_polarity
        assert captured["extract_recommendations"] is extract_vr_recommendations
        # Enqueue closure is present (callable)
        assert callable(captured["enqueue_investigate"])
