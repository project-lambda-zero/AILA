"""M3.R-2 — HonestVulnResearcher unit tests.

Pure-helper tests (no DB, no LLM). The full DB-round-trip test for
``run_turn`` requires fixtures that stand up the schema + insert a
target / investigation / branch, which is more work than warranted
here — that path will get its integration test once the workflow
state machine (M3.R-7) is wired.
"""
from __future__ import annotations

import json

import pytest

from aila.modules.vr.agents.vuln_researcher import (
    _decision_to_message_payload,
    _decode_case_state,
    _encode_case_state,
    _load_prompt,
    _outcome_payload,
    _render_operator_messages_section,
    _terminal_outcome_kind,
    _to_outcome_confidence,
)
from aila.modules.vr.contracts import OutcomeConfidence, OutcomeKind, PayloadKind
from aila.platform.contracts.reasoning import (
    EvidenceProvenance,
    Hypothesis,
    ReasoningCaseState,
    ReasoningContract,
    ReasoningTurnDecision,
    RejectedHypothesis,
)


class TestCaseStateEncoding:
    def test_round_trip(self) -> None:
        original = ReasoningCaseState(
            contract=ReasoningContract(answer_type="x", answer_format="json"),
            hypotheses=[Hypothesis(id="h1", claim="c", why_plausible="w", kill_criterion="k")],
            rejected=[RejectedHypothesis(id="h0", claim="old", reason="r")],
            observables={"k": "v"},
        )
        encoded = _encode_case_state(original)
        assert isinstance(encoded, str)
        restored = _decode_case_state(encoded)
        assert restored == original

    def test_empty_decode(self) -> None:
        assert _decode_case_state(None) == ReasoningCaseState()
        assert _decode_case_state("") == ReasoningCaseState()

    def test_invalid_json_decode_recovers(self) -> None:
        assert _decode_case_state("{not json") == ReasoningCaseState()

    def test_invalid_shape_recovers(self) -> None:
        assert _decode_case_state(json.dumps({"hypotheses": "not a list"})) == ReasoningCaseState()


class TestDecisionToMessagePayload:
    def test_tool_run(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="run decompile on the suspect",
            action="tool_run",
            expected_observation="pseudocode of the function",
            command="decompile",
            script_content="address_or_name=0x140012345",
        )
        kind, payload = _decision_to_message_payload(d)
        assert kind == PayloadKind.TOOL_CALL
        assert payload["command"] == "decompile"
        assert "address_or_name=0x140012345" in payload["script_content"]
        assert payload["reasoning"] == "run decompile on the suspect"

    def test_submit(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="audit complete",
            action="submit",
            expected_observation="final",
            answer="no bug found in region",
            confidence="strong",
            provenance=EvidenceProvenance(
                primary_artifact="step-3",
                corroboration=["step-5"],
                rejected_alternatives=[],
            ),
        )
        kind, payload = _decision_to_message_payload(d)
        assert kind == PayloadKind.OUTCOME_PENDING
        assert payload["answer"] == "no bug found in region"
        assert payload["confidence"] == "strong"

    def test_reasoning(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="thinking about JSPI",
            action="reasoning",
            expected_observation="hypothesis refined",
        )
        kind, payload = _decision_to_message_payload(d)
        assert kind == PayloadKind.TEXT
        assert payload["text"] == "thinking about JSPI"


class TestTerminalOutcomeKindRouting:
    def test_strong_confidence_becomes_direct_finding(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="r", action="submit", confidence="strong", answer="found",
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.DIRECT_FINDING

    def test_exact_confidence_becomes_direct_finding(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="r", action="submit", confidence="exact", answer="found",
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.DIRECT_FINDING

    def test_medium_becomes_assessment_report(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="r", action="submit", confidence="medium", answer="maybe",
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.ASSESSMENT_REPORT

    def test_caveated_becomes_assessment_report(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="r", action="submit", confidence="caveated", answer="unclear",
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.ASSESSMENT_REPORT

    def test_unknown_becomes_assessment_report(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="r", action="submit", confidence="unknown", answer="dunno",
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.ASSESSMENT_REPORT


class TestToOutcomeConfidence:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("exact", OutcomeConfidence.EXACT),
            ("strong", OutcomeConfidence.STRONG),
            ("medium", OutcomeConfidence.MEDIUM),
            ("caveated", OutcomeConfidence.CAVEATED),
            ("unknown", OutcomeConfidence.UNKNOWN),
        ],
    )
    def test_passthrough(self, value: str, expected: OutcomeConfidence) -> None:
        d = ReasoningTurnDecision(reasoning="", action="submit", confidence=value)
        assert _to_outcome_confidence(d) == expected

    def test_missing_confidence_defaults_unknown(self) -> None:
        d = ReasoningTurnDecision(reasoning="", action="submit")
        assert _to_outcome_confidence(d) == OutcomeConfidence.UNKNOWN


class TestOutcomePayload:
    def test_basic_shape(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="r",
            action="submit",
            answer="ok",
            confidence="strong",
            contract=ReasoningContract(answer_type="audit"),
        )
        payload = _outcome_payload(d)
        assert payload["answer"] == "ok"
        assert payload["reasoning"] == "r"
        assert payload["contract"]["answer_type"] == "audit"

    def test_no_contract(self) -> None:
        d = ReasoningTurnDecision(reasoning="r", action="submit", answer="x")
        payload = _outcome_payload(d)
        assert payload["contract"] is None


class TestPromptLoading:
    def test_audit_prompt_loads(self) -> None:
        text = _load_prompt("vulnerability_research.audit")
        assert "audit-only investigation" in text
        assert "submit" in text

    def test_unknown_strategy_falls_back_to_audit(self) -> None:
        text = _load_prompt("vulnerability_research.discovery_research")
        # Falls back to audit prompt for v0.3 v1 (other strategies stub)
        assert "audit-only investigation" in text

    def test_completely_unknown_family_also_falls_back(self) -> None:
        text = _load_prompt("weird.unknown_family")
        assert "audit-only investigation" in text


class TestRenderOperatorMessagesSection:
    def test_empty_returns_empty_string(self) -> None:
        assert _render_operator_messages_section([]) == ""

    def test_single_message_includes_text_and_intent(self) -> None:
        out = _render_operator_messages_section([
            {"id": "m1", "text": "check JSPI base", "intent": "steering"},
        ])
        assert "check JSPI base" in out
        assert "[intent: steering]" in out
        assert "Operator messages" in out

    def test_unclassified_intent_default(self) -> None:
        out = _render_operator_messages_section([
            {"id": "m1", "text": "look at recv", "intent": ""},
        ])
        assert "[intent: unclassified]" in out

    def test_multiple_messages_preserve_order(self) -> None:
        out = _render_operator_messages_section([
            {"id": "m1", "text": "first thought", "intent": "steering"},
            {"id": "m2", "text": "second thought", "intent": "correction"},
        ])
        assert out.index("first thought") < out.index("second thought")
        assert "[intent: steering]" in out
        assert "[intent: correction]" in out

    def test_missing_text_doesnt_crash(self) -> None:
        out = _render_operator_messages_section([{"id": "m1", "intent": "steering"}])
        assert "[intent: steering]" in out
