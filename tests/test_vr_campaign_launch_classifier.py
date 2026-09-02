"""Tests for the CAMPAIGN_LAUNCH override in ``_terminal_outcome_kind`` and
the sibling-open-hyp gate exemption in
``HonestVulnResearcher._maybe_reject_no_finding_while_sibling_open_hyp``
(spec ``.run/ralph/frontend-improvements/specs/vr-fuzz-merge.md`` AC2).

Both paths are exercised without a live DB / LLM. The classifier is a
module-level function, so it is called directly. The instance method is
called with a ``SimpleNamespace`` stand-in for ``self`` that carries the
two staticmethods the CAMPAIGN_LAUNCH early-return path reads.
"""
from __future__ import annotations

from types import SimpleNamespace

from aila.modules.vr.agents.vuln_researcher import (
    HonestVulnResearcher,
    _outcome_payload,
    _terminal_outcome_kind,
)
from aila.modules.vr.contracts import OutcomeKind
from aila.platform.contracts.reasoning import (
    Hypothesis,
    ReasoningCaseState,
    ReasoningTurnDecision,
)


class TestCampaignLaunchClassifier:
    def test_payload_requests_campaign_launch(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="dispatch fuzz job",
            action="submit",
            confidence="medium",
            answer="Launch AFL++ campaign against the JS parser harness.",
            payload={"outcome_kind": "campaign_launch"},
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.CAMPAIGN_LAUNCH

    def test_payload_requests_campaign_launch_case_insensitive(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="dispatch fuzz job",
            action="submit",
            confidence="strong",
            answer="Launch libFuzzer campaign.",
            payload={"outcome_kind": "CAMPAIGN_LAUNCH"},
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.CAMPAIGN_LAUNCH

    def test_without_payload_kind_uses_default_routing(self) -> None:
        # Strong-confidence positive answer with no requested outcome_kind
        # still routes to DIRECT_FINDING via the existing classifier.
        d = ReasoningTurnDecision(
            reasoning="r",
            action="submit",
            confidence="strong",
            answer="Authentication bypass: forged token grants admin access.",
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.DIRECT_FINDING

    def test_agent_cannot_request_direct_finding_to_bypass_gate(self) -> None:
        # A negative-finding answer with a bogus requested outcome_kind
        # of "direct_finding" MUST still route to AUDIT_MEMO. Only
        # CAMPAIGN_LAUNCH is honored on the payload override; other
        # requested kinds fall through to the existing classifier.
        d = ReasoningTurnDecision(
            reasoning="r",
            action="submit",
            confidence="strong",
            answer="No exploitable vulnerability found in the sandbox.",
            payload={"outcome_kind": "direct_finding"},
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.AUDIT_MEMO

    def test_unknown_requested_kind_falls_through(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="r",
            action="submit",
            confidence="medium",
            answer="maybe",
            payload={"outcome_kind": "not_a_real_kind"},
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.ASSESSMENT_REPORT


class TestSiblingOpenHypGateCampaignLaunchExempt:
    def _fake_self(self) -> SimpleNamespace:
        return SimpleNamespace(
            _terminal_outcome_kind=_terminal_outcome_kind,
            _clear_sibling_open_hyp_gate_state=(
                HonestVulnResearcher._clear_sibling_open_hyp_gate_state
            ),
        )

    def test_campaign_launch_submit_not_rejected_by_sibling_open_hyp(
        self,
    ) -> None:
        # A sibling holds a live hypothesis id "h_sib_1" that no branch
        # has rejected. A no_finding/inconclusive submit would normally
        # be rejected. CAMPAIGN_LAUNCH must pass through unchanged.
        decision = ReasoningTurnDecision(
            reasoning="dispatch fuzz job",
            action="submit",
            confidence="medium",
            answer="Launch AFL++ campaign against the JS parser harness.",
            payload={"outcome_kind": "campaign_launch"},
        )
        case_state = ReasoningCaseState(
            observables={
                "_sibling_open_hyp_reject_count": 1,
                "_directive.sibling_open_hyp_block": "prior directive text",
            },
        )
        sibling_context = [
            {
                "branch_id": "branch-sibling",
                "persona_voice": "renzo",
                "hypotheses": [
                    {"id": "h_sib_1", "claim": "sibling still hunting"},
                ],
                "rejected": [],
            },
        ]
        fake_self = self._fake_self()
        out = HonestVulnResearcher._maybe_reject_no_finding_while_sibling_open_hyp(
            fake_self,  # type: ignore[arg-type]
            decision=decision,
            case_state=case_state,
            sibling_context=sibling_context,
            turn_number=7,
        )
        # Decision passes through unchanged.
        assert out is decision
        assert out.action == "submit"
        # Gate state cleared (mirrors the other pass branches).
        assert "_sibling_open_hyp_reject_count" not in case_state.observables
        assert (
            "_directive.sibling_open_hyp_block" not in case_state.observables
        )

    def test_non_campaign_submit_still_gated(self) -> None:
        # Regression: a no_finding submit with an open sibling hyp is
        # still swapped to a non-terminal placeholder (the existing
        # gate behavior). The CAMPAIGN_LAUNCH short-circuit must not
        # short-circuit anything else.
        decision = ReasoningTurnDecision(
            reasoning="closing out",
            action="submit",
            confidence="strong",
            answer="No exploitable vulnerability found in the target.",
        )
        case_state = ReasoningCaseState(
            hypotheses=[
                Hypothesis(
                    id="h_self_1",
                    claim="my own live hyp",
                    why_plausible="w",
                    kill_criterion="k",
                ),
            ],
        )
        sibling_context = [
            {
                "branch_id": "branch-sibling",
                "persona_voice": "renzo",
                "hypotheses": [
                    {"id": "h_sib_1", "claim": "sibling still hunting"},
                ],
                "rejected": [],
            },
        ]
        fake_self = SimpleNamespace(
            _terminal_outcome_kind=_terminal_outcome_kind,
            _outcome_payload=_outcome_payload,
            _clear_sibling_open_hyp_gate_state=(
                HonestVulnResearcher._clear_sibling_open_hyp_gate_state
            ),
            _sibling_open_hyp_reject_cap=3,
            investigation_id="inv-test",
            branch_id="branch-self",
        )
        out = HonestVulnResearcher._maybe_reject_no_finding_while_sibling_open_hyp(
            fake_self,  # type: ignore[arg-type]
            decision=decision,
            case_state=case_state,
            sibling_context=sibling_context,
            turn_number=1,
        )
        # Gate rejects: action swapped from "submit" to "tool_run".
        assert out.action == "tool_run"
        assert out.payload.get("_sibling_open_hyp_gate_rejected") is True
