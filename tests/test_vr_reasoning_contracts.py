"""M3.R-1 -- Reasoning subsystem contract round-trip tests.

Schema-only milestone: tests verify Pydantic model construction,
enum cardinalities, ``extra='forbid'`` behavior, and round-tripping
through ``model_dump`` / ``model_validate`` to catch silent drift.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from aila.modules.vr.contracts import (
    AuditMemoCreate,
    AuditMemoScope,
    AuditMemoSummary,
    BranchStatus,
    InvestigationKind,
    InvestigationPauseReason,
    InvestigationStatus,
    OperatorIntent,
    OutcomeConfidence,
    OutcomeDispatchStatus,
    OutcomeKind,
    PayloadKind,
    PersonaVoice,
    SenderKind,
    VRBranchSummary,
    VRInvestigationCreate,
    VRInvestigationSummary,
    VRMessageCreate,
    VRMessageSummary,
    VROutcomeCreate,
    VROutcomeSummary,
)


class TestInvestigationEnums:

    def test_status_values(self) -> None:
        # ``stalled`` joined the set when RFC-13 escalation added a distinct
        # terminal state for investigations that stopped making progress
        # (see aila.platform.contracts.enums.InvestigationStatus).
        assert {m.value for m in InvestigationStatus} == {
            "created", "running", "paused", "completed", "failed", "abandoned", "stalled",
        }

    def test_pause_reason_values(self) -> None:
        assert {m.value for m in InvestigationPauseReason} == {
            "operator", "low_confidence", "cost_budget",
            "awaiting_campaign", "awaiting_mcp",
        }


class TestBranchEnums:
    def test_status_values(self) -> None:
        # BranchStatus gained `completed` after the original M3.R-5 set:
        # a branch that finished cleanly (not merged / promoted /
        # abandoned) closes as COMPLETED.
        assert {m.value for m in BranchStatus} == {
            "active", "paused", "merged", "promoted", "abandoned",
            "completed",
        }


class TestMessageEnums:


    def test_operator_intents_match_d43_ga30(self) -> None:
        # D-43 GA-30 lists 6 operator intents + UNCLASSIFIED escape
        assert {m.value for m in OperatorIntent} == {
            "steering", "question", "correction", "dismissal",
            "outcome_selection", "branch_command", "unclassified",
        }


class TestOutcomeEnums:

    def test_confidence_matches_reasoning(self) -> None:
        # Matches platform's ReasoningConfidence
        assert {m.value for m in OutcomeConfidence} == {
            "exact", "strong", "medium", "caveated", "unknown",
        }

    def test_dispatch_status(self) -> None:
        assert {m.value for m in OutcomeDispatchStatus} == {
            "pending", "claimed", "dispatched", "failed", "skipped",
        }


class TestInvestigationCreate:

    def test_title_min_length(self) -> None:
        with pytest.raises(ValidationError):
            VRInvestigationCreate(
                title="", initial_question="x", target_id="t",
            )

    def test_negative_budget_rejected(self) -> None:
        with pytest.raises(ValidationError):
            VRInvestigationCreate(
                title="x", initial_question="y", target_id="t",
                cost_budget_usd=-1.0,
            )

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            VRInvestigationCreate(  # type: ignore[call-arg]
                title="x", initial_question="y", target_id="t", junk=1,
            )


class TestInvestigationSummaryRoundTrip:
    def test_round_trip(self) -> None:
        original = VRInvestigationSummary(
            id="inv-1",
            title="t",
            target_id="tgt-1",
            workspace_id="ws-1",
            kind=InvestigationKind.DISCOVERY,
            status=InvestigationStatus.RUNNING,
            auto_pilot=True,
            strategy_family="vulnerability_research.discovery_research",
            cost_budget_usd=50.0,
            cost_actual_usd=12.3,
            branch_count=2,
            message_count=14,
            outcome_count=0,
            linked_campaign_ids=["c1"],
            linked_finding_ids=[],
        )
        dumped = original.model_dump(mode="json")
        restored = VRInvestigationSummary.model_validate(dumped)
        assert restored == original


class TestBranchSummaryRoundTrip:
    def test_round_trip(self) -> None:
        original = VRBranchSummary(
            id="br-1",
            investigation_id="inv-1",
            status=BranchStatus.ACTIVE,
            persona_voice=PersonaVoice.HALVAR,
            fork_reason="persona dispatch",
            fork_at_turn=3,
            turn_count=12,
            branch_cost_usd=4.5,
        )
        dumped = original.model_dump(mode="json")
        restored = VRBranchSummary.model_validate(dumped)
        assert restored == original


class TestMessageCreate:

    def test_text_min_length(self) -> None:
        with pytest.raises(ValidationError):
            VRMessageCreate(text="")


class TestMessageSummaryRoundTrip:
    def test_round_trip_engine_message(self) -> None:
        original = VRMessageSummary(
            id="m-1",
            investigation_id="inv-1",
            branch_id="br-1",
            sender_kind=SenderKind.ENGINE,
            payload_kind=PayloadKind.DECOMPILED_FUNCTION,
            payload={"function_name": "v8::FastAPI::serialize", "address": "0x140012345"},
            at_turn=5,
            evidence_refs=["step-3", "step-4"],
        )
        dumped = original.model_dump(mode="json")
        restored = VRMessageSummary.model_validate(dumped)
        assert restored == original

    def test_round_trip_operator_message(self) -> None:
        original = VRMessageSummary(
            id="m-2",
            investigation_id="inv-1",
            branch_id="br-1",
            sender_kind=SenderKind.OPERATOR,
            sender_id="user-abc",
            payload_kind=PayloadKind.TEXT,
            payload={"text": "what about JSPI?"},
            operator_intent=OperatorIntent.STEERING,
        )
        dumped = original.model_dump(mode="json")
        restored = VRMessageSummary.model_validate(dumped)
        assert restored == original


class TestOutcomeCreate:

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            VROutcomeCreate(  # type: ignore[call-arg]
                branch_id="b",
                outcome_kind=OutcomeKind.AUDIT_MEMO,
                confidence=OutcomeConfidence.MEDIUM,
                junk=1,
            )


class TestOutcomeSummaryRoundTrip:
    def test_round_trip_with_payload(self) -> None:
        original = VROutcomeSummary(
            id="o-1",
            investigation_id="inv-1",
            branch_id="br-1",
            outcome_kind=OutcomeKind.DIRECT_FINDING,
            payload={
                "crash_signature": "deadbeef" * 8,
                "crash_type": "type_confusion",
                "vulnerable_function": "v8::FastAPI::serialize",
            },
            confidence=OutcomeConfidence.STRONG,
            evidence_refs=["step-12", "step-15"],
            dispatch_status=OutcomeDispatchStatus.PENDING,
        )
        dumped = original.model_dump(mode="json")
        restored = VROutcomeSummary.model_validate(dumped)
        assert restored == original


class TestAuditMemoCreate:
    def test_minimum_valid(self) -> None:
        m = AuditMemoCreate(
            investigation_id="inv-1",
            target_signature="deadbeef" * 8,
            region_descriptor="function v8::FastAPI::serialize at api-natives.cc:1024",
            claim="Audited for integer overflow on length parameter; bounds check at line 1031 is correct.",
        )
        assert m.scope == AuditMemoScope.LOCAL
        assert m.confidence == OutcomeConfidence.MEDIUM


class TestAuditMemoSummaryRoundTrip:
    def test_round_trip(self) -> None:
        original = AuditMemoSummary(
            id="memo-1",
            investigation_id="inv-1",
            workspace_id="ws-1",
            target_signature="deadbeef" * 8,
            region_descriptor="r",
            claim="c",
            evidence_refs=["e1", "e2"],
            confidence=OutcomeConfidence.STRONG,
            pivot_history=["tried symbolic exec", "tried fuzz, no hits"],
            scope=AuditMemoScope.WORKSPACE,
            promoted=False,
        )
        dumped = original.model_dump(mode="json")
        restored = AuditMemoSummary.model_validate(dumped)
        assert restored == original
