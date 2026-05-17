"""M3.R-1 — Reasoning subsystem contract round-trip tests.

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
    BranchOperation,
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
    def test_kind_values(self) -> None:
        assert {m.value for m in InvestigationKind} == {
            "discovery", "variant_hunt", "triage", "n_day", "audit",
        }

    def test_status_values(self) -> None:
        assert {m.value for m in InvestigationStatus} == {
            "created", "running", "paused", "completed", "failed", "abandoned",
        }

    def test_pause_reason_values(self) -> None:
        assert {m.value for m in InvestigationPauseReason} == {
            "operator", "low_confidence", "cost_budget",
            "awaiting_campaign", "awaiting_mcp",
        }


class TestBranchEnums:
    def test_status_values(self) -> None:
        assert {m.value for m in BranchStatus} == {
            "active", "paused", "merged", "promoted", "abandoned",
        }

    def test_six_personas(self) -> None:
        # D-39: six persona voices
        assert {m.value for m in PersonaVoice} == {
            "halvar", "maddie", "yuki", "renzo", "noor", "wei",
        }

    def test_branch_operations(self) -> None:
        # D-41 + pause/resume
        assert {m.value for m in BranchOperation} == {
            "fork", "merge", "promote", "abandon", "pause", "resume",
            "spawn_strategy",
        }


class TestMessageEnums:
    def test_sender_kinds(self) -> None:
        assert {m.value for m in SenderKind} == {"engine", "operator"}

    def test_payload_kinds_match_d44(self) -> None:
        # D-44 lists 10 typed engine payload kinds
        assert {m.value for m in PayloadKind} == {
            "text", "tool_call", "code_pointer", "graph_view",
            "taint_flow", "xref_view", "patch_diff",
            "decompiled_function", "hypothesis_update", "outcome_pending",
        }

    def test_operator_intents_match_d43_ga30(self) -> None:
        # D-43 GA-30 lists 6 operator intents + UNCLASSIFIED escape
        assert {m.value for m in OperatorIntent} == {
            "steering", "question", "correction", "dismissal",
            "outcome_selection", "branch_command", "unclassified",
        }


class TestOutcomeEnums:
    def test_eleven_outcome_kinds(self) -> None:
        # D-43 lists 11 typed outcomes
        assert {m.value for m in OutcomeKind} == {
            "assessment_report", "strategy_descriptor", "profile_spec_draft",
            "config_delta", "variant_hunt_order", "patch_assessment_report",
            "audit_memo", "direct_finding", "crash_triage_report",
            "campaign_launch", "sub_investigation",
        }
        assert len(list(OutcomeKind)) == 11

    def test_confidence_matches_reasoning(self) -> None:
        # Matches platform's ReasoningConfidence
        assert {m.value for m in OutcomeConfidence} == {
            "exact", "strong", "medium", "caveated", "unknown",
        }

    def test_dispatch_status(self) -> None:
        assert {m.value for m in OutcomeDispatchStatus} == {
            "pending", "dispatched", "failed", "skipped",
        }


class TestAuditMemoEnums:
    def test_scope_ladder(self) -> None:
        # Promotion ladder matches D-43 GA-41 pattern scopes
        assert {m.value for m in AuditMemoScope} == {
            "local", "workspace", "team", "global",
        }


class TestInvestigationCreate:
    def test_minimum_valid(self) -> None:
        inv = VRInvestigationCreate(
            title="Audit V8 Map Inference for missing alias checks",
            initial_question="Are there places in InferMaps that miss the alias check?",
            target_id="tgt-1",
        )
        assert inv.kind == InvestigationKind.DISCOVERY
        assert inv.auto_pilot is True
        assert inv.cost_budget_usd == 50.0
        assert inv.strategy_family == "vulnerability_research.discovery_research"

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

    def test_variant_hunt_parent(self) -> None:
        inv = VRInvestigationCreate(
            title="variant hunt CVE-2025-2135",
            initial_question="any siblings?",
            target_id="tgt-2",
            kind=InvestigationKind.VARIANT_HUNT,
            parent_investigation_id="inv-1",
        )
        assert inv.parent_investigation_id == "inv-1"
        assert inv.kind == InvestigationKind.VARIANT_HUNT


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
    def test_minimum_valid(self) -> None:
        m = VRMessageCreate(text="please check JSPI base address handling")
        assert m.branch_id is None
        assert m.explicit_intent is None

    def test_text_min_length(self) -> None:
        with pytest.raises(ValidationError):
            VRMessageCreate(text="")

    def test_explicit_intent_override(self) -> None:
        m = VRMessageCreate(
            text="that finding is bogus",
            explicit_intent=OperatorIntent.DISMISSAL,
        )
        assert m.explicit_intent == OperatorIntent.DISMISSAL


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
    def test_minimum_valid(self) -> None:
        o = VROutcomeCreate(
            branch_id="br-1",
            outcome_kind=OutcomeKind.AUDIT_MEMO,
            confidence=OutcomeConfidence.MEDIUM,
        )
        assert o.payload == {}
        assert o.evidence_refs == []

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
