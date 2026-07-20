"""M3.R-5 -- Branch manager unit tests.

Tests cover the pure case-state merge helpers + the BranchOpResult /
BranchOperation enum coverage. DB-bound state transition paths are
exercised in integration tests once test fixtures stand up the schema
with sample investigation + branch rows.
"""
from __future__ import annotations

from aila.modules.vr.agents.branch_manager import (
    _decode,
    _encode,
    _has_contract,
    _merge_case_states,
    merge_hypotheses,
    merge_rejected,
)
from aila.modules.vr.contracts.branch import BranchOperation, BranchStatus
from aila.platform.contracts.reasoning import (
    Hypothesis,
    ReasoningCaseState,
    ReasoningContract,
    RejectedHypothesis,
)


class TestBranchOperationEnum:
    def test_seven_operations(self) -> None:
        assert {m.value for m in BranchOperation} == {
            "fork", "merge", "promote", "abandon", "pause", "resume",
            "spawn_strategy",
        }


class TestBranchStatusEnum:
    def test_six_statuses(self) -> None:
        # `completed` was added to BranchStatus after the initial
        # M3.R-5 milestone; every terminal-but-not-abandoned/merged/
        # promoted branch closes as COMPLETED.
        assert {m.value for m in BranchStatus} == {
            "active", "paused", "merged", "promoted", "abandoned",
            "completed",
        }


class TestHasContract:
    def test_empty_contract(self) -> None:
        assert _has_contract(ReasoningContract()) is False

    def test_has_answer_type(self) -> None:
        assert _has_contract(ReasoningContract(answer_type="audit")) is True

    def test_has_answer_format(self) -> None:
        assert _has_contract(ReasoningContract(answer_format="json")) is True

    def test_has_evidence_domain(self) -> None:
        assert _has_contract(ReasoningContract(evidence_domain="binary")) is True


class TestMergeHypotheses:
    def test_distinct_ids_union(self) -> None:
        a = [Hypothesis(id="h1", claim="A claim", why_plausible="", kill_criterion="")]
        b = [Hypothesis(id="h2", claim="B claim", why_plausible="", kill_criterion="")]
        out = merge_hypotheses(a, b)
        assert {h.id for h in out} == {"h1", "h2"}

    def test_same_id_b_wins(self) -> None:
        a = [Hypothesis(id="h1", claim="OLD", why_plausible="", kill_criterion="")]
        b = [Hypothesis(id="h1", claim="NEW", why_plausible="", kill_criterion="")]
        out = merge_hypotheses(a, b)
        assert len(out) == 1
        assert out[0].claim == "NEW"

    def test_empty_inputs(self) -> None:
        assert merge_hypotheses([], []) == []


class TestMergeRejected:
    def test_distinct_ids_union(self) -> None:
        a = [RejectedHypothesis(id="r1", claim="A", reason="ra")]
        b = [RejectedHypothesis(id="r2", claim="B", reason="rb")]
        out = merge_rejected(a, b)
        assert {h.id for h in out} == {"r1", "r2"}

    def test_same_id_b_wins(self) -> None:
        a = [RejectedHypothesis(id="r1", claim="A", reason="ra")]
        b = [RejectedHypothesis(id="r1", claim="A", reason="rb_better")]
        out = merge_rejected(a, b)
        assert out[0].reason == "rb_better"


class TestMergeCaseStates:
    def test_a_contract_wins_when_b_empty(self) -> None:
        a = ReasoningCaseState(contract=ReasoningContract(answer_type="audit"))
        b = ReasoningCaseState()
        merged = _merge_case_states(a, b)
        assert merged.contract.answer_type == "audit"

    def test_b_contract_wins_when_a_empty(self) -> None:
        a = ReasoningCaseState()
        b = ReasoningCaseState(contract=ReasoningContract(answer_type="discovery"))
        merged = _merge_case_states(a, b)
        assert merged.contract.answer_type == "discovery"

    def test_a_contract_wins_when_both_have_one(self) -> None:
        a = ReasoningCaseState(contract=ReasoningContract(answer_type="A"))
        b = ReasoningCaseState(contract=ReasoningContract(answer_type="B"))
        merged = _merge_case_states(a, b)
        assert merged.contract.answer_type == "A"

    def test_observables_b_wins_on_conflict(self) -> None:
        a = ReasoningCaseState(observables={"k1": "a_v1", "k2": "a_v2"})
        b = ReasoningCaseState(observables={"k1": "b_v1", "k3": "b_v3"})
        merged = _merge_case_states(a, b)
        assert merged.observables == {"k1": "b_v1", "k2": "a_v2", "k3": "b_v3"}

    def test_hypotheses_union(self) -> None:
        a = ReasoningCaseState(hypotheses=[
            Hypothesis(id="h1", claim="A", why_plausible="", kill_criterion=""),
        ])
        b = ReasoningCaseState(hypotheses=[
            Hypothesis(id="h2", claim="B", why_plausible="", kill_criterion=""),
        ])
        merged = _merge_case_states(a, b)
        assert {h.id for h in merged.hypotheses} == {"h1", "h2"}


class TestCaseStateEncoding:
    def test_round_trip(self) -> None:
        original = ReasoningCaseState(
            contract=ReasoningContract(answer_type="audit"),
            hypotheses=[
                Hypothesis(id="h1", claim="c", why_plausible="w", kill_criterion="k"),
            ],
            observables={"key": "value"},
        )
        encoded = _encode(original)
        restored = _decode(encoded)
        assert restored.contract.answer_type == "audit"
        assert len(restored.hypotheses) == 1
        assert restored.hypotheses[0].id == "h1"
        assert restored.observables == {"key": "value"}

    def test_invalid_json_returns_empty_state(self) -> None:
        restored = _decode("not json")
        assert restored == ReasoningCaseState()

    def test_none_returns_empty_state(self) -> None:
        assert _decode(None) == ReasoningCaseState()
        assert _decode("") == ReasoningCaseState()
