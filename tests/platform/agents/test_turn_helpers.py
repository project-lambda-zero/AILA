"""Unit tests for the shared turn-runner helpers (RFC-03 lift).

These four functions were byte-identical copies in the vr and malware
turn runners; they now live once in ``aila.platform.agents.turn_helpers``.
Pure functions, no infra required.
"""
from __future__ import annotations

from aila.platform.agents.turn_helpers import (
    auto_resolve_live_on_terminal,
    decode_case_state,
    encode_case_state,
    to_outcome_confidence,
)
from aila.platform.contracts.enums import OutcomeConfidence
from aila.platform.contracts.reasoning import (
    Hypothesis,
    ReasoningCaseState,
    ReasoningTurnDecision,
    ResolvedHypothesis,
)


class TestCaseStateCodec:
    def test_decode_none_returns_empty(self) -> None:
        assert decode_case_state(None) == ReasoningCaseState()

    def test_decode_invalid_json_returns_empty(self) -> None:
        assert decode_case_state("{not valid json") == ReasoningCaseState()

    def test_decode_wrong_shape_returns_empty(self) -> None:
        # Valid JSON but a list, not the expected object -- validation
        # fails and the codec degrades to a fresh empty state.
        assert decode_case_state("[1, 2, 3]") == ReasoningCaseState()

    def test_encode_decode_round_trip(self) -> None:
        state = ReasoningCaseState(hypotheses=[Hypothesis(id="h1", claim="c1")])
        restored = decode_case_state(encode_case_state(state))
        assert [h.id for h in restored.hypotheses] == ["h1"]
        assert restored.hypotheses[0].claim == "c1"


class TestToOutcomeConfidence:
    def test_none_confidence_maps_to_unknown(self) -> None:
        decision = ReasoningTurnDecision(reasoning="x", confidence=None)
        assert to_outcome_confidence(decision) == OutcomeConfidence.UNKNOWN

    def test_set_confidence_maps_through(self) -> None:
        decision = ReasoningTurnDecision(reasoning="x", confidence="strong")
        assert to_outcome_confidence(decision) == OutcomeConfidence("strong")


class TestAutoResolveLiveOnTerminal:
    def test_empty_hypotheses_is_noop(self) -> None:
        state = ReasoningCaseState()
        auto_resolve_live_on_terminal(state, turn=5, outcome_kind="direct_finding")
        assert state.resolved == []
        assert state.hypotheses == []

    def test_live_hypotheses_move_to_resolved(self) -> None:
        state = ReasoningCaseState(
            hypotheses=[
                Hypothesis(id="h1", claim="c1"),
                Hypothesis(id="h2", claim="c2"),
            ],
        )
        auto_resolve_live_on_terminal(state, turn=7, outcome_kind="direct_finding")
        assert state.hypotheses == []
        assert {r.id for r in state.resolved} == {"h1", "h2"}
        for r in state.resolved:
            assert r.resolved_at_turn == 7
            assert r.terminal_outcome_kind == "direct_finding"

    def test_already_resolved_id_not_duplicated(self) -> None:
        state = ReasoningCaseState(
            hypotheses=[Hypothesis(id="h1", claim="c1")],
            resolved=[ResolvedHypothesis(id="h1", claim="c1", resolved_at_turn=3)],
        )
        auto_resolve_live_on_terminal(state, turn=9, outcome_kind="no_finding")
        # h1 was already resolved (turn 3) so it is not re-appended, but
        # the live list is still cleared.
        assert [r.resolved_at_turn for r in state.resolved] == [3]
        assert state.hypotheses == []
