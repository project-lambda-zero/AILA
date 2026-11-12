"""Forensics persists revival history across applied turn state (#301).

``HonestInvestigator._run_turn`` absorbs through the shared engine and
then writes the result back with ``_apply_case_state``. The once-only
revival rule depends on ``revived_hypothesis_ids`` surviving that
round-trip; dropping it lets a terminal id revive once per turn.

Exercised without database, SSH, or network access: the engine's
``absorb`` makes no LLM call, so the engine is built without a client.
"""
from __future__ import annotations

from aila.modules.forensics.agents.investigator import HonestInvestigator
from aila.platform.contracts.reasoning import (
    Hypothesis,
    ReasoningCaseState,
    ReasoningTurnDecision,
    RejectedHypothesis,
)
from aila.platform.services.reasoning import CyberReasoningEngine


def _investigator() -> HonestInvestigator:
    inv = HonestInvestigator.__new__(HonestInvestigator)
    inv.investigation_id = "inv-test-301"
    inv.reasoning_engine = CyberReasoningEngine(None)  # type: ignore[arg-type]
    inv.contract = {}
    inv.hypotheses = []
    inv.rejected = []
    inv.resolved = []
    inv.observables = {}
    inv.revived_hypothesis_ids = []
    return inv


def _run_turn(inv: HonestInvestigator, decision: ReasoningTurnDecision, turn: int) -> None:
    """Mirror the ``_run_turn`` absorb + apply sequence."""
    case_state = inv._case_state()
    case_state = inv.reasoning_engine.absorb(case_state, decision, turn_number=turn)
    inv._apply_case_state(case_state)


def test_repeated_reject_and_reemit_revives_terminal_id_only_once() -> None:
    inv = _investigator()
    inv._apply_case_state(ReasoningCaseState(
        rejected=[RejectedHypothesis(id="H1", claim="c", reason="r")],
    ))

    _run_turn(inv, ReasoningTurnDecision(
        reasoning="first evidence-backed re-emit",
        action="reasoning",
        hypotheses=[Hypothesis(id="H1", claim="c", confirmed_by="src/a.py:1")],
    ), turn=2)
    assert [h["id"] for h in inv.hypotheses] == ["H1"]
    assert inv.rejected == []
    assert inv.revived_hypothesis_ids == ["H1"]
    assert inv._case_state().revived_hypothesis_ids == ["H1"]

    _run_turn(inv, ReasoningTurnDecision(
        reasoning="reject again",
        action="reasoning",
        rejected=[RejectedHypothesis(id="H1", claim="c", reason="disproved")],
    ), turn=3)
    assert inv.hypotheses == []
    assert [r["id"] for r in inv.rejected] == ["H1"]

    _run_turn(inv, ReasoningTurnDecision(
        reasoning="second evidence-backed re-emit",
        action="reasoning",
        hypotheses=[Hypothesis(id="H1", claim="c", confirmed_by="src/a.py:2")],
    ), turn=4)
    assert inv.hypotheses == []
    assert [r["id"] for r in inv.rejected] == ["H1"]
    assert inv.revived_hypothesis_ids == ["H1"]
