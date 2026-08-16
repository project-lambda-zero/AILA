"""Forensics free-flow closure discipline (issue #175).

Covers the platform-parity wiring landed in
``HonestInvestigator._maybe_reject_submit_with_unresolved_hypotheses``
and the terminal-submit auto-resolve, exercised without database or
network access:

* The gate returns ``None`` (submit allowed) when every live hypothesis
  is either in ``decision.rejected[]`` or named verbatim in the answer
  text.
* The gate returns a rejection reason (submit refused) and stamps
  ``_directive.unresolved_hyp_submit_rejected`` on
  ``case_state.observables`` when a live hypothesis is unresolved.
* Consecutive rejections increment ``_unresolved_hyp_gate_rejects``;
  the (cap+1)th call passes through with the directive cleared so the
  caller can force the submit through and stamp the advisory on the
  provenance.
* :func:`auto_resolve_live_on_terminal` moves every still-live
  hypothesis into ``state.resolved`` with a note pointing at the
  terminal outcome kind (parity with vr / malware).
"""
from __future__ import annotations

import asyncio

import pytest

from aila.modules.forensics.agents.investigator import HonestInvestigator
from aila.platform.agents.turn_helpers import auto_resolve_live_on_terminal
from aila.platform.contracts.reasoning import (
    EvidenceProvenance,
    Hypothesis,
    ReasoningCaseState,
    ReasoningContract,
    ReasoningTurnDecision,
    RejectedHypothesis,
)


def _bare_investigator(cap: int = 3) -> HonestInvestigator:
    """Return an investigator with the instance attributes the gate reads.

    Skips ``__init__`` because the gate is pure (no DB, no SSH, no
    engine); construction would otherwise demand a Settings + engine +
    integration bag. Pre-populates ``_unresolved_hyp_reject_cap`` so
    the gate does not hit the async ConfigRegistry read.
    """
    inv = HonestInvestigator.__new__(HonestInvestigator)
    inv.investigation_id = "inv-test-175"
    inv._unresolved_hyp_reject_cap = cap
    inv._unresolved_hyp_gate_rejects = 0
    return inv


def _decision(answer: str, rejected_ids: list[str]) -> ReasoningTurnDecision:
    return ReasoningTurnDecision(
        reasoning="test",
        contract=ReasoningContract(),
        action="submit",
        answer=answer,
        confidence="medium",
        provenance=EvidenceProvenance(primary_artifact="a1"),
        rejected=[
            RejectedHypothesis(id=hid, claim=f"claim-{hid}", reason="test")
            for hid in rejected_ids
        ],
    )


def _case_state(live_ids: list[str]) -> ReasoningCaseState:
    return ReasoningCaseState(
        contract=ReasoningContract(),
        hypotheses=[
            Hypothesis(id=hid, claim=f"claim-{hid}", kill_criterion="k")
            for hid in live_ids
        ],
    )


def test_gate_allows_when_every_live_id_is_rejected() -> None:
    inv = _bare_investigator()
    case_state = _case_state(["h1", "h2"])
    decision = _decision(answer="root cause: X", rejected_ids=["h1", "h2"])
    result = asyncio.run(
        inv._maybe_reject_submit_with_unresolved_hypotheses(
            decision=decision, case_state=case_state,
            answer="root cause: X", turn=5,
        )
    )
    assert result is None
    assert inv._unresolved_hyp_gate_rejects == 0
    assert (
        "_directive.unresolved_hyp_submit_rejected"
        not in case_state.observables
    )


def test_gate_allows_when_live_id_named_in_answer() -> None:
    inv = _bare_investigator()
    case_state = _case_state(["h1"])
    decision = _decision(answer="finding folds h1 into the answer", rejected_ids=[])
    result = asyncio.run(
        inv._maybe_reject_submit_with_unresolved_hypotheses(
            decision=decision, case_state=case_state,
            answer="finding folds h1 into the answer", turn=5,
        )
    )
    assert result is None


def test_gate_rejects_when_live_id_neither_rejected_nor_named() -> None:
    inv = _bare_investigator(cap=3)
    case_state = _case_state(["h1", "h2"])
    decision = _decision(answer="root cause: something else", rejected_ids=[])
    result = asyncio.run(
        inv._maybe_reject_submit_with_unresolved_hypotheses(
            decision=decision, case_state=case_state,
            answer="root cause: something else", turn=5,
        )
    )
    assert result is not None
    assert "h1" in result or "h2" in result
    assert inv._unresolved_hyp_gate_rejects == 1
    directive = case_state.observables.get(
        "_directive.unresolved_hyp_submit_rejected",
    )
    assert isinstance(directive, str)
    assert "SUBMIT REJECTED" in directive
    assert "h1" in directive and "h2" in directive


def test_gate_disabled_when_cap_zero() -> None:
    inv = _bare_investigator(cap=0)
    case_state = _case_state(["h1"])
    decision = _decision(answer="whatever", rejected_ids=[])
    result = asyncio.run(
        inv._maybe_reject_submit_with_unresolved_hypotheses(
            decision=decision, case_state=case_state,
            answer="whatever", turn=1,
        )
    )
    assert result is None
    assert inv._unresolved_hyp_gate_rejects == 0


def test_gate_force_through_after_cap_rejections() -> None:
    inv = _bare_investigator(cap=2)
    case_state = _case_state(["h1"])
    decision = _decision(answer="finding", rejected_ids=[])
    # First rejection.
    r1 = asyncio.run(
        inv._maybe_reject_submit_with_unresolved_hypotheses(
            decision=decision, case_state=case_state,
            answer="finding", turn=1,
        )
    )
    assert r1 is not None
    assert inv._unresolved_hyp_gate_rejects == 1
    # Second rejection lands at the cap and still refuses.
    r2 = asyncio.run(
        inv._maybe_reject_submit_with_unresolved_hypotheses(
            decision=decision, case_state=case_state,
            answer="finding", turn=2,
        )
    )
    assert r2 is not None
    assert inv._unresolved_hyp_gate_rejects == 2
    # Third attempt crosses the cap: gate passes and clears the directive
    # so the caller can force through and stamp the advisory on the
    # provenance.
    r3 = asyncio.run(
        inv._maybe_reject_submit_with_unresolved_hypotheses(
            decision=decision, case_state=case_state,
            answer="finding", turn=3,
        )
    )
    assert r3 is None
    assert inv._unresolved_hyp_gate_rejects == 3
    # Directive is cleared on the force-through pass.
    assert (
        "_directive.unresolved_hyp_submit_rejected"
        not in case_state.observables
    )


def test_gate_clears_directive_when_no_live_hypotheses() -> None:
    inv = _bare_investigator()
    case_state = _case_state([])
    case_state.observables["_directive.unresolved_hyp_submit_rejected"] = (
        "stale directive"
    )
    decision = _decision(answer="clean submit", rejected_ids=[])
    result = asyncio.run(
        inv._maybe_reject_submit_with_unresolved_hypotheses(
            decision=decision, case_state=case_state,
            answer="clean submit", turn=1,
        )
    )
    assert result is None
    assert (
        "_directive.unresolved_hyp_submit_rejected"
        not in case_state.observables
    )


def test_auto_resolve_moves_live_hypotheses_to_resolved() -> None:
    """Platform helper parity: at terminal submit, live hypotheses that
    the agent did not explicitly close land in ``state.resolved`` with a
    neutral note pointing at the terminal outcome kind. The frontend
    then renders them with a neutral badge instead of showing live
    claims under a completed investigation.
    """
    state = _case_state(["h1", "h2"])
    auto_resolve_live_on_terminal(state, turn=7, outcome_kind="hash")
    assert state.hypotheses == []
    assert {r.id for r in state.resolved} == {"h1", "h2"}
    for r in state.resolved:
        assert r.resolved_at_turn == 7
        assert r.terminal_outcome_kind == "hash"
        assert "auto-resolved at turn 7" in r.note


def test_auto_resolve_noop_when_no_live_hypotheses() -> None:
    state = _case_state([])
    auto_resolve_live_on_terminal(state, turn=1, outcome_kind="answer")
    assert state.hypotheses == []
    assert state.resolved == []


@pytest.mark.parametrize("outcome_kind", ["filename", "hash", "ip:port", "technique"])
def test_auto_resolve_carries_outcome_kind(outcome_kind: str) -> None:
    state = _case_state(["h1"])
    auto_resolve_live_on_terminal(state, turn=3, outcome_kind=outcome_kind)
    assert state.resolved[0].terminal_outcome_kind == outcome_kind
