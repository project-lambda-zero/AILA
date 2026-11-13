"""Unresolved-hypothesis submit gate: folding a hypothesis into the answer resolves it.

Issue #300. The directive offers "fold the hypothesis into your answer" as a
way to clear the gate, so a live hypothesis cited as an exact id token in
``decision.answer`` must count as resolved, the same as one in
``decision.rejected[]``.
"""

from __future__ import annotations

import pytest

from aila.modules.malware.agents.malware_researcher import HonestMalwareResearcher
from aila.modules.vr.agents.vuln_researcher import HonestVulnResearcher
from aila.platform.contracts.reasoning import (
    EvidenceProvenance,
    Hypothesis,
    ReasoningCaseState,
    ReasoningTurnDecision,
    RejectedHypothesis,
)

_COUNTER_KEY = "_unresolved_hyp_submit_rejected_count"
_DIRECTIVE_KEY = "_directive.unresolved_hyp_submit_rejected"

_RESEARCHERS = {"vr": HonestVulnResearcher, "malware": HonestMalwareResearcher}


@pytest.fixture(params=sorted(_RESEARCHERS))
def researcher(request: pytest.FixtureRequest):
    cls = _RESEARCHERS[request.param]
    r = cls(reasoning_engine=None, investigation_id="inv-test", branch_id="br-test")
    r._unresolved_hyp_reject_cap = 3
    return r


def _case(*ids: str) -> ReasoningCaseState:
    return ReasoningCaseState(
        hypotheses=[
            Hypothesis(id=i, claim=f"claim {i}", why_plausible="why", kill_criterion="kill")
            for i in ids
        ],
    )


def _submit(
    answer: str | None,
    rejected: tuple[str, ...] = (),
) -> ReasoningTurnDecision:
    return ReasoningTurnDecision(
        reasoning="test",
        action="submit",
        answer=answer,
        confidence="strong",
        provenance=EvidenceProvenance(),
        rejected=[RejectedHypothesis(id=i, claim=f"claim {i}", reason="r") for i in rejected],
        payload={},
    )


def _gate(researcher, case: ReasoningCaseState, decision: ReasoningTurnDecision):
    return researcher._maybe_reject_submit_with_unresolved_hypotheses(
        decision=decision,
        case_state=case,
        turn_number=1,
    )


def _assert_passed(result, decision, case: ReasoningCaseState) -> None:
    assert result is decision
    assert _COUNTER_KEY not in case.observables
    assert _DIRECTIVE_KEY not in case.observables


def _assert_rejected(result, case: ReasoningCaseState) -> None:
    assert result.action == "tool_run"
    assert case.observables[_COUNTER_KEY] == 1
    assert _DIRECTIVE_KEY in case.observables


@pytest.mark.parametrize(
    "answer",
    [
        "h1",
        "(h1)",
        "h1.",
        "h1,",
        "Confirmed: h1 is exploitable through the parser.",
    ],
)
def test_exact_citation_in_answer_resolves_live_hypothesis(researcher, answer: str) -> None:
    case = _case("h1")
    decision = _submit(answer)

    result = _gate(researcher, case, decision)

    _assert_passed(result, decision, case)


@pytest.mark.parametrize("answer", ["h10 is the live path", "h1_b is the live path",
                                    "xh1 is the live path", "h1-b is the live path",
                                    "H1 is the live path", "no hypothesis cited"])
def test_non_exact_mention_does_not_resolve_live_hypothesis(researcher, answer: str) -> None:
    case = _case("h1")
    decision = _submit(answer)

    result = _gate(researcher, case, decision)

    _assert_rejected(result, case)


def test_no_citation_and_no_rejection_rejects(researcher) -> None:
    case = _case("h1")
    decision = _submit("the answer says nothing about hypotheses")

    result = _gate(researcher, case, decision)

    _assert_rejected(result, case)


def test_rejected_id_still_resolves_with_no_answer(researcher) -> None:
    case = _case("h1")
    decision = _submit(None, rejected=("h1",))

    result = _gate(researcher, case, decision)

    _assert_passed(result, decision, case)


def test_rejected_and_cited_ids_together_resolve_all_live_hypotheses(researcher) -> None:
    case = _case("h1", "h2")
    decision = _submit("h2 is the root cause", rejected=("h1",))

    result = _gate(researcher, case, decision)

    _assert_passed(result, decision, case)


def test_one_uncited_hypothesis_still_rejects(researcher) -> None:
    case = _case("h1", "h2")
    decision = _submit("h1 is the root cause")

    result = _gate(researcher, case, decision)

    _assert_rejected(result, case)


def test_non_string_answer_rejects_without_crashing(researcher) -> None:
    case = _case("h1")
    decision = _submit(None)

    result = _gate(researcher, case, decision)

    _assert_rejected(result, case)


def test_passing_submit_clears_stale_rejection_state(researcher) -> None:
    case = _case("h1")
    case.observables[_COUNTER_KEY] = 2
    case.observables[_DIRECTIVE_KEY] = "stale directive"
    decision = _submit("h1 holds")

    result = _gate(researcher, case, decision)

    _assert_passed(result, decision, case)
