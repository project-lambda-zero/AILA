"""Operator intent classifier tests.

Deterministic -- no LLM calls. Each test pins a specific operator phrasing
to its expected OperatorIntent so the heuristic rule table can be edited
without silent regressions.
"""
from __future__ import annotations

import pytest

from aila.modules.vr.agents.intent_classifier import classify_intent
from aila.modules.vr.contracts import OperatorIntent


class TestBranchCommands:
    @pytest.mark.parametrize("text", [
        "stop that branch",
        "pause the investigation",
        "resume it",
        "abort and start over",
        "kill the variant hunt",
        "fork from this point",
        "merge h2 into mainline",
        "abandon h3",
        "promote branch alpha to primary",
    ])
    def test_branch_keywords(self, text: str) -> None:
        assert classify_intent(text) == OperatorIntent.BRANCH_COMMAND


class TestOutcomeSelection:
    @pytest.mark.parametrize("text", [
        "promote h3 as the finding",
        "pick outcome 2",
        "select finding for disclosure",
        "accept hypothesis h7",
        "finalize memo m4",
        "publish the audit memo",
    ])
    def test_outcome_keywords(self, text: str) -> None:
        assert classify_intent(text) == OperatorIntent.OUTCOME_SELECTION


class TestDismissal:
    @pytest.mark.parametrize("text", [
        "ignore that finding",
        "skip the next step",
        "drop h2",
        "discard the suggestion",
        "reject that hypothesis",
        "never mind that idea",
        "forget the previous direction",
    ])
    def test_dismissal_keywords(self, text: str) -> None:
        assert classify_intent(text) == OperatorIntent.DISMISSAL


class TestCorrection:
    @pytest.mark.parametrize("text", [
        "you're wrong about the alias check",
        "you are wrong",
        "that's wrong",
        "that is wrong",
        "you missed the bounds check",
        "actually no, look upstream",
        "actually, the encoder runs after",
        "incorrect -- the field is signed",
        "no, the dispatcher returns void",
    ])
    def test_correction_keywords(self, text: str) -> None:
        assert classify_intent(text) == OperatorIntent.CORRECTION


class TestSteering:
    @pytest.mark.parametrize("text", [
        "look at the parse_header function",
        "focus on the recv path",
        "try the variant hunt strategy",
        "instead use the source MCP",
        "check out the http parser",
        "consider the integer overflow angle",
        "investigate the wasm path",
        "explore the prototype chain",
        "pivot to the renderer process",
    ])
    def test_steering_keywords(self, text: str) -> None:
        assert classify_intent(text) == OperatorIntent.STEERING


class TestQuestion:
    @pytest.mark.parametrize("text", [
        "what does that flag do?",
        "Why did you reject h2?",
        "how does the dispatcher route?",
        "when was that patch landed?",
        "where is the call site?",
        "which version is this?",
        "who maintains this module?",
        "is it really uninitialised?",
        "does it overflow at zero?",
        "can you check the bounds?",
    ])
    def test_wh_words(self, text: str) -> None:
        assert classify_intent(text) == OperatorIntent.QUESTION

    @pytest.mark.parametrize("text", [
        "the parser is utf8?",
        "that flag set?",
    ])
    def test_trailing_question_mark(self, text: str) -> None:
        assert classify_intent(text) == OperatorIntent.QUESTION


class TestUnclassified:
    @pytest.mark.parametrize("text", [
        "",
        "   ",
        "thanks",
        "ok",
        "interesting",
        "go ahead",
    ])
    def test_no_keyword_match(self, text: str) -> None:
        assert classify_intent(text) == OperatorIntent.UNCLASSIFIED

    def test_none_input(self) -> None:
        assert classify_intent(None) == OperatorIntent.UNCLASSIFIED  # type: ignore[arg-type]


class TestRulePriority:
    """Earlier rules in _RULES take precedence -- these tests pin behavior."""

    def test_stop_and_look_at_x_is_branch_command(self) -> None:
        # 'stop' wins over 'look at' because branch commands come first
        assert (
            classify_intent("stop and look at parse_header")
            == OperatorIntent.BRANCH_COMMAND
        )

    def test_promote_outcome_wins_over_steering(self) -> None:
        # 'promote outcome' is matched as OUTCOME_SELECTION before STEERING
        # (which has no 'promote' keyword anyway, but verifying explicit order)
        assert (
            classify_intent("promote outcome 1 and look at next")
            == OperatorIntent.OUTCOME_SELECTION
        )

    def test_dismissal_wins_over_correction(self) -> None:
        # 'ignore that you missed it' → DISMISSAL (ignore matched first)
        assert (
            classify_intent("ignore the fact that you missed the check")
            == OperatorIntent.DISMISSAL
        )
