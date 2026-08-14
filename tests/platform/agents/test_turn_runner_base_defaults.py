"""Safe default implementations of the three submit-gate hooks (#168).

Prior to the fix, ``AgentTurnRunnerBase`` referenced
``_maybe_reject_submit_when_draft_pending``,
``_maybe_reject_revote_when_already_voted``, and
``_maybe_reject_submit_with_unresolved_hypotheses`` without providing
default implementations. Any module built off the ``_template`` scaffold
(which does not override them) crashed with ``AttributeError`` the
moment its researcher processed a ``submit`` decision.

The base now defines all three as no-ops that return the incoming
decision unchanged, matching the ``_maybe_reject_fanout_submit`` /
``_maybe_reject_no_finding_while_sibling_open_hyp`` pattern. This test
locks the safe-default contract in place.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

from aila.modules._template.agents.researcher import TemplateResearcher
from aila.platform.agents.turn_runner import AgentTurnRunnerBase


class _MinimalRunner(AgentTurnRunnerBase):
    """A subclass with zero gate overrides -- what ``_template`` becomes."""

    _LOG_LABEL = "test"


def _sentinel_decision() -> SimpleNamespace:
    """A stand-in decision object -- the base hooks NEVER inspect it."""
    return SimpleNamespace(action="submit", marker="unchanged")


def test_maybe_reject_submit_when_draft_pending_default_allows() -> None:
    runner = _MinimalRunner.__new__(_MinimalRunner)
    decision = _sentinel_decision()
    result = asyncio.run(
        runner._maybe_reject_submit_when_draft_pending(
            decision=decision, case_state=None, turn_number=1,
        )
    )
    assert result is decision


def test_maybe_reject_revote_when_already_voted_default_allows() -> None:
    runner = _MinimalRunner.__new__(_MinimalRunner)
    decision = _sentinel_decision()
    result = asyncio.run(
        runner._maybe_reject_revote_when_already_voted(
            decision=decision, case_state=None, turn_number=1,
        )
    )
    assert result is decision


def test_maybe_reject_submit_with_unresolved_hypotheses_default_allows() -> None:
    runner = _MinimalRunner.__new__(_MinimalRunner)
    decision = _sentinel_decision()
    result = runner._maybe_reject_submit_with_unresolved_hypotheses(
        decision=decision, case_state=None, turn_number=1,
    )
    assert result is decision


def test_template_module_researcher_inherits_safe_defaults() -> None:
    """The actual ``_template`` researcher must inherit the no-ops.

    Guards against a future regression where the base class loses the
    defaults or the ``_template`` module starts overriding them
    incompletely.
    """
    assert (
        TemplateResearcher._maybe_reject_submit_when_draft_pending
        is AgentTurnRunnerBase._maybe_reject_submit_when_draft_pending
    )
    assert (
        TemplateResearcher._maybe_reject_revote_when_already_voted
        is AgentTurnRunnerBase._maybe_reject_revote_when_already_voted
    )
    assert (
        TemplateResearcher._maybe_reject_submit_with_unresolved_hypotheses
        is AgentTurnRunnerBase._maybe_reject_submit_with_unresolved_hypotheses
    )
