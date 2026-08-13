"""turn_runner: defense-check gate writes rejection directive to observables.

Regression guard for AILA-97 / RFC #208 P0: the defense-check submit gate
tried to record its rejection reason with ``case_state["_directive.defense_check_rejected"] = _reject``.
``case_state`` is a ``ReasoningCaseState`` Pydantic BaseModel with no
``__setitem__``, so every rejection raised ``TypeError`` from ``run_turn``,
crashed the branch turn instead of steering the agent, and the rejection
reason never reached the next prompt's directive section.

The fix writes to ``case_state.observables[...]`` (matching the adjacent
empty-tool-run coerce directive one branch below in the same method).

This test drives ``AgentTurnRunnerBase.run_turn`` through a forced
defense-check rejection with a minimal stub subclass. Every dependency
above the gate is either a default no-op on the base class or stubbed
here; ``UnitOfWork``, ``lookup_cached_response``, and
``check_defense_verification`` are monkeypatched so the test is DB-free.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from aila.platform.agents import submit_gates, turn_runner
from aila.platform.agents.turn_runner import AgentTurnRunnerBase
from aila.platform.contracts.reasoning import (
    ReasoningCaseState,
    ReasoningTurnDecision,
)


class _ResearcherError(Exception):
    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class _CapturedCaseState(Exception):
    """Sentinel: short-circuit run_turn AFTER the defense-check gate ran.

    Raised from an override of the next hook (``_maybe_reject_fanout_submit``)
    so the test can inspect ``case_state.observables`` at exactly the point
    where the buggy line raised TypeError, and no further stubs are needed
    for the message-write / outcome-upsert plumbing below.
    """

    def __init__(self, case_state: ReasoningCaseState, decision: Any) -> None:
        super().__init__("captured")
        self.case_state = case_state
        self.decision = decision


class _SubmittingEngine:
    """Returns a terminal submit decision so the gate chain fires."""

    async def decide_next_turn(self, **_kwargs: Any) -> ReasoningTurnDecision:
        return ReasoningTurnDecision(
            reasoning="claim ready",
            action="submit",
            answer="Integer overflow in the allocation path.",
        )

    async def resolve_model_family(self, _task_type: str) -> None:
        return None


class _StubMessageModel:
    __tablename__ = "vr_investigation_messages"


class _StubRunner(AgentTurnRunnerBase):
    """Minimal concrete runner that reaches the defense-check gate."""

    _LOG_LABEL = "test"

    def __init__(self) -> None:
        self.investigation_id = "inv-test"
        self.branch_id = "branch-test"
        self._engine = _SubmittingEngine()
        self._applicable_patterns: list[Any] = []
        self._error_cls = _ResearcherError
        self._message_model = _StubMessageModel

    # Staticmethod-bound helpers on real subclasses; bare methods here.
    def _terminal_outcome_kind(self, _decision: Any) -> Any:
        return SimpleNamespace(value="direct_finding")

    def _outcome_payload(self, _decision: Any) -> dict[str, Any]:
        return {}

    # ---- gates upstream of the defense-check: allow-through stubs ----

    async def _maybe_reject_submit_when_draft_pending(
        self, *, decision: Any, case_state: Any, turn_number: int,
    ) -> Any:
        del case_state, turn_number
        return decision

    async def _maybe_reject_revote_when_already_voted(
        self, *, decision: Any, case_state: Any, turn_number: int,
    ) -> Any:
        del case_state, turn_number
        return decision

    def _maybe_reject_submit_with_unresolved_hypotheses(
        self, *, decision: Any, case_state: Any, turn_number: int,
    ) -> Any:
        del case_state, turn_number
        return decision

    # ---- gate DOWNSTREAM of the defense-check: capture + short-circuit ----

    def _maybe_reject_fanout_submit(
        self, *, decision: Any, inv: Any, case_state: Any, turn_number: int,
    ) -> Any:
        del inv, turn_number
        raise _CapturedCaseState(case_state, decision)

    # ---- shared instance methods run_turn expects ----

    async def _load(self) -> tuple[Any, Any, dict[str, Any]]:
        inv = SimpleNamespace(id=self.investigation_id, strategy_family="scoring")
        branch = SimpleNamespace(
            id=self.branch_id,
            case_state_json=None,
            turn_count=0,
            persona_voice=None,
        )
        return inv, branch, {}

    async def _consume_pending_operator_messages(self, _turn: int) -> list[Any]:
        return []

    async def _load_prior_outcomes(self) -> list[Any]:
        return []

    async def _load_sibling_context(self) -> list[dict[str, Any]]:
        return []

    async def _load_ledger_board(self) -> str:
        return ""

    async def _load_prompt(
        self, _family: Any, _persona: Any, *,
        investigation_id: Any = None, model_family: Any = None,
    ) -> Any:
        del investigation_id, model_family
        return SimpleNamespace(body="system prompt", version=None, canary_key=None)

    async def _fetch_tool_specs(
        self, *, target_kind: Any = None, primary_language: Any = None,
    ) -> list[Any]:
        del target_kind, primary_language
        return []

    def _build_user_prompt(self, **_kwargs: Any) -> str:
        return "user prompt"

    def _resolve_task_type(self, _persona: Any) -> str:
        return "scoring"


class _FakeSession:
    async def execute(self, _stmt: Any) -> Any:
        # Not reached: check_defense_verification is monkeypatched.
        raise AssertionError("session.execute should not be called")


class _FakeUoW:
    """Async context manager matching UnitOfWork's shape for the paths we hit."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.session = _FakeSession()

    async def __aenter__(self) -> "_FakeUoW":
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        return None


def _install_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch UoW, cache lookup, and the defense-check helper."""
    monkeypatch.setattr(turn_runner, "UnitOfWork", _FakeUoW)

    async def _no_cache(_session: Any, _key: str) -> None:
        return None
    monkeypatch.setattr(turn_runner, "lookup_cached_response", _no_cache)

    _reject_reason = "test: allocator/input-reader/callers_of check failed"

    async def _force_reject(**_kwargs: Any) -> tuple[bool, str]:
        return (False, _reject_reason)
    # Import inside the method body resolves against the source module.
    monkeypatch.setattr(
        submit_gates, "check_defense_verification", _force_reject,
    )


@pytest.mark.asyncio
async def test_defense_check_rejection_writes_directive_to_observables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fixed code: rejection reason lands in case_state.observables and
    the decision is downgraded to ``reasoning`` without raising TypeError.

    Fails on the pre-fix line ``case_state["_directive..."] = _reject``
    with ``TypeError: 'ReasoningCaseState' object does not support item
    assignment``.
    """
    _install_stubs(monkeypatch)
    runner = _StubRunner()

    with pytest.raises(_CapturedCaseState) as excinfo:
        await runner.run_turn()

    captured = excinfo.value
    # (a) No TypeError -- the sentinel from the downstream hook fired.
    # (b) The decision was downgraded to reasoning by the gate.
    assert captured.decision.action == "reasoning"
    # (c) The rejection reason was recorded on the observables mapping,
    #     not attempted as a dict-subscript on the BaseModel itself.
    assert (
        captured.case_state.observables["_directive.defense_check_rejected"]
        == "test: allocator/input-reader/callers_of check failed"
    )


def test_reasoning_case_state_rejects_dict_subscript() -> None:
    """Locks in why the pre-fix line raised: ReasoningCaseState is a
    Pydantic BaseModel with no ``__setitem__``. Any future refactor that
    reintroduces a dict-subscript write on ``case_state`` MUST route
    through ``case_state.observables`` instead.
    """
    cs = ReasoningCaseState()
    with pytest.raises(TypeError):
        cs["_directive.defense_check_rejected"] = "x"  # type: ignore[index]
