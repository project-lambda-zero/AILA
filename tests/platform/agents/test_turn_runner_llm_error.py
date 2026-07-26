"""turn_runner wraps an engine LLMError as the module error class.

Regression guard for the dispatch-hub wiring bug: a non-retryable
provider ``LLMError`` raised from ``decide_next_turn`` must surface as the
module ``_error_cls`` (researcher_error) so the investigation loop keeps
the investigation RUNNING and auto_continue re-enqueues the branch.

Before the fix, ``LLMError`` was absent from the except tuple in
``run_turn`` (it is a direct ``Exception`` subclass, not ``OSError`` /
``RuntimeError`` / etc.), so it escaped ``run_turn`` uncaught, crashed the
phase state, failed the task, and flipped the whole investigation to
FAILED, starving every sibling branch at setup STATUS_LOCKED.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from aila.platform.agents.turn_runner import AgentTurnRunnerBase
from aila.platform.llm.errors import LLMError


class _ResearcherError(Exception):
    """Stand-in for a module ``researcher_error`` class."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class _RaisingEngine:
    async def decide_next_turn(self, **_kwargs: Any) -> Any:
        raise LLMError(
            "provider rejected request: model unavailable (400)",
            retryable=False,
        )


class _StubRunner(AgentTurnRunnerBase):
    """Minimal concrete runner that reaches the engine call and no further."""

    _LOG_LABEL = "test"

    def __init__(self) -> None:
        self.investigation_id = "inv-test"
        self.branch_id = "branch-test"
        self._engine = _RaisingEngine()
        self._applicable_patterns: list[Any] = []
        self._error_cls = _ResearcherError

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
        self, _family: Any, _persona: Any, *, investigation_id: Any = None,
    ) -> Any:
        del investigation_id
        return SimpleNamespace(body="system prompt", version=None)

    async def _fetch_tool_specs(
        self, *, target_kind: Any = None, primary_language: Any = None,
    ) -> list[Any]:
        del target_kind, primary_language
        return []

    def _build_user_prompt(self, **_kwargs: Any) -> str:
        return "user prompt"

    def _resolve_task_type(self, _persona: Any) -> str:
        return "scoring"


@pytest.mark.usefixtures("test_db")
async def test_engine_llm_error_wrapped_as_module_error() -> None:
    runner = _StubRunner()
    with pytest.raises(_ResearcherError) as excinfo:
        await runner.run_turn()
    assert "engine.decide_next_turn failed" in str(excinfo.value)
    # The original LLMError is chained so the traceback keeps the provider
    # message for the operator-private worker log.
    assert isinstance(excinfo.value.__cause__, LLMError)


def test_llm_error_is_not_a_builtin_error_subclass() -> None:
    # Locks in why LLMError needs explicit listing in the except tuple:
    # it is a direct Exception subclass, so the pre-fix tuple of builtin
    # error types could never have caught it.
    assert issubclass(LLMError, Exception)
    assert not issubclass(
        LLMError,
        (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError),
    )
