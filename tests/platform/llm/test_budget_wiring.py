"""Tests for Phase 175 Plan 02 budget check wiring (LLM-COST-02).

Verifies that persist_cost_record calls check_monthly_budget after
successfully writing the cost record, and that the registry parameter
flows correctly from client.py through to budget_alert.py.

Tests:
  1. persist_cost_record with registry calls check_monthly_budget with correct args
  2. persist_cost_record with registry=None does NOT call check_monthly_budget
  3. persist_cost_record with team_id=None does NOT call check_monthly_budget
  4. check_monthly_budget failure does not prevent persist_cost_record from succeeding
  5. client.py passes registry=self._config._registry to persist_cost_record
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _AsyncRegistry:
    """Async ConfigRegistry stub for testing."""

    async def get(self, namespace: str, key: str) -> Any:
        return None


def _make_mock_session() -> AsyncMock:
    """AsyncMock session with sync .add() to avoid unawaited-coroutine warnings.

    SQLAlchemy session.add() is synchronous; AsyncMock makes it async by
    default, causing RuntimeWarning when called without await.
    """
    session = AsyncMock()
    session.add = MagicMock()  # sync -- matches real SQLAlchemy session.add()
    session.commit = AsyncMock()
    return session


# ---------------------------------------------------------------------------
# Test: persist_cost_record -> check_monthly_budget wiring
# ---------------------------------------------------------------------------


class TestPersistCostRecordBudgetWiring:
    """persist_cost_record calls check_monthly_budget after successful DB write."""

    @pytest.mark.asyncio
    async def test_with_registry_calls_check_monthly_budget(self) -> None:
        """When registry and team_id are both provided, check_monthly_budget is called."""
        registry = _AsyncRegistry()

        budget_check_mock = AsyncMock()
        mock_session = _make_mock_session()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_scope():
            yield mock_session

        # cost.py uses lazy `from aila.storage.database import async_session_scope`
        # inside the function body, so patch the source module.
        with patch("aila.storage.database.async_session_scope", mock_scope):
            with patch("aila.platform.llm.budget_alert.check_monthly_budget", budget_check_mock):
                from aila.platform.llm.cost import persist_cost_record
                await persist_cost_record(
                    run_id="run-01",
                    model_id="gpt-4o",
                    task_type="scoring",
                    team_id="team-wired",
                    prompt_tokens=100,
                    completion_tokens=50,
                    cost_usd=0.005,
                    registry=registry,
                )

        budget_check_mock.assert_awaited_once_with("team-wired", registry)

    @pytest.mark.asyncio
    async def test_without_registry_skips_check_monthly_budget(self) -> None:
        """When registry=None, check_monthly_budget is never called."""
        budget_check_mock = AsyncMock()
        mock_session = _make_mock_session()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_scope():
            yield mock_session

        with patch("aila.storage.database.async_session_scope", mock_scope):
            with patch("aila.platform.llm.budget_alert.check_monthly_budget", budget_check_mock):
                from aila.platform.llm.cost import persist_cost_record
                await persist_cost_record(
                    run_id="run-02",
                    model_id="gpt-4o",
                    task_type="scoring",
                    team_id="team-no-registry",
                    prompt_tokens=100,
                    completion_tokens=50,
                    cost_usd=0.005,
                    registry=None,  # No registry -- skip budget check
                )

        budget_check_mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_with_none_team_id_skips_check_monthly_budget(self) -> None:
        """When team_id=None, check_monthly_budget is not called even with registry."""
        registry = _AsyncRegistry()
        budget_check_mock = AsyncMock()
        mock_session = _make_mock_session()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_scope():
            yield mock_session

        with patch("aila.storage.database.async_session_scope", mock_scope):
            with patch("aila.platform.llm.budget_alert.check_monthly_budget", budget_check_mock):
                from aila.platform.llm.cost import persist_cost_record
                await persist_cost_record(
                    run_id="run-03",
                    model_id="gpt-4o",
                    task_type="scoring",
                    team_id=None,  # No team -- skip budget check
                    prompt_tokens=100,
                    completion_tokens=50,
                    cost_usd=0.005,
                    registry=registry,
                )

        budget_check_mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_budget_check_failure_does_not_prevent_persist_success(self) -> None:
        """When check_monthly_budget raises, persist_cost_record does not re-raise it.

        The budget check is called from inside the try/except that wraps
        persist_cost_record's DB write.  check_monthly_budget itself also
        swallows exceptions, but even if it leaks one, persist_cost_record
        catches it at the outer level (fire-and-forget).
        """
        registry = _AsyncRegistry()
        committed = []
        mock_session = _make_mock_session()

        async def _commit():
            committed.append(True)

        mock_session.commit.side_effect = _commit

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_scope():
            yield mock_session

        # Simulate a leaking budget check exception
        async def _raise_budget(*args, **kwargs):
            raise RuntimeError("budget check exploded")

        with patch("aila.storage.database.async_session_scope", mock_scope):
            with patch("aila.platform.llm.budget_alert.check_monthly_budget", side_effect=_raise_budget):
                from aila.platform.llm.cost import persist_cost_record
                # Must NOT raise -- fire-and-forget wrapper catches it
                await persist_cost_record(
                    run_id="run-04",
                    model_id="gpt-4o",
                    task_type="scoring",
                    team_id="team-budget-err",
                    prompt_tokens=50,
                    completion_tokens=25,
                    cost_usd=0.002,
                    registry=registry,
                )

        # DB commit still happened before the budget check failure
        assert len(committed) == 1


# ---------------------------------------------------------------------------
# Test: client.py passes registry to persist_cost_record
# ---------------------------------------------------------------------------


class TestClientRegistryPassthrough:
    """client.py wires self._config._registry into persist_cost_record."""

    def _make_canned_completion(
        self,
        content: str = "ok",
        prompt_tokens: int = 10,
        completion_tokens: int = 5,
    ) -> MagicMock:
        usage_mock = MagicMock()
        usage_mock.prompt_tokens = prompt_tokens
        usage_mock.completion_tokens = completion_tokens
        usage_mock.total_tokens = prompt_tokens + completion_tokens
        message = MagicMock()
        message.content = content
        message.tool_calls = []
        choice = MagicMock()
        choice.message = message
        choice.finish_reason = "stop"
        completion = MagicMock()
        completion.choices = [choice]
        completion.usage = usage_mock
        return completion

    @pytest.mark.asyncio
    async def test_client_passes_registry_to_persist_cost_record(self) -> None:
        """After a successful LLM call, persist_cost_record receives registry=self._config._registry."""
        from aila.platform.llm.client import AilaLLMClient
        from aila.platform.llm.config import LLMRouting

        registry = _AsyncRegistry()
        secret_store = MagicMock()
        secret_store.resolve_provider_secret = AsyncMock(return_value="sk-test")

        client = AilaLLMClient(registry=registry, secret_store=secret_store)  # type: ignore[arg-type]
        routing = LLMRouting(
            model_id="gpt-4o",
            base_url="https://test.example.com",
            api_key="sk-test",
            max_tokens=1000,
            temperature=0.0,
            max_tool_steps=0,
            task_type="scoring",
        )
        client._config.is_disabled = AsyncMock(return_value=False)
        client._config.resolve_routing = AsyncMock(return_value=routing)

        completion = self._make_canned_completion()
        persist_mock = AsyncMock()

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            MockOAI.return_value = mock_instance

            with patch("aila.platform.llm.cost.persist_cost_record", persist_mock):
                with patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(return_value=(0.005, True))):
                    await client.chat(
                        "scoring",
                        [{"role": "user", "content": "test"}],
                        team_id="team-passthrough",
                    )

        persist_mock.assert_awaited_once()
        kwargs = persist_mock.call_args.kwargs
        # registry must be the same ConfigRegistry instance the client holds
        assert kwargs.get("registry") is client._config._registry
