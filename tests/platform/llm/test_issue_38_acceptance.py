"""Acceptance tests for issue #38 (LLM cost + budget correctness).

Covers the six-finding audit; each finding gets one focused test.

  #1  ``CostTracker._resolve_ceiling`` uses the sync registry twin and
      actually enforces the token ceiling (previously an un-awaited
      coroutine slipped through and disabled enforcement).
  #2  ``AilaLLMClient._inner_call`` (consensus + verify path) records
      cost WITH ``team_id`` AND runs a pre-flight budget check.
  #3  ``check_monthly_budget`` raises ``BudgetExceededError`` at >= 100%
      of the configured ceiling.
  #4  ``llm_cost_per_1k_prompt_{slug}`` / ``llm_cost_per_1k_completion_{slug}``
      are declared as ``DynamicKeyFamily`` on ``PlatformConfigSchema`` so
      ``ConfigRegistry.set()`` accepts operator writes; a model that
      resolves to price 0 emits a WARNING log through
      ``emit_missing_pricing_notification``.
  #6  ``BudgetState.reconcile_actual_cost`` + ``estimated_cost_usd``
      surface the durable LLM cost ledger; ``cost_per_turn_usd`` is
      wired to real spend via ``effective_cost_per_turn_usd``.

Offline only -- every DB / registry / LLM interaction is mocked. Mirrors
the existing ``test_cost.py`` / ``test_budget_hard_stop.py`` patterns
(``_StubRegistry`` / ``AsyncMock`` session context manager).
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aila.platform.config import _PLATFORM_DYNAMIC_FAMILIES, PlatformConfigSchema
from aila.platform.contracts.budget import BudgetConfig, BudgetState
from aila.platform.llm.budget_alert import check_monthly_budget
from aila.platform.llm.client import AilaLLMClient
from aila.platform.llm.config import LLMRouting
from aila.platform.llm.cost import (
    _WARNED_MISSING_PRICING,
    CostTracker,
    emit_missing_pricing_notification,
)
from aila.platform.llm.errors import BudgetExceededError
from aila.platform.llm.run_memory import RunMemory
from aila.storage.registry import ConfigRegistry

# ---------------------------------------------------------------------------
# Registry stubs -- mirrors production ConfigRegistry surface
# ---------------------------------------------------------------------------


class _RegistryStub:
    """ConfigRegistry double with the same sync/async twin surface as prod.

    ``get`` is async (a bare call yields a coroutine, matching prod), and
    ``get_sync`` is the sync twin used by ``CostTracker._resolve_ceiling``.
    Both read from the same in-memory dict.
    """

    def __init__(self, data: dict[str, Any] | None = None) -> None:
        self._data: dict[str, Any] = data or {}

    async def get(self, namespace: str, key: str) -> Any:
        return self._data.get(f"{namespace}.{key}")

    def get_sync(self, namespace: str, key: str) -> Any:
        return self._data.get(f"{namespace}.{key}")


def _routing(task_type: str = "scoring") -> LLMRouting:
    return LLMRouting(
        model_id="test/model",
        base_url="http://localhost/v1",
        api_key="test-key",
        max_tokens=64,
        temperature=0.0,
        max_tool_steps=0,
        task_type=task_type,
    )


def _new_client_stub() -> AilaLLMClient:
    """Build an ``AilaLLMClient`` bypassing ``__init__`` -- the pre-flight
    budget-check test only touches ``cost_tracker`` / ``_client_pool`` /
    ``_config`` / ``_single_call`` before the provider dispatch.
    """
    client = object.__new__(AilaLLMClient)
    client.cost_tracker = None
    client.bus = None
    client._client_pool = MagicMock()
    return client


# ---------------------------------------------------------------------------
# Finding #1 -- _resolve_ceiling returns a NUMBER (awaited), enforcement live
# ---------------------------------------------------------------------------


class TestFinding1CeilingReturnsNumberAndEnforces:
    """``_resolve_ceiling`` must resolve through ``get_sync`` (not the async
    ``get`` producing an un-awaited coroutine) so the returned value is a
    number and the ceiling is actually enforced.
    """

    def test_resolve_ceiling_returns_int_from_sync_registry(self) -> None:
        registry = _RegistryStub(
            {"platform.llm_budget_max_total_tokens_scoring": "250"},
        )
        tracker = CostTracker(RunMemory(), registry)
        ceiling = tracker._resolve_ceiling("scoring")
        assert isinstance(ceiling, int)
        assert ceiling == 250

    def test_over_ceiling_raises_budget_exceeded(self) -> None:
        registry = _RegistryStub(
            {"platform.llm_budget_max_total_tokens_scoring": 100},
        )
        tracker = CostTracker(RunMemory(), registry)
        tracker.record("r1", {"prompt_tokens": 70, "completion_tokens": 40})
        with pytest.raises(BudgetExceededError, match="budget exceeded"):
            tracker.check_budget("r1", "scoring")

    def test_no_ceiling_configured_stays_unlimited(self) -> None:
        registry = _RegistryStub()
        tracker = CostTracker(RunMemory(), registry)
        tracker.record("r1", {"prompt_tokens": 10_000, "completion_tokens": 10_000})
        # No raise -- 0 means unlimited.
        tracker.check_budget("r1", "scoring")


# ---------------------------------------------------------------------------
# Finding #2 -- _inner_call attributes cost to team AND pre-flights the budget
# ---------------------------------------------------------------------------


class TestFinding2InnerCallTeamAndBudget:
    """The consensus + verify path (``_inner_call``) must (a) pre-flight the
    per-run token budget so an over-budget run cannot spend on a retry, and
    (b) persist the cost record WITH the caller's ``team_id`` so per-team
    monthly budget accounting stays sound.
    """

    async def test_over_budget_raises_before_provider_call(self) -> None:
        client = _new_client_stub()

        tracker = MagicMock()
        tracker.check_budget_async = AsyncMock(
            side_effect=BudgetExceededError(
                "LLM budget exceeded for run r1: 999/500 tokens used. "
                "Partial results preserved.",
            ),
        )
        client.cost_tracker = tracker

        single_call = AsyncMock(name="_single_call")
        client._single_call = single_call  # type: ignore[method-assign]

        with pytest.raises(BudgetExceededError):
            await client._inner_call(
                routing=_routing(),
                messages=[{"role": "user", "content": "hi"}],
                run_id="r1",
                team_id="team-alpha",
            )
        tracker.check_budget_async.assert_awaited_once_with("r1", "scoring")
        single_call.assert_not_awaited()

    async def test_cost_persist_receives_team_id(self) -> None:
        client = _new_client_stub()

        tracker = MagicMock()
        tracker.check_budget_async = AsyncMock(return_value=None)
        tracker.record = MagicMock()
        client.cost_tracker = tracker

        fake_response = MagicMock()
        fake_response.usage = {"prompt_tokens": 5, "completion_tokens": 3}
        fake_response.content = "ok"
        fake_response.finish_reason = "stop"

        single_call = AsyncMock(name="_single_call", return_value=fake_response)
        client._single_call = single_call  # type: ignore[method-assign]

        cfg_stub = MagicMock()
        cfg_stub._registry = MagicMock()
        cfg_stub._registry.get = AsyncMock(return_value=None)
        client._config = cfg_stub  # type: ignore[attr-defined]

        persist_call = AsyncMock(return_value=None)
        with (
            patch(
                "aila.platform.llm.cost.calculate_cost_usd",
                AsyncMock(return_value=(0.0, False)),
            ),
            patch(
                "aila.platform.llm.cost.persist_cost_record",
                persist_call,
            ),
        ):
            await client._inner_call(
                routing=_routing(),
                messages=[{"role": "user", "content": "hi"}],
                run_id="r1",
                team_id="team-alpha",
            )

        # persist_cost_record is called with team_id threaded through as a
        # keyword arg. This is the fix for orphaned cost rows on the
        # consensus/verify retry paths (issue #38).
        persist_call.assert_awaited_once()
        kwargs = persist_call.await_args.kwargs
        assert kwargs["team_id"] == "team-alpha"
        assert kwargs["run_id"] == "r1"
        assert kwargs["model_id"] == "test/model"


# ---------------------------------------------------------------------------
# Finding #3 -- monthly budget hard-stop at >= 100%
# ---------------------------------------------------------------------------


class _RegistryMonthly:
    def __init__(self, ceiling: float | None) -> None:
        self._ceiling = ceiling

    async def get(self, namespace: str, key: str) -> Any:
        if key.startswith("llm_monthly_budget_usd_"):
            return self._ceiling
        return None


def _install_ledger_sum(monthly_total: float):
    """Patch ``async_session_scope`` in ``budget_alert`` so the SUM query
    returns ``monthly_total`` and every follow-up exec is a no-op.
    """
    sum_mock = MagicMock()
    sum_mock.one = MagicMock(return_value=monthly_total)

    session = AsyncMock()
    exec_count = {"n": 0}

    async def _exec_side_effect(_stmt, *_args, **_kwargs):
        exec_count["n"] += 1
        if exec_count["n"] == 1:
            return sum_mock
        return AsyncMock()

    session.exec.side_effect = _exec_side_effect
    session.commit = AsyncMock()

    @asynccontextmanager
    async def _scope():
        yield session

    return session, _scope


class TestFinding3MonthlyHardStop:
    async def test_at_101_percent_raises(self) -> None:
        registry = _RegistryMonthly(ceiling=100.0)
        _sess, scope = _install_ledger_sum(monthly_total=101.0)
        with patch("aila.platform.llm.budget_alert.async_session_scope", scope):
            with pytest.raises(BudgetExceededError) as excinfo:
                await check_monthly_budget(team_id="team-alpha", registry=registry)  # type: ignore[arg-type]
        msg = str(excinfo.value)
        assert "team-alpha" in msg
        assert "101.00" in msg

    async def test_at_100_percent_raises_boundary(self) -> None:
        registry = _RegistryMonthly(ceiling=100.0)
        _sess, scope = _install_ledger_sum(monthly_total=100.0)
        with patch("aila.platform.llm.budget_alert.async_session_scope", scope):
            with pytest.raises(BudgetExceededError):
                await check_monthly_budget(team_id="team-alpha", registry=registry)  # type: ignore[arg-type]

    async def test_under_100_percent_alerts_but_does_not_raise(self) -> None:
        registry = _RegistryMonthly(ceiling=100.0)
        _sess, scope = _install_ledger_sum(monthly_total=81.0)
        with patch("aila.platform.llm.budget_alert.async_session_scope", scope):
            # 81% -> alert path only, no raise.
            await check_monthly_budget(team_id="team-alpha", registry=registry)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Finding #4 -- pricing keys settable via schema; missing price WARNs
# ---------------------------------------------------------------------------


class TestFinding4PricingSchemaAndMissingWarning:
    """The ``llm_cost_per_1k_prompt_`` / ``llm_cost_per_1k_completion_`` key
    families are declared on ``PlatformConfigSchema``; ``ConfigRegistry.set``
    resolves them through ``__dynamic_families__`` and casts to float. A
    model with no configured price causes ``emit_missing_pricing_notification``
    to log at WARNING level (per-process dedup) so the missing-price signal
    is visible in the worker log without opening the notifications UI.
    """

    def test_pricing_families_declared_on_platform_schema(self) -> None:
        prefixes = {fam.prefix for fam in _PLATFORM_DYNAMIC_FAMILIES}
        assert "llm_cost_per_1k_prompt_" in prefixes
        assert "llm_cost_per_1k_completion_" in prefixes
        # Both families cast values to float (rejects non-numeric writes at set-time).
        by_prefix = {fam.prefix: fam for fam in _PLATFORM_DYNAMIC_FAMILIES}
        assert by_prefix["llm_cost_per_1k_prompt_"].value_type is float
        assert by_prefix["llm_cost_per_1k_completion_"].value_type is float

    def test_pricing_key_resolves_to_family_descriptor(self) -> None:
        """The registry's schema resolver picks the pricing family for a
        model-suffixed key so ``ConfigRegistry.set`` finds a validator and
        does NOT reject the write as an unknown key.
        """
        reg = ConfigRegistry()
        reg._schemas["platform"] = PlatformConfigSchema  # type: ignore[assignment]
        descriptor = reg._resolve_field(
            "platform", "llm_cost_per_1k_prompt_anthropic_claude-sonnet-4-6",
        )
        assert descriptor is not None
        assert descriptor.annotation is float

    @pytest.mark.asyncio
    async def test_missing_price_logs_warning(self, caplog) -> None:
        """The first call for a fresh model logs at WARNING; a repeat call
        for the same model is silent (per-process dedup).
        """
        # Reset per-process dedup so this test is deterministic irrespective
        # of prior tests in the session.
        _WARNED_MISSING_PRICING.discard("brand-new-model-x")

        mock_session = AsyncMock()
        exec_result = MagicMock()
        exec_result.first = MagicMock(return_value=None)
        mock_session.exec = AsyncMock(return_value=exec_result)
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        @asynccontextmanager
        async def _scope():
            yield mock_session

        with patch("aila.storage.database.async_session_scope", _scope):
            with caplog.at_level(logging.WARNING, logger="aila.platform.llm.cost"):
                await emit_missing_pricing_notification("brand-new-model-x")

        assert any(
            "llm_pricing_missing" in rec.getMessage()
            and "brand-new-model-x" in rec.getMessage()
            for rec in caplog.records
        ), f"expected WARNING log for missing price, got {caplog.records!r}"

    @pytest.mark.asyncio
    async def test_missing_price_warning_dedups_per_process(self, caplog) -> None:
        _WARNED_MISSING_PRICING.discard("dedup-model")

        mock_session = AsyncMock()
        exec_result = MagicMock()
        exec_result.first = MagicMock(return_value=None)
        mock_session.exec = AsyncMock(return_value=exec_result)
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        @asynccontextmanager
        async def _scope():
            yield mock_session

        with patch("aila.storage.database.async_session_scope", _scope):
            with caplog.at_level(logging.WARNING, logger="aila.platform.llm.cost"):
                await emit_missing_pricing_notification("dedup-model")
                # Second call: dedup set already contains the slug.
                caplog.clear()
                await emit_missing_pricing_notification("dedup-model")

        warnings = [
            rec for rec in caplog.records
            if "llm_pricing_missing" in rec.getMessage()
        ]
        assert warnings == [], (
            "second call for the same model must not re-log the warning; "
            f"got {[r.getMessage() for r in warnings]!r}"
        )


# ---------------------------------------------------------------------------
# Finding #6 -- BudgetState reconciles with the durable cost ledger
# ---------------------------------------------------------------------------


class TestFinding6BudgetStateReconciles:
    """``cost_per_turn_usd`` used to be a static prior with no wire to
    actual spend; ``estimated_cost_usd`` reported 0 for the whole run. The
    fix adds ``BudgetState.actual_cost_usd`` (raised monotonically by
    ``record_cost`` and ``reconcile_actual_cost``) so ``estimated_cost_usd``
    and ``effective_cost_per_turn_usd`` surface measured spend.
    """

    def test_estimated_cost_usd_prefers_measured_over_prior(self) -> None:
        state = BudgetState(
            config=BudgetConfig(max_turns=10, cost_per_turn_usd=0.02),
        )
        state.record_turn()
        state.record_turn()
        # Prior would suggest 0.04; measured spend of 1.25 wins.
        state.record_cost(1.25)
        assert state.estimated_cost_usd == pytest.approx(1.25)

    def test_effective_cost_per_turn_reflects_actual_spend(self) -> None:
        state = BudgetState(
            config=BudgetConfig(max_turns=10, cost_per_turn_usd=0.10),
        )
        state.record_turn()
        state.record_turn()
        state.record_turn()
        state.record_turn()
        state.record_cost(2.00)
        # 2.00 / 4 turns = 0.50 per turn, replacing the 0.10 prior.
        assert state.effective_cost_per_turn_usd == pytest.approx(0.50)
        # Without any measurement, effective falls back to the prior.
        blank = BudgetState(
            config=BudgetConfig(max_turns=5, cost_per_turn_usd=0.10),
        )
        assert blank.effective_cost_per_turn_usd == pytest.approx(0.10)

    def test_reconcile_is_monotonic_never_lowers(self) -> None:
        state = BudgetState(config=BudgetConfig(max_turns=10))
        state.record_cost(3.0)
        # Stale ledger read below the in-flight total must be ignored.
        state.reconcile_actual_cost(1.0)
        assert state.actual_cost_usd == pytest.approx(3.0)
        # Higher ledger read raises the accumulator.
        state.reconcile_actual_cost(5.5)
        assert state.actual_cost_usd == pytest.approx(5.5)
        assert state.estimated_cost_usd == pytest.approx(5.5)

    def test_negative_cost_delta_raises(self) -> None:
        state = BudgetState(config=BudgetConfig(max_turns=10))
        with pytest.raises(ValueError):
            state.record_cost(-0.01)


# ---------------------------------------------------------------------------
# pytest-asyncio auto mode -- mirror sibling files' contract
# ---------------------------------------------------------------------------


pytestmark = pytest.mark.asyncio
