"""Tests for the async-correctness slice covering findings #38-3.2 and #38-3.3.

* :func:`check_monthly_budget` raises :class:`BudgetExceededError` when a
  team's month-to-date LLM spend reaches or exceeds 100% of the configured
  ceiling (#38-3.3 hard stop / D-08).
* :meth:`AilaLLMClient._inner_call` performs a pre-flight
  ``check_budget_async`` on the injected :class:`CostTracker` BEFORE the
  provider call so consensus (gate.py) and verify (verify.py) retries never
  spend past the per-run token ceiling (#38-3.2).

Static-gate only -- no real DB, no real provider. Uses the same
``async_session_scope`` monkey-patch pattern as ``test_budget_alert.py``.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aila.platform.llm.budget_alert import check_monthly_budget
from aila.platform.llm.client import AilaLLMClient
from aila.platform.llm.config import LLMRouting
from aila.platform.llm.errors import BudgetExceededError

# ---------------------------------------------------------------------------
# Test doubles: registry + session
# ---------------------------------------------------------------------------


class _RegistryWithCeiling:
    """ConfigRegistry stub that returns a configured monthly ceiling."""

    def __init__(self, ceiling: float | None = 100.0) -> None:
        self._ceiling = ceiling

    async def get(self, namespace: str, key: str) -> Any:
        if key.startswith("llm_monthly_budget_usd_"):
            return self._ceiling
        return None


def _install_session_returning(monthly_total: float):
    """Patch ``async_session_scope`` to yield a session whose SUM query
    returns ``monthly_total`` and whose subsequent exec/commit calls are
    no-ops. Returns the ``AsyncMock`` session so tests can inspect calls.
    """
    mock_session = AsyncMock()

    sum_mock = MagicMock()
    sum_mock.one = MagicMock(return_value=monthly_total)

    exec_call_count = {"n": 0}

    async def _exec_side_effect(_stmt, *_args, **_kwargs):
        exec_call_count["n"] += 1
        if exec_call_count["n"] == 1:
            # First exec: SUM(cost_usd) query.
            return sum_mock
        # Subsequent execs (the dedup INSERT) are best-effort no-ops.
        return AsyncMock()

    mock_session.exec.side_effect = _exec_side_effect
    mock_session.commit = AsyncMock()

    @asynccontextmanager
    async def _fake_scope():
        yield mock_session

    return mock_session, _fake_scope, exec_call_count


# ---------------------------------------------------------------------------
# #38-3.3: BudgetExceededError raised at >= 100% spend
# ---------------------------------------------------------------------------


class TestMonthlyBudgetHardStop:
    """check_monthly_budget raises BudgetExceededError when spend reaches
    or exceeds 100% of the configured monthly ceiling (D-08 hard stop).
    """

    async def test_at_101_percent_raises_budget_exceeded(self) -> None:
        """Spend at 101 USD against a 100 USD ceiling raises the hard stop."""
        registry = _RegistryWithCeiling(ceiling=100.0)
        _session, fake_scope, _n = _install_session_returning(monthly_total=101.0)

        with patch("aila.platform.llm.budget_alert.async_session_scope", fake_scope):
            with pytest.raises(BudgetExceededError) as excinfo:
                await check_monthly_budget(team_id="team-alpha", registry=registry)

        message = str(excinfo.value)
        assert "team-alpha" in message
        assert "101.00" in message
        assert "100.00" in message
        # Hard-stop must be non-retryable (see errors.py:BudgetExceededError).
        assert excinfo.value.retryable is False

    async def test_at_exactly_100_percent_raises(self) -> None:
        """Boundary: spend equal to ceiling triggers the hard stop (>=)."""
        registry = _RegistryWithCeiling(ceiling=100.0)
        _session, fake_scope, _n = _install_session_returning(monthly_total=100.0)

        with patch("aila.platform.llm.budget_alert.async_session_scope", fake_scope):
            with pytest.raises(BudgetExceededError):
                await check_monthly_budget(team_id="team-alpha", registry=registry)

    async def test_at_81_percent_does_not_raise(self) -> None:
        """Spend at 81% still fires the alert path and does NOT raise the hard stop."""
        registry = _RegistryWithCeiling(ceiling=100.0)
        _session, fake_scope, exec_count = _install_session_returning(monthly_total=81.0)

        with patch("aila.platform.llm.budget_alert.async_session_scope", fake_scope):
            # Must not raise -- alert path only.
            await check_monthly_budget(team_id="team-alpha", registry=registry)

        # SUM + INSERT: both exec calls fired, and commit ran once.
        assert exec_count["n"] >= 2

    async def test_no_ceiling_configured_does_not_raise(self) -> None:
        """None ceiling short-circuits before any DB access; never raises."""
        registry = _RegistryWithCeiling(ceiling=None)
        # Session scope should never be entered -- if it is, the assertion
        # inside would fire.
        entered = {"flag": False}

        @asynccontextmanager
        async def _fake_scope():
            entered["flag"] = True
            yield AsyncMock()

        with patch("aila.platform.llm.budget_alert.async_session_scope", _fake_scope):
            await check_monthly_budget(team_id="team-alpha", registry=registry)

        assert entered["flag"] is False


# ---------------------------------------------------------------------------
# #38-3.2: _inner_call pre-flight budget check
# ---------------------------------------------------------------------------


def _new_client_stub() -> AilaLLMClient:
    """Build an AilaLLMClient bypassing __init__ so the test does not need
    a live ConfigRegistry / SecretStore. Only the fields _inner_call touches
    before the provider dispatch are populated.
    """
    client = object.__new__(AilaLLMClient)
    client.cost_tracker = None
    client.bus = None
    # _client_pool.get() is only invoked AFTER the pre-flight check; the
    # over-budget test asserts the pre-flight raises first, so a bare mock
    # here is sufficient.
    client._client_pool = MagicMock()
    return client


def _routing() -> LLMRouting:
    return LLMRouting(
        model_id="test/model",
        base_url="http://localhost/v1",
        api_key="test-key",
        max_tokens=64,
        temperature=0.0,
        max_tool_steps=0,
        task_type="scoring",
    )


class TestInnerCallPreflightBudgetCheck:
    """_inner_call must call cost_tracker.check_budget_async BEFORE the
    provider dispatch, mirroring the pre-flight check in _call_with_retry.
    A run over budget raises BudgetExceededError without ever invoking
    _single_call, i.e. no upstream provider spend occurs.
    """

    async def test_over_budget_raises_before_single_call(self) -> None:
        """cost_tracker.check_budget_async raises -> _single_call never runs."""
        client = _new_client_stub()

        cost_tracker = MagicMock()
        cost_tracker.check_budget_async = AsyncMock(
            side_effect=BudgetExceededError(
                "LLM budget exceeded for run r1: 999/500 tokens used. "
                "Partial results preserved."
            )
        )
        client.cost_tracker = cost_tracker

        # If the pre-flight fails to raise, the test would fall through to
        # _single_call. The AsyncMock records the invocation so we can assert
        # the negative.
        single_call = AsyncMock(name="_single_call")
        client._single_call = single_call  # type: ignore[method-assign]

        with pytest.raises(BudgetExceededError):
            await client._inner_call(
                routing=_routing(),
                messages=[{"role": "user", "content": "hello"}],
                run_id="r1",
                team_id="team-alpha",
            )

        cost_tracker.check_budget_async.assert_awaited_once_with("r1", "scoring")
        single_call.assert_not_awaited()

    async def test_under_budget_passes_through_to_single_call(self) -> None:
        """check_budget_async returns cleanly -> _single_call is invoked."""
        client = _new_client_stub()

        cost_tracker = MagicMock()
        cost_tracker.check_budget_async = AsyncMock(return_value=None)
        cost_tracker.record = MagicMock()
        client.cost_tracker = cost_tracker

        # _single_call is called with a real client from the pool; the pool
        # is a MagicMock, so its .get() returns a MagicMock and _single_call
        # (also mocked) never touches it. The response returned to _inner_call
        # is a hand-built LLMResponse-shaped MagicMock exposing .usage/.content
        # so the post-call cost-recording branch can execute without raising.
        fake_response = MagicMock()
        fake_response.usage = {"prompt_tokens": 5, "completion_tokens": 3}
        fake_response.content = "ok"
        fake_response.finish_reason = "stop"

        single_call = AsyncMock(name="_single_call", return_value=fake_response)
        client._single_call = single_call  # type: ignore[method-assign]

        # Prevent the post-call cost-persistence branch from reaching a real
        # DB or ConfigRegistry: _config is only used to fetch pricing. A stub
        # whose _registry.get returns None makes calculate_cost_usd short
        # circuit to (0.0, False) without any network / DB I/O.
        cfg_stub = MagicMock()
        cfg_stub._registry = MagicMock()
        cfg_stub._registry.get = AsyncMock(return_value=None)
        client._config = cfg_stub  # type: ignore[attr-defined]

        # persist_cost_record and calculate_cost_usd are re-imported inside
        # _inner_call; monkey-patch them at the source module.
        with (
            patch(
                "aila.platform.llm.cost.calculate_cost_usd",
                AsyncMock(return_value=(0.0, False)),
            ),
            patch(
                "aila.platform.llm.cost.persist_cost_record",
                AsyncMock(return_value=None),
            ),
        ):
            response = await client._inner_call(
                routing=_routing(),
                messages=[{"role": "user", "content": "hello"}],
                run_id="r1",
                team_id="team-alpha",
            )

        cost_tracker.check_budget_async.assert_awaited_once_with("r1", "scoring")
        single_call.assert_awaited_once()
        assert response is fake_response

    async def test_no_cost_tracker_skips_check(self) -> None:
        """Backward-compatible path: cost_tracker=None -> no check, no raise."""
        client = _new_client_stub()
        # Leave client.cost_tracker as None (default set by _new_client_stub).

        fake_response = MagicMock()
        fake_response.usage = {"prompt_tokens": 0, "completion_tokens": 0}
        fake_response.content = "ok"
        fake_response.finish_reason = "stop"

        single_call = AsyncMock(name="_single_call", return_value=fake_response)
        client._single_call = single_call  # type: ignore[method-assign]

        cfg_stub = MagicMock()
        cfg_stub._registry = MagicMock()
        cfg_stub._registry.get = AsyncMock(return_value=None)
        client._config = cfg_stub  # type: ignore[attr-defined]

        with (
            patch(
                "aila.platform.llm.cost.calculate_cost_usd",
                AsyncMock(return_value=(0.0, False)),
            ),
            patch(
                "aila.platform.llm.cost.persist_cost_record",
                AsyncMock(return_value=None),
            ),
        ):
            await client._inner_call(
                routing=_routing(),
                messages=[{"role": "user", "content": "hi"}],
                run_id="r1",
                team_id=None,
            )

        single_call.assert_awaited_once()

    async def test_no_run_id_skips_check(self) -> None:
        """Standalone calls (run_id=None) skip the pre-flight check.

        Consensus and verify retries always pass a run_id, so this branch
        covers only the unusual call site that omits the identifier.
        """
        client = _new_client_stub()

        cost_tracker = MagicMock()
        cost_tracker.check_budget_async = AsyncMock(return_value=None)
        cost_tracker.record = MagicMock()
        client.cost_tracker = cost_tracker

        fake_response = MagicMock()
        fake_response.usage = {"prompt_tokens": 0, "completion_tokens": 0}
        fake_response.content = "ok"
        fake_response.finish_reason = "stop"

        single_call = AsyncMock(name="_single_call", return_value=fake_response)
        client._single_call = single_call  # type: ignore[method-assign]

        cfg_stub = MagicMock()
        cfg_stub._registry = MagicMock()
        cfg_stub._registry.get = AsyncMock(return_value=None)
        client._config = cfg_stub  # type: ignore[attr-defined]

        with (
            patch(
                "aila.platform.llm.cost.calculate_cost_usd",
                AsyncMock(return_value=(0.0, False)),
            ),
            patch(
                "aila.platform.llm.cost.persist_cost_record",
                AsyncMock(return_value=None),
            ),
        ):
            await client._inner_call(
                routing=_routing(),
                messages=[{"role": "user", "content": "hi"}],
                run_id=None,
                team_id=None,
            )

        cost_tracker.check_budget_async.assert_not_awaited()
        single_call.assert_awaited_once()
