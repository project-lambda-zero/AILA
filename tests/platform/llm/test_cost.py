"""Unit tests for aila.platform.llm.cost -- CostTracker."""

from __future__ import annotations

import json
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import sqlalchemy.exc

from aila.platform.llm.client import AilaLLMClient
from aila.platform.llm.cost import (
    CostTracker,
    calculate_cost_usd,
    emit_missing_pricing_notification,
    persist_cost_record,
)
from aila.platform.llm.errors import BudgetExceededError, LLMError
from aila.platform.llm.run_memory import RunMemory
from aila.storage.db_models import NotificationRecord


class _StubRegistry:
    """Minimal ConfigRegistry stub for testing.

    Production ConfigRegistry.get is async (see aila.storage.registry); the
    LLM client path awaits it via LLMConfigProvider.resolve_routing /
    is_disabled. CostTracker._resolve_ceiling instead uses the sync twin
    get_sync so a call from sync code never returns an un-awaited coroutine
    (issue #38). Mirror both surfaces here.
    """

    def __init__(self, data: dict[str, Any] | None = None) -> None:
        self._data: dict[str, Any] = data or {}

    async def get(self, namespace: str, key: str) -> Any:
        return self._data.get(f"{namespace}.{key}")

    def get_sync(self, namespace: str, key: str) -> Any:
        return self._data.get(f"{namespace}.{key}")


class _AsyncGetStubRegistry:
    """Registry whose ``get`` is async (like the real ConfigRegistry) and whose
    ``get_sync`` is the sync twin. Reproduces production shape: calling ``get``
    without await yields a coroutine, not a value."""

    def __init__(self, data: dict[str, Any] | None = None) -> None:
        self._data: dict[str, Any] = data or {}

    async def get(self, namespace: str, key: str) -> Any:
        return self._data.get(f"{namespace}.{key}")

    def get_sync(self, namespace: str, key: str) -> Any:
        return self._data.get(f"{namespace}.{key}")


# ---------------------------------------------------------------------------
# CostTracker.record
# ---------------------------------------------------------------------------


class TestRecord:
    """CostTracker.record() accumulates tokens via RunMemory."""

    def test_single_record(self) -> None:
        mem = RunMemory()
        tracker = CostTracker(mem, _StubRegistry())
        tracker.record("r1", {"prompt_tokens": 10, "completion_tokens": 5})
        usage = tracker.get_usage("r1")
        assert usage == {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}

    def test_accumulation(self) -> None:
        mem = RunMemory()
        tracker = CostTracker(mem, _StubRegistry())
        tracker.record("r1", {"prompt_tokens": 10, "completion_tokens": 5})
        tracker.record("r1", {"prompt_tokens": 20, "completion_tokens": 10})
        usage = tracker.get_usage("r1")
        assert usage == {"prompt_tokens": 30, "completion_tokens": 15, "total_tokens": 45}

    def test_missing_keys_default_to_zero(self) -> None:
        mem = RunMemory()
        tracker = CostTracker(mem, _StubRegistry())
        tracker.record("r1", {})
        usage = tracker.get_usage("r1")
        assert usage == {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    def test_none_run_id_uses_no_run(self) -> None:
        mem = RunMemory()
        tracker = CostTracker(mem, _StubRegistry())
        tracker.record(None, {"prompt_tokens": 7, "completion_tokens": 3})  # type: ignore[arg-type]
        usage = tracker.get_usage(None)  # type: ignore[arg-type]
        assert usage == {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}


# ---------------------------------------------------------------------------
# CostTracker.get_usage
# ---------------------------------------------------------------------------


class TestGetUsage:
    """CostTracker.get_usage() returns token counts."""

    def test_unknown_run_id_returns_zeros(self) -> None:
        mem = RunMemory()
        tracker = CostTracker(mem, _StubRegistry())
        usage = tracker.get_usage("unknown")
        assert usage == {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    def test_none_run_id_returns_no_run_data(self) -> None:
        mem = RunMemory()
        tracker = CostTracker(mem, _StubRegistry())
        tracker.record(None, {"prompt_tokens": 5, "completion_tokens": 2})  # type: ignore[arg-type]
        usage = tracker.get_usage(None)  # type: ignore[arg-type]
        assert usage["total_tokens"] == 7


# ---------------------------------------------------------------------------
# CostTracker.check_budget
# ---------------------------------------------------------------------------


class TestBudgetCheck:
    """CostTracker.check_budget() enforces ceilings."""

    def test_raises_when_exceeded(self) -> None:
        reg = _StubRegistry({"platform.llm_budget_max_total_tokens_scoring": 100})
        mem = RunMemory()
        tracker = CostTracker(mem, reg)
        tracker.record("r1", {"prompt_tokens": 60, "completion_tokens": 50})
        with pytest.raises(BudgetExceededError, match="budget exceeded"):
            tracker.check_budget("r1", "scoring")

    def test_no_raise_when_under(self) -> None:
        reg = _StubRegistry({"platform.llm_budget_max_total_tokens_scoring": 200})
        mem = RunMemory()
        tracker = CostTracker(mem, reg)
        tracker.record("r1", {"prompt_tokens": 50, "completion_tokens": 40})
        tracker.check_budget("r1", "scoring")  # should not raise

    def test_ceiling_zero_means_unlimited(self) -> None:
        reg = _StubRegistry({"platform.llm_budget_max_total_tokens_scoring": 0})
        mem = RunMemory()
        tracker = CostTracker(mem, reg)
        tracker.record("r1", {"prompt_tokens": 999999, "completion_tokens": 999999})
        tracker.check_budget("r1", "scoring")  # should not raise

    def test_no_run_skipped(self) -> None:
        reg = _StubRegistry({"platform.llm_budget_max_total_tokens_scoring": 10})
        mem = RunMemory()
        tracker = CostTracker(mem, reg)
        tracker.record(None, {"prompt_tokens": 999, "completion_tokens": 999})  # type: ignore[arg-type]
        tracker.check_budget(None, "scoring")  # type: ignore[arg-type]  # should not raise

    def test_missing_config_defaults_unlimited(self) -> None:
        reg = _StubRegistry()  # no config at all
        mem = RunMemory()
        tracker = CostTracker(mem, reg)
        tracker.record("r1", {"prompt_tokens": 999999, "completion_tokens": 999999})
        tracker.check_budget("r1", "scoring")  # should not raise

    def test_error_message_contains_details(self) -> None:
        reg = _StubRegistry({"platform.llm_budget_max_total_tokens_scoring": 50})
        mem = RunMemory()
        tracker = CostTracker(mem, reg)
        tracker.record("r1", {"prompt_tokens": 30, "completion_tokens": 25})
        with pytest.raises(BudgetExceededError, match="r1") as exc_info:
            tracker.check_budget("r1", "scoring")
        assert "55" in str(exc_info.value)
        assert "50" in str(exc_info.value)

    def test_budget_exceeded_is_llm_error(self) -> None:
        reg = _StubRegistry({"platform.llm_budget_max_total_tokens_scoring": 10})
        mem = RunMemory()
        tracker = CostTracker(mem, reg)
        tracker.record("r1", {"prompt_tokens": 10, "completion_tokens": 5})
        with pytest.raises(LLMError):
            tracker.check_budget("r1", "scoring")


# ---------------------------------------------------------------------------
# RunMemory.clear clears cost data
# ---------------------------------------------------------------------------


class TestClearOnRunCompletion:
    """After RunMemory.clear(), cost data resets to zero."""

    def test_clear_resets_usage(self) -> None:
        mem = RunMemory()
        tracker = CostTracker(mem, _StubRegistry())
        tracker.record("r1", {"prompt_tokens": 100, "completion_tokens": 50})
        mem.clear("r1")
        usage = tracker.get_usage("r1")
        assert usage == {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


# ---------------------------------------------------------------------------
# Budget config is read at check time (no caching)
# ---------------------------------------------------------------------------


class TestBudgetConfigRead:
    """Ceiling is read from registry at check time, not cached."""

    def test_config_change_between_checks(self) -> None:
        reg = _StubRegistry({"platform.llm_budget_max_total_tokens_scoring": 200})
        mem = RunMemory()
        tracker = CostTracker(mem, reg)
        tracker.record("r1", {"prompt_tokens": 50, "completion_tokens": 50})
        # First check: under 200 -> passes
        tracker.check_budget("r1", "scoring")

        # Change ceiling to 80
        reg._data["platform.llm_budget_max_total_tokens_scoring"] = 80
        # Second check: 100 >= 80 -> raises
        with pytest.raises(BudgetExceededError):
            tracker.check_budget("r1", "scoring")


class TestBudgetCeilingUsesSyncResolver:
    """_resolve_ceiling must use get_sync so the async registry.get does not
    return an un-awaited coroutine that silently disables the budget (#38)."""

    def test_ceiling_enforced_with_async_registry(self) -> None:
        reg = _AsyncGetStubRegistry(
            {"platform.llm_budget_max_total_tokens_scoring": 100}
        )
        tracker = CostTracker(RunMemory(), reg)
        tracker.record("r1", {"prompt_tokens": 60, "completion_tokens": 50})
        with pytest.raises(BudgetExceededError):
            tracker.check_budget("r1", "scoring")


# ---------------------------------------------------------------------------
# Integration: Client + CostTracker wiring (Plan 02)
# ---------------------------------------------------------------------------


class TestCostIntegration:
    """Integration tests for CostTracker wired into AilaLLMClient."""

    @pytest.fixture(autouse=True)
    def _isolate_db(self) -> Any:
        """Prevent the LLM client path from touching a real PostgreSQL.

        client.chat() reaches ``async_session_scope`` from three sites:
          * RunMemory.ensure_cost_seeded -- seeds token totals from
            LLMCostRecord (would cross-pollute run_ids across sessions).
          * persist_cost_record -- writes the durable LLMCostRecord.
          * emit_missing_pricing_notification -- writes NotificationRecord.

        Leaving those live in unit tests leaks asyncpg connections whose
        cleanup then runs on a closed pytest-asyncio event loop and
        surfaces as ``AttributeError: 'NoneType' object has no attribute
        'send'``. Patch every entry point to a no-op session so the LLM
        path stays hermetic.
        """
        noop_session = AsyncMock()
        noop_session.add = MagicMock()
        noop_session.commit = AsyncMock()
        exec_result = MagicMock()
        exec_result.first = MagicMock(return_value=None)
        noop_session.execute = AsyncMock(return_value=exec_result)
        noop_session.exec = AsyncMock(return_value=exec_result)

        def _noop_cm(*_args: Any, **_kwargs: Any) -> AsyncMock:
            cm = AsyncMock()
            cm.__aenter__ = AsyncMock(return_value=noop_session)
            cm.__aexit__ = AsyncMock(return_value=False)
            return cm

        with patch(
            "aila.storage.database.async_session_scope",
            side_effect=_noop_cm,
        ), patch(
            "aila.platform.llm.run_memory.async_session_scope",
            side_effect=_noop_cm,
        ):
            yield

    def _make_client_with_tracker(
        self, budget: int | None = None
    ) -> tuple[Any, CostTracker]:
        """Build an AilaLLMClient with CostTracker attached.

        Returns (client, cost_tracker) pair.
        """


        reg_data: dict[str, Any] = {}
        if budget is not None:
            reg_data["platform.llm_budget_max_total_tokens_scoring"] = budget

        reg = _StubRegistry(reg_data)
        # LLMConfigProvider.resolve_api_key awaits secret_store.resolve_provider_secret,
        # so it must be an AsyncMock -- a bare MagicMock returns a value that
        # ``await`` cannot consume.
        secret_store = MagicMock()
        secret_store.resolve_provider_secret = AsyncMock(return_value="sk-test-key")

        client = AilaLLMClient(registry=reg, secret_store=secret_store)  # type: ignore[arg-type]

        mem = RunMemory()
        tracker = CostTracker(mem, reg)
        client.cost_tracker = tracker

        return client, tracker

    @pytest.mark.asyncio
    async def test_chat_records_usage_with_run_id(self) -> None:
        """chat() with run_id records token usage to CostTracker."""

        client, tracker = self._make_client_with_tracker()
        # Unique per-invocation run_id: the integration path hits a real DB
        # via CostTracker.check_budget_async -> RunMemory.ensure_cost_seeded,
        # so hardcoded ids get seeded from prior runs' LLMCostRecord rows and
        # this test then observes doubled totals.
        run_id = f"test-run-{uuid.uuid4().hex}"

        usage_mock = MagicMock()
        usage_mock.prompt_tokens = 25
        usage_mock.completion_tokens = 15
        usage_mock.total_tokens = 40
        message = MagicMock()
        message.content = "response text"
        message.tool_calls = []
        choice = MagicMock()
        choice.message = message
        choice.finish_reason = "stop"
        completion = MagicMock()
        completion.choices = [choice]
        completion.usage = usage_mock

        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            mock_oai.return_value = mock_instance

            response = await client.chat(
                "scoring",
                [{"role": "user", "content": "test"}],
                run_id=run_id,
            )

        assert response.content == "response text"
        usage = tracker.get_usage(run_id)
        assert usage["prompt_tokens"] == 25
        assert usage["completion_tokens"] == 15
        assert usage["total_tokens"] == 40

    @pytest.mark.asyncio
    async def test_budget_exceeded_blocks_call(self) -> None:
        """When budget is already exceeded, chat() raises BudgetExceededError before API call."""
        client, tracker = self._make_client_with_tracker(budget=50)
        run_id = f"test-run-{uuid.uuid4().hex}"

        # Pre-load usage above budget
        tracker.record(run_id, {"prompt_tokens": 30, "completion_tokens": 25})

        with pytest.raises(BudgetExceededError, match="budget exceeded"):
            await client.chat(
                "scoring",
                [{"role": "user", "content": "test"}],
                run_id=run_id,
            )

    @pytest.mark.asyncio
    async def test_no_run_id_records_under_no_run(self) -> None:
        """chat() without run_id records under _no_run sentinel."""

        client, tracker = self._make_client_with_tracker()

        usage_mock = MagicMock()
        usage_mock.prompt_tokens = 10
        usage_mock.completion_tokens = 5
        usage_mock.total_tokens = 15
        message = MagicMock()
        message.content = "ok"
        message.tool_calls = []
        choice = MagicMock()
        choice.message = message
        choice.finish_reason = "stop"
        completion = MagicMock()
        completion.choices = [choice]
        completion.usage = usage_mock

        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            mock_oai.return_value = mock_instance

            await client.chat(
                "scoring",
                [{"role": "user", "content": "test"}],
            )

        # Recorded under _no_run sentinel (None -> _no_run)
        usage = tracker.get_usage(None)  # type: ignore[arg-type]
        assert usage["total_tokens"] == 15

    @pytest.mark.asyncio
    async def test_no_tracker_backward_compatible(self) -> None:
        """Client without cost_tracker set still works normally."""

        reg = _StubRegistry()
        # Same async-await contract as _make_client_with_tracker.
        secret_store = MagicMock()
        secret_store.resolve_provider_secret = AsyncMock(return_value="sk-test-key")
        client_obj = __import__(
            "aila.platform.llm.client", fromlist=["AilaLLMClient"]
        ).AilaLLMClient(
            registry=reg,  # type: ignore[arg-type]
            secret_store=secret_store,  # type: ignore[arg-type]
        )
        # cost_tracker is None by default

        usage_mock = MagicMock()
        usage_mock.prompt_tokens = 5
        usage_mock.completion_tokens = 3
        usage_mock.total_tokens = 8
        message = MagicMock()
        message.content = "works"
        message.tool_calls = []
        choice = MagicMock()
        choice.message = message
        choice.finish_reason = "stop"
        completion = MagicMock()
        completion.choices = [choice]
        completion.usage = usage_mock

        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            mock_oai.return_value = mock_instance

            response = await client_obj.chat(
                "scoring",
                [{"role": "user", "content": "test"}],
            )

        assert response.content == "works"

    @pytest.mark.asyncio
    async def test_run_id_flows_to_pipeline_ctx(self) -> None:
        """run_id is set in pipeline ctx for seal step to read."""

        client, tracker = self._make_client_with_tracker()
        run_id = f"test-run-{uuid.uuid4().hex}"

        captured_ctx: dict[str, Any] = {}

        original_run = client._pipeline.run

        async def spy_run(**kwargs: Any) -> Any:
            result = await original_run(**kwargs)
            captured_ctx.update(result[1])  # ctx is second element
            return result

        client._pipeline.run = spy_run  # type: ignore[assignment]

        usage_mock = MagicMock()
        usage_mock.prompt_tokens = 5
        usage_mock.completion_tokens = 3
        usage_mock.total_tokens = 8
        message = MagicMock()
        message.content = "ctx test"
        message.tool_calls = []
        choice = MagicMock()
        choice.message = message
        choice.finish_reason = "stop"
        completion = MagicMock()
        completion.choices = [choice]
        completion.usage = usage_mock

        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            mock_oai.return_value = mock_instance

            await client.chat(
                "scoring",
                [{"role": "user", "content": "test"}],
                run_id=run_id,
            )

        assert captured_ctx.get("run_id") == run_id

    @pytest.mark.asyncio
    async def test_chat_json_accepts_run_id(self) -> None:
        """chat_json() also accepts run_id kwarg."""

        client, tracker = self._make_client_with_tracker()
        run_id = f"test-run-{uuid.uuid4().hex}"

        usage_mock = MagicMock()
        usage_mock.prompt_tokens = 12
        usage_mock.completion_tokens = 8
        usage_mock.total_tokens = 20
        message = MagicMock()
        message.content = json.dumps({"score": 5.0})
        message.tool_calls = []
        choice = MagicMock()
        choice.message = message
        choice.finish_reason = "stop"
        completion = MagicMock()
        completion.choices = [choice]
        completion.usage = usage_mock

        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            mock_oai.return_value = mock_instance

            await client.chat_json(
                "scoring",
                [{"role": "user", "content": "test"}],
                {"type": "object", "properties": {"score": {"type": "number"}}},
                run_id=run_id,
            )

        usage = tracker.get_usage(run_id)
        assert usage["total_tokens"] == 20

    def test_chat_sync_accepts_run_id(self) -> None:
        """chat_sync() passes run_id through."""

        client, tracker = self._make_client_with_tracker()
        run_id = f"test-run-{uuid.uuid4().hex}"

        usage_mock = MagicMock()
        usage_mock.prompt_tokens = 7
        usage_mock.completion_tokens = 4
        usage_mock.total_tokens = 11
        message = MagicMock()
        message.content = "sync ok"
        message.tool_calls = []
        choice = MagicMock()
        choice.message = message
        choice.finish_reason = "stop"
        completion = MagicMock()
        completion.choices = [choice]
        completion.usage = usage_mock

        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=completion)
            mock_oai.return_value = mock_instance

            client.chat_sync(
                "scoring",
                [{"role": "user", "content": "test"}],
                run_id=run_id,
            )

        usage = tracker.get_usage(run_id)
        assert usage["total_tokens"] == 11


# ---------------------------------------------------------------------------
# Phase 175: calculate_cost_usd tests
# ---------------------------------------------------------------------------


class _AsyncStubRegistry:
    """Async-compatible ConfigRegistry stub for Phase 175 tests."""

    def __init__(self, data: dict[str, Any] | None = None) -> None:
        self._data: dict[str, Any] = data or {}

    async def get(self, namespace: str, key: str) -> Any:
        return self._data.get(f"{namespace}.{key}")


class TestCalculateCostUsd:
    """calculate_cost_usd() computes dollar amounts from ConfigRegistry pricing."""

    @pytest.mark.asyncio
    async def test_calculate_cost_usd_both_keys_present(self) -> None:
        """Returns (cost, True) when both pricing keys exist and are valid."""

        registry = _AsyncStubRegistry({
            "platform.llm_cost_per_1k_prompt_gpt-4o": 0.005,
            "platform.llm_cost_per_1k_completion_gpt-4o": 0.015,
        })
        cost, configured = await calculate_cost_usd(
            model_id="gpt-4o",
            prompt_tokens=1000,
            completion_tokens=500,
            registry=registry,  # type: ignore[arg-type]
        )
        # (1000/1000)*0.005 + (500/1000)*0.015 = 0.005 + 0.0075 = 0.0125
        assert configured is True
        assert abs(cost - 0.0125) < 1e-9

    @pytest.mark.asyncio
    async def test_calculate_cost_usd_missing_keys(self) -> None:
        """Returns (0.0, False) when pricing keys are missing."""

        registry = _AsyncStubRegistry()  # no keys
        cost, configured = await calculate_cost_usd(
            model_id="gpt-4o",
            prompt_tokens=1000,
            completion_tokens=500,
            registry=registry,  # type: ignore[arg-type]
        )
        assert cost == 0.0
        assert configured is False

    @pytest.mark.asyncio
    async def test_calculate_cost_usd_non_numeric_keys(self) -> None:
        """Returns (0.0, False) when pricing keys are non-numeric strings."""

        registry = _AsyncStubRegistry({
            "platform.llm_cost_per_1k_prompt_gpt-4o": "not-a-number",
            "platform.llm_cost_per_1k_completion_gpt-4o": "also-not-a-number",
        })
        cost, configured = await calculate_cost_usd(
            model_id="gpt-4o",
            prompt_tokens=1000,
            completion_tokens=500,
            registry=registry,  # type: ignore[arg-type]
        )
        assert cost == 0.0
        assert configured is False

    @pytest.mark.asyncio
    async def test_calculate_cost_usd_negative_price_rejected(self) -> None:
        """Returns (0.0, False) when prices are negative (T-175-01)."""

        registry = _AsyncStubRegistry({
            "platform.llm_cost_per_1k_prompt_gpt-4o": -0.005,
            "platform.llm_cost_per_1k_completion_gpt-4o": 0.015,
        })
        cost, configured = await calculate_cost_usd(
            model_id="gpt-4o",
            prompt_tokens=1000,
            completion_tokens=500,
            registry=registry,  # type: ignore[arg-type]
        )
        assert cost == 0.0
        assert configured is False

    @pytest.mark.asyncio
    async def test_calculate_cost_usd_zero_tokens(self) -> None:
        """Zero tokens yields zero cost but still configured=True."""

        registry = _AsyncStubRegistry({
            "platform.llm_cost_per_1k_prompt_gpt-4o": 0.005,
            "platform.llm_cost_per_1k_completion_gpt-4o": 0.015,
        })
        cost, configured = await calculate_cost_usd(
            model_id="gpt-4o",
            prompt_tokens=0,
            completion_tokens=0,
            registry=registry,  # type: ignore[arg-type]
        )
        assert cost == 0.0
        assert configured is True

    @pytest.mark.asyncio
    async def test_calculate_cost_usd_only_prompt_key_missing(self) -> None:
        """Returns (0.0, False) when only one key is missing."""

        registry = _AsyncStubRegistry({
            # prompt key missing
            "platform.llm_cost_per_1k_completion_gpt-4o": 0.015,
        })
        cost, configured = await calculate_cost_usd(
            model_id="gpt-4o",
            prompt_tokens=1000,
            completion_tokens=500,
            registry=registry,  # type: ignore[arg-type]
        )
        assert cost == 0.0
        assert configured is False


# ---------------------------------------------------------------------------
# Phase 175: persist_cost_record tests
# ---------------------------------------------------------------------------


class TestPersistCostRecord:
    """persist_cost_record() writes to DB and never raises on failure."""

    @pytest.mark.asyncio
    async def test_persist_cost_record_swallows_db_exception(self) -> None:
        """persist_cost_record() swallows DB exceptions and never raises."""


        # Patch async_session_scope to raise on commit. Production catches
        # sqlalchemy.exc.SQLAlchemyError specifically (see cost.py) -- the
        # honesty-audit rule forbids bare ``except Exception``. A real commit()
        # failure surfaces as OperationalError (a SQLAlchemyError subclass),
        # so raise the same shape here.
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock(
            side_effect=sqlalchemy.exc.OperationalError(
                "COMMIT", None, RuntimeError("DB connection lost"),
            ),
        )
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("aila.platform.llm.cost.async_session_scope", return_value=mock_cm, create=True):
            with patch("aila.storage.database.async_session_scope", return_value=mock_cm):
                # Must not raise even when DB explodes
                await persist_cost_record(
                    run_id="run-test",
                    model_id="gpt-4o",
                    task_type="scoring",
                    team_id="team-1",
                    prompt_tokens=100,
                    completion_tokens=50,
                    cost_usd=0.001,
                )
        # Reaching here means no exception was raised

    @pytest.mark.asyncio
    async def test_persist_cost_record_none_run_id_defaults(self) -> None:
        """persist_cost_record() with run_id=None uses '_no_run' sentinel."""


        added_records: list = []

        mock_session = AsyncMock()
        mock_session.add = MagicMock(side_effect=lambda r: added_records.append(r))
        mock_session.commit = AsyncMock()
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("aila.storage.database.async_session_scope", return_value=mock_cm):
            await persist_cost_record(
                run_id=None,
                model_id="gpt-4o",
                task_type="scoring",
                team_id=None,
                prompt_tokens=10,
                completion_tokens=5,
                cost_usd=0.0,
            )

        assert len(added_records) == 1
        assert added_records[0].run_id == "_no_run"

    @pytest.mark.asyncio
    async def test_persist_cost_record_sets_all_fields(self) -> None:
        """persist_cost_record() creates record with all fields set correctly."""


        added_records: list = []

        mock_session = AsyncMock()
        mock_session.add = MagicMock(side_effect=lambda r: added_records.append(r))
        mock_session.commit = AsyncMock()
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("aila.storage.database.async_session_scope", return_value=mock_cm):
            await persist_cost_record(
                run_id="run-xyz",
                model_id="gpt-4o-mini",
                task_type="analysis",
                team_id="team-42",
                prompt_tokens=200,
                completion_tokens=100,
                cost_usd=0.0042,
            )

        assert len(added_records) == 1
        rec = added_records[0]
        assert rec.run_id == "run-xyz"
        assert rec.model_id == "gpt-4o-mini"
        assert rec.task_type == "analysis"
        assert rec.team_id == "team-42"
        assert rec.prompt_tokens == 200
        assert rec.completion_tokens == 100
        assert rec.cost_usd == 0.0042


# ---------------------------------------------------------------------------
# Phase 175: emit_missing_pricing_notification tests
# ---------------------------------------------------------------------------


class TestEmitMissingPricingNotification:
    """emit_missing_pricing_notification() emits one-time system notifications."""

    @pytest.mark.asyncio
    async def test_emit_missing_pricing_notification_creates_record(self) -> None:
        """Creates a NotificationRecord with user_id='__system__' on first call."""


        added_records: list = []

        mock_session = AsyncMock()
        # No existing record
        mock_exec_result = MagicMock()
        mock_exec_result.first.return_value = None
        mock_session.exec = AsyncMock(return_value=mock_exec_result)
        mock_session.add = MagicMock(side_effect=lambda r: added_records.append(r))
        mock_session.commit = AsyncMock()
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("aila.storage.database.async_session_scope", return_value=mock_cm):
            await emit_missing_pricing_notification("gpt-4o")

        assert len(added_records) == 1
        notif = added_records[0]
        assert notif.user_id == "__system__"
        assert notif.category == "warning"
        assert notif.source_module == "llm_cost"
        assert "pricing_missing:gpt-4o" in notif.source_entity_id

    @pytest.mark.asyncio
    async def test_emit_missing_pricing_notification_idempotent(self) -> None:
        """Does NOT create a new record if one already exists (dedup)."""


        added_records: list = []

        # Simulate existing record
        existing = MagicMock(spec=NotificationRecord)
        existing.source_entity_id = "pricing_missing:gpt-4o"

        mock_session = AsyncMock()
        mock_exec_result = MagicMock()
        mock_exec_result.first.return_value = existing
        mock_session.exec = AsyncMock(return_value=mock_exec_result)
        mock_session.add = MagicMock(side_effect=lambda r: added_records.append(r))
        mock_session.commit = AsyncMock()
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("aila.storage.database.async_session_scope", return_value=mock_cm):
            await emit_missing_pricing_notification("gpt-4o")

        # No new record should have been added
        assert len(added_records) == 0

    @pytest.mark.asyncio
    async def test_emit_missing_pricing_notification_swallows_exception(self) -> None:
        """Swallows DB exceptions and never raises."""


        # Production catches sqlalchemy.exc.SQLAlchemyError specifically
        # (see cost.py -- narrow catch per honesty-audit rule). A real
        # session-open failure surfaces as OperationalError.
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(
            side_effect=sqlalchemy.exc.OperationalError(
                "CONNECT", None, RuntimeError("DB unavailable"),
            ),
        )
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("aila.storage.database.async_session_scope", return_value=mock_cm):
            # Must not raise
            await emit_missing_pricing_notification("some-model")
        # Reaching here means no exception was raised

    @pytest.mark.asyncio
    async def test_emit_missing_pricing_notification_uses_system_user_id(self) -> None:
        """user_id is always '__system__' (required non-nullable field)."""


        added_records: list = []

        mock_session = AsyncMock()
        mock_exec_result = MagicMock()
        mock_exec_result.first.return_value = None
        mock_session.exec = AsyncMock(return_value=mock_exec_result)
        mock_session.add = MagicMock(side_effect=lambda r: added_records.append(r))
        mock_session.commit = AsyncMock()
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("aila.storage.database.async_session_scope", return_value=mock_cm):
            await emit_missing_pricing_notification("claude-haiku")

        assert added_records[0].user_id == "__system__"

    @pytest.mark.asyncio
    async def test_emit_missing_pricing_notification_source_entity_id_format(self) -> None:
        """source_entity_id uses 'pricing_missing:{model_id}' format for dedup."""


        added_records: list = []

        mock_session = AsyncMock()
        mock_exec_result = MagicMock()
        mock_exec_result.first.return_value = None
        mock_session.exec = AsyncMock(return_value=mock_exec_result)
        mock_session.add = MagicMock(side_effect=lambda r: added_records.append(r))
        mock_session.commit = AsyncMock()
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("aila.storage.database.async_session_scope", return_value=mock_cm):
            await emit_missing_pricing_notification("my-model-v2")

        assert added_records[0].source_entity_id == "pricing_missing:my-model-v2"
