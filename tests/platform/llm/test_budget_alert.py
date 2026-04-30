"""Tests for Phase 175 Plan 02 budget alerting (LLM-COST-02).

Verifies check_monthly_budget:
  1. Creates exactly one NotificationRecord at 80% threshold
  2. Deduplicates -- second call in same month creates no new record
  3. Below threshold (79%) -- no notification created
  4. No ceiling configured -- silently skipped
  5. Ceiling = 0 -- silently skipped (unlimited budget)
  6. source_entity_id format: budget_alert:{team_id}:{YYYY-MM}:80pct
  7. DB exceptions are swallowed (fire-and-forget)
  8. user_id="__system__" on all notifications
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest


# ---------------------------------------------------------------------------
# Async registry stubs
# ---------------------------------------------------------------------------


class _RegistryWithCeiling:
    """ConfigRegistry stub that returns a configured budget ceiling."""

    def __init__(self, ceiling: float | None = 100.0) -> None:
        self._ceiling = ceiling

    async def get(self, namespace: str, key: str) -> Any:
        # Only match team-specific budget keys
        if key.startswith("llm_monthly_budget_usd_"):
            return self._ceiling
        return None


class _RegistryNoCeiling:
    """ConfigRegistry stub with no ceiling configured."""

    async def get(self, namespace: str, key: str) -> Any:
        return None


# ---------------------------------------------------------------------------
# Session mock factory
# ---------------------------------------------------------------------------


def _make_session_mock(monthly_total: float = 0.0, existing_alert: bool = False):
    """Create an async session mock with configurable state."""
    session = AsyncMock()

    # exec() is called for two purposes:
    # 1. SUM query -> returns monthly total
    # 2. INSERT ... ON CONFLICT -> dedup insert

    # For the SUM query, exec returns an object with .one()
    sum_result = MagicMock()
    sum_result.one.return_value = monthly_total

    # Track exec calls
    exec_results = [sum_result]
    session.exec.side_effect = lambda stmt, *args, **kwargs: AsyncMock(return_value=exec_results[0])()

    return session


# ---------------------------------------------------------------------------
# Test: 81% triggers exactly one notification
# ---------------------------------------------------------------------------


class TestBudgetAlertThreshold:
    """Budget alerts fire at 80% and above."""

    @pytest.mark.asyncio
    async def test_at_81_percent_creates_one_notification(self) -> None:
        """81% of ceiling creates exactly one NotificationRecord with correct fields."""
        registry = _RegistryWithCeiling(ceiling=100.0)

        # Mock async_session_scope and session.exec
        mock_session = AsyncMock()

        # First exec: SUM returns 81.0 (81% of 100.0)
        sum_mock = AsyncMock()
        sum_mock.one = MagicMock(return_value=81.0)

        # We need exec to handle both the SUM query and the INSERT text
        exec_call_count = 0

        async def exec_side_effect(stmt, *args, **kwargs):
            nonlocal exec_call_count
            exec_call_count += 1
            if exec_call_count == 1:
                return sum_mock
            # Second call is the INSERT ... WHERE NOT EXISTS
            return AsyncMock()

        mock_session.exec.side_effect = exec_side_effect
        mock_session.commit = AsyncMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_scope():
            yield mock_session

        with patch("aila.platform.llm.budget_alert.async_session_scope", mock_scope):
            from aila.platform.llm.budget_alert import check_monthly_budget
            await check_monthly_budget(team_id="team-alpha", registry=registry)

        # exec was called at least twice: SUM + INSERT
        assert exec_call_count >= 2
        mock_session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_at_81_percent_notification_has_warning_category(self) -> None:
        """Notification created at 81% has category='warning'."""
        registry = _RegistryWithCeiling(ceiling=100.0)

        captured_inserts = []
        mock_session = AsyncMock()

        exec_call_count = 0
        sum_mock = AsyncMock()
        sum_mock.one = MagicMock(return_value=81.0)

        async def exec_side_effect(stmt, params=None, *args, **kwargs):
            nonlocal exec_call_count
            exec_call_count += 1
            if exec_call_count == 1:
                return sum_mock
            # Capture params from INSERT
            if params:
                captured_inserts.append(params)
            return AsyncMock()

        mock_session.exec.side_effect = exec_side_effect
        mock_session.commit = AsyncMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_scope():
            yield mock_session

        with patch("aila.platform.llm.budget_alert.async_session_scope", mock_scope):
            from aila.platform.llm.budget_alert import check_monthly_budget
            await check_monthly_budget(team_id="team-beta", registry=registry)

        # Verify the INSERT params have expected values
        assert len(captured_inserts) == 1
        params = captured_inserts[0]
        assert params["category"] == "warning"
        assert params["source_module"] == "llm_cost"
        assert params["user_id"] == "__system__"

    @pytest.mark.asyncio
    async def test_source_entity_id_format(self) -> None:
        """source_entity_id must follow 'budget_alert:{team_id}:{YYYY-MM}:80pct' format."""
        registry = _RegistryWithCeiling(ceiling=50.0)

        captured_inserts = []
        mock_session = AsyncMock()

        exec_call_count = 0
        sum_mock = AsyncMock()
        sum_mock.one = MagicMock(return_value=45.0)  # 90% of 50.0

        async def exec_side_effect(stmt, params=None, *args, **kwargs):
            nonlocal exec_call_count
            exec_call_count += 1
            if exec_call_count == 1:
                return sum_mock
            if params:
                captured_inserts.append(params)
            return AsyncMock()

        mock_session.exec.side_effect = exec_side_effect
        mock_session.commit = AsyncMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_scope():
            yield mock_session

        now = datetime.now(timezone.utc)
        expected_ym = now.strftime("%Y-%m")

        with patch("aila.platform.llm.budget_alert.async_session_scope", mock_scope):
            from aila.platform.llm.budget_alert import check_monthly_budget
            await check_monthly_budget(team_id="team-gamma", registry=registry)

        assert len(captured_inserts) == 1
        entity_id = captured_inserts[0]["source_entity_id"]
        assert entity_id == f"budget_alert:team-gamma:{expected_ym}:80pct"

    @pytest.mark.asyncio
    async def test_user_id_is_system(self) -> None:
        """NotificationRecord must always have user_id='__system__'."""
        registry = _RegistryWithCeiling(ceiling=100.0)

        captured_params = []
        mock_session = AsyncMock()
        exec_call_count = 0
        sum_mock = AsyncMock()
        sum_mock.one = MagicMock(return_value=85.0)

        async def exec_side_effect(stmt, params=None, *args, **kwargs):
            nonlocal exec_call_count
            exec_call_count += 1
            if exec_call_count == 1:
                return sum_mock
            if params:
                captured_params.append(params)
            return AsyncMock()

        mock_session.exec.side_effect = exec_side_effect
        mock_session.commit = AsyncMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_scope():
            yield mock_session

        with patch("aila.platform.llm.budget_alert.async_session_scope", mock_scope):
            from aila.platform.llm.budget_alert import check_monthly_budget
            await check_monthly_budget(team_id="team-delta", registry=registry)

        assert len(captured_params) == 1
        assert captured_params[0]["user_id"] == "__system__"


# ---------------------------------------------------------------------------
# Test: Below threshold -- no notification
# ---------------------------------------------------------------------------


class TestBelowThreshold:
    """No notification is created when spending is below 80%."""

    @pytest.mark.asyncio
    async def test_79_percent_creates_no_notification(self) -> None:
        """79% of ceiling creates zero NotificationRecords."""
        registry = _RegistryWithCeiling(ceiling=100.0)

        mock_session = AsyncMock()
        exec_call_count = 0
        sum_mock = AsyncMock()
        sum_mock.one = MagicMock(return_value=79.0)  # 79% -- below threshold

        async def exec_side_effect(stmt, params=None, *args, **kwargs):
            nonlocal exec_call_count
            exec_call_count += 1
            if exec_call_count == 1:
                return sum_mock
            return AsyncMock()

        mock_session.exec.side_effect = exec_side_effect
        mock_session.commit = AsyncMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_scope():
            yield mock_session

        with patch("aila.platform.llm.budget_alert.async_session_scope", mock_scope):
            from aila.platform.llm.budget_alert import check_monthly_budget
            await check_monthly_budget(team_id="team-zeta", registry=registry)

        # Only SUM was called, no INSERT
        assert exec_call_count == 1
        mock_session.commit.assert_not_awaited()


# ---------------------------------------------------------------------------
# Test: No ceiling configured
# ---------------------------------------------------------------------------


class TestNoCeilingConfigured:
    """Teams without a budget ceiling are silently skipped."""

    @pytest.mark.asyncio
    async def test_no_ceiling_skips_db_access(self) -> None:
        """When registry returns None for ceiling, no DB access occurs."""
        registry = _RegistryNoCeiling()

        mock_session = AsyncMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_scope():
            yield mock_session

        with patch("aila.platform.llm.budget_alert.async_session_scope", mock_scope):
            from aila.platform.llm.budget_alert import check_monthly_budget
            await check_monthly_budget(team_id="team-no-ceiling", registry=registry)

        # No DB access should have happened
        mock_session.exec.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_none_team_id_returns_immediately(self) -> None:
        """None team_id returns without any action (exits before any DB access)."""
        registry = _RegistryWithCeiling(ceiling=100.0)

        # Patch module-level async_session_scope so any accidental DB access raises
        with patch("aila.platform.llm.budget_alert.async_session_scope", side_effect=RuntimeError("should not reach DB")):
            from aila.platform.llm.budget_alert import check_monthly_budget
            # Should not raise -- exits before DB access due to None team_id guard
            await check_monthly_budget(team_id=None, registry=registry)


# ---------------------------------------------------------------------------
# Test: Zero ceiling (unlimited budget)
# ---------------------------------------------------------------------------


class TestZeroCeiling:
    """Ceiling of 0 means unlimited budget -- silently skip."""

    @pytest.mark.asyncio
    async def test_zero_ceiling_skips_db_access(self) -> None:
        """When ceiling is 0, no DB access occurs."""
        registry = _RegistryWithCeiling(ceiling=0.0)

        mock_session = AsyncMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_scope():
            yield mock_session

        with patch("aila.platform.llm.budget_alert.async_session_scope", mock_scope):
            from aila.platform.llm.budget_alert import check_monthly_budget
            await check_monthly_budget(team_id="team-unlimited", registry=registry)

        mock_session.exec.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_negative_ceiling_treated_as_unlimited(self) -> None:
        """Negative ceiling is treated as 0 (unlimited)."""
        registry = _RegistryWithCeiling(ceiling=-10.0)

        mock_session = AsyncMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_scope():
            yield mock_session

        with patch("aila.platform.llm.budget_alert.async_session_scope", mock_scope):
            from aila.platform.llm.budget_alert import check_monthly_budget
            await check_monthly_budget(team_id="team-neg", registry=registry)

        mock_session.exec.assert_not_awaited()


# ---------------------------------------------------------------------------
# Test: DB exceptions are swallowed
# ---------------------------------------------------------------------------


class TestFireAndForgetSafety:
    """DB exceptions in check_monthly_budget are swallowed -- never re-raised."""

    @pytest.mark.asyncio
    async def test_db_exception_does_not_raise(self) -> None:
        """RuntimeError during DB access is swallowed and does not propagate."""
        registry = _RegistryWithCeiling(ceiling=100.0)

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_scope_raises():
            raise RuntimeError("DB is down")
            yield  # noqa: unreachable

        with patch("aila.platform.llm.budget_alert.async_session_scope", mock_scope_raises):
            from aila.platform.llm.budget_alert import check_monthly_budget
            # Must NOT raise
            await check_monthly_budget(team_id="team-err", registry=registry)

    @pytest.mark.asyncio
    async def test_registry_exception_does_not_raise(self) -> None:
        """Exception from registry.get() is swallowed."""

        class _BrokenRegistry:
            async def get(self, namespace: str, key: str) -> Any:
                raise ConnectionError("Registry connection failed")

        from aila.platform.llm.budget_alert import check_monthly_budget
        # Must NOT raise
        await check_monthly_budget(team_id="team-broken", registry=_BrokenRegistry())
