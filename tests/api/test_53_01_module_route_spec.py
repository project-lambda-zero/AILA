"""Tests for Phase 53 Plan 01: Redesigned ModuleRouteSpec and extended ModuleProtocol.

Tests verify:
- ModuleRouteSpec has the new frozen dataclass shape (prefix, router_factory, tool_keys,
  config_namespace, payload_type) -- no legacy fields (action_id, http_method, path, etc.)
- ModuleProtocol gains system_summary() and report_count() with default {} return
- ModuleProtocol.route_specs() default return value is still [] (backwards compat)
"""
from __future__ import annotations

import pytest


class TestModuleRouteSpecNewShape:
    """ModuleRouteSpec is a frozen dataclass with the new Phase 53 contract."""


    def test_is_frozen(self) -> None:
        """ModuleRouteSpec is frozen -- mutation raises FrozenInstanceError."""
        from dataclasses import FrozenInstanceError

        from aila.platform.modules.protocol import ModuleRouteSpec

        spec = ModuleRouteSpec(prefix="/x", router_factory=lambda: None)
        with pytest.raises(FrozenInstanceError):
            spec.prefix = "/y"  # type: ignore[misc]


class TestModuleProtocolNewMethods:
    """ModuleProtocol gains system_summary() and report_count() with default {} return."""


    async def test_report_count_default_returns_empty_dict(self) -> None:
        """ModuleProtocol.report_count default implementation returns {}.

        The Protocol default is ``async def`` (protocol.py declares it with a
        coroutine signature), so callers must await the return value.
        """
        from unittest.mock import MagicMock

        from aila.platform.modules.protocol import ModuleProtocol

        mock_session = MagicMock()

        class MinimalModule:
            module_id = "test_mod"

            def capability_profiles(self):
                return []

            def required_tools(self):
                return ["some.tool"]

            def report_filter_keys(self):
                return []

            def register_tools(self, *args, **kwargs):
                pass

            def build_runtime(self, context):
                return MagicMock()

            def filter_report_rows(self, rows, filters=None):
                return rows

            def seed_data(self, session):
                pass

            def route_specs(self):
                return []

        mod = MinimalModule()
        result = await ModuleProtocol.report_count(mod, run_id="some-run-id", session=mock_session)
        assert result == {}

