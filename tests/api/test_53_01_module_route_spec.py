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

    def test_construct_minimal_spec(self) -> None:
        """ModuleRouteSpec(prefix='/x', router_factory=fn) works with only required fields."""
        from aila.platform.modules.protocol import ModuleRouteSpec

        spec = ModuleRouteSpec(prefix="/x", router_factory=lambda: None)
        assert spec.prefix == "/x"
        assert spec.router_factory is not None

    def test_tool_keys_defaults_to_empty_tuple(self) -> None:
        """tool_keys defaults to empty tuple (not list -- frozen dataclass requires immutable)."""
        from aila.platform.modules.protocol import ModuleRouteSpec

        spec = ModuleRouteSpec(prefix="/x", router_factory=lambda: None)
        assert spec.tool_keys == ()
        assert isinstance(spec.tool_keys, tuple)

    def test_config_namespace_defaults_to_none(self) -> None:
        """config_namespace defaults to None."""
        from aila.platform.modules.protocol import ModuleRouteSpec

        spec = ModuleRouteSpec(prefix="/x", router_factory=lambda: None)
        assert spec.config_namespace is None

    def test_payload_type_defaults_to_none(self) -> None:
        """payload_type defaults to None."""
        from aila.platform.modules.protocol import ModuleRouteSpec

        spec = ModuleRouteSpec(prefix="/x", router_factory=lambda: None)
        assert spec.payload_type is None

    def test_construct_full_spec_with_all_fields(self) -> None:
        """All fields can be set explicitly."""
        from aila.platform.modules.protocol import ModuleRouteSpec

        def my_factory():
            return None

        spec = ModuleRouteSpec(
            prefix="/vulnerability",
            router_factory=my_factory,
            tool_keys=("vuln.findings", "vuln.reports"),
            config_namespace="vulnerability",
            payload_type="VulnPayload",
        )
        assert spec.prefix == "/vulnerability"
        assert spec.router_factory is my_factory
        assert spec.tool_keys == ("vuln.findings", "vuln.reports")
        assert spec.config_namespace == "vulnerability"
        assert spec.payload_type == "VulnPayload"

    def test_is_frozen(self) -> None:
        """ModuleRouteSpec is frozen -- mutation raises FrozenInstanceError."""
        from dataclasses import FrozenInstanceError

        from aila.platform.modules.protocol import ModuleRouteSpec

        spec = ModuleRouteSpec(prefix="/x", router_factory=lambda: None)
        with pytest.raises(FrozenInstanceError):
            spec.prefix = "/y"  # type: ignore[misc]

    def test_old_action_id_field_absent(self) -> None:
        """Legacy action_id field does not exist on the new ModuleRouteSpec."""
        from aila.platform.modules.protocol import ModuleRouteSpec

        spec = ModuleRouteSpec(prefix="/x", router_factory=lambda: None)
        assert not hasattr(spec, "action_id")

    def test_old_http_method_field_absent(self) -> None:
        """Legacy http_method field does not exist on the new ModuleRouteSpec."""
        from aila.platform.modules.protocol import ModuleRouteSpec

        spec = ModuleRouteSpec(prefix="/x", router_factory=lambda: None)
        assert not hasattr(spec, "http_method")

    def test_old_path_field_absent(self) -> None:
        """Legacy path field does not exist on the new ModuleRouteSpec."""
        from aila.platform.modules.protocol import ModuleRouteSpec

        spec = ModuleRouteSpec(prefix="/x", router_factory=lambda: None)
        assert not hasattr(spec, "path")

    def test_old_request_model_field_absent(self) -> None:
        """Legacy request_model field does not exist on the new ModuleRouteSpec."""
        from aila.platform.modules.protocol import ModuleRouteSpec

        spec = ModuleRouteSpec(prefix="/x", router_factory=lambda: None)
        assert not hasattr(spec, "request_model")

    def test_old_response_model_field_absent(self) -> None:
        """Legacy response_model field does not exist on the new ModuleRouteSpec."""
        from aila.platform.modules.protocol import ModuleRouteSpec

        spec = ModuleRouteSpec(prefix="/x", router_factory=lambda: None)
        assert not hasattr(spec, "response_model")

    def test_spec_importable_from_package_barrel(self) -> None:
        """ModuleRouteSpec is re-exported from aila.platform.modules."""
        from aila.platform.modules import ModuleRouteSpec

        spec = ModuleRouteSpec(prefix="/x", router_factory=lambda: None)
        assert spec.prefix == "/x"


class TestModuleProtocolNewMethods:
    """ModuleProtocol gains system_summary() and report_count() with default {} return."""

    def test_system_summary_method_exists_on_protocol(self) -> None:
        """ModuleProtocol has a system_summary method."""
        from aila.platform.modules.protocol import ModuleProtocol

        assert hasattr(ModuleProtocol, "system_summary")

    def test_report_count_method_exists_on_protocol(self) -> None:
        """ModuleProtocol has a report_count method."""
        from aila.platform.modules.protocol import ModuleProtocol

        assert hasattr(ModuleProtocol, "report_count")

    async def test_system_summary_default_returns_empty_dict(self) -> None:
        """ModuleProtocol.system_summary default implementation returns {}.

        The Protocol default is ``async def`` (protocol.py declares it with a
        coroutine signature), so callers must await the return value.
        """
        from unittest.mock import MagicMock

        from aila.platform.modules.protocol import ModuleProtocol

        # We call the default implementation directly through the class method
        mock_session = MagicMock()

        # Create a minimal concrete class satisfying the protocol
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
        # system_summary is an optional async method defined on the Protocol class
        result = await ModuleProtocol.system_summary(mod, system_id=1, session=mock_session)
        assert result == {}

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

    def test_route_specs_still_returns_empty_list(self) -> None:
        """route_specs() default still returns [] (backwards compatibility)."""
        from unittest.mock import MagicMock

        from aila.platform.modules.protocol import ModuleProtocol

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

        mod = MinimalModule()
        result = ModuleProtocol.route_specs(mod)
        assert result == []
