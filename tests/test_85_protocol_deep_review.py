"""Phase 85 deep review: ModuleProtocol defaults and ModuleRouteSpec contract.

Tests verify:
- Every optional protocol method has a working default that does not raise
- Both vulnerability and hello_world modules satisfy isinstance(ModuleProtocol)
- ModuleRouteSpec has all fields consumed by _mount_module_routers()
- A minimal class with only required methods + inherited defaults passes isinstance
- ModuleRouteSpec is frozen (mutation rejected)
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from unittest.mock import MagicMock

import pytest

from aila.platform.modules.protocol import (
    ModuleCapabilityProfile,
    ModuleContext,
    ModuleProtocol,
    ModuleRouteSpec,
    ModuleRuntime,
)

__all__ = [
    "TestProtocolDefaults",
    "TestModuleCompliance",
    "TestRouteSpecContract",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _MinimalModule(ModuleProtocol):
    """Bare-minimum module implementing only truly required methods.

    Inherits defaults for report_filter_keys, filter_report_rows, seed_data,
    route_specs, system_summary, system_findings, report_count, health_checks.
    """

    module_id = "minimal"

    def capability_profiles(self) -> list[ModuleCapabilityProfile]:
        return [
            ModuleCapabilityProfile(
                module_id=self.module_id,
                action_id="minimal.run",
                description="Minimal test action",
                tools=["some.tool"],
                examples=["do something"],
            )
        ]

    def required_tools(self) -> list[str]:
        return ["some.tool"]

    def register_tools(self, tool_registry, settings, registry=None, schema_registry=None):
        pass

    def build_runtime(self, context: ModuleContext) -> ModuleRuntime:
        return MagicMock(spec=ModuleRuntime, module_id=self.module_id)


# ---------------------------------------------------------------------------
# Class 1: Protocol default implementations
# ---------------------------------------------------------------------------


class TestProtocolDefaults:
    """Every optional protocol method returns a sensible default without raising."""

    @pytest.fixture()
    def module(self) -> _MinimalModule:
        return _MinimalModule()

    def test_report_filter_keys_default_empty_list(self, module: _MinimalModule) -> None:
        """report_filter_keys() defaults to [] for modules without filterable reports."""
        result = module.report_filter_keys()
        assert result == []
        assert isinstance(result, list)

    def test_filter_report_rows_default_passthrough(self, module: _MinimalModule) -> None:
        """filter_report_rows() defaults to returning all rows unchanged."""
        rows = [{"cve_id": "CVE-2024-0001"}, {"cve_id": "CVE-2024-0002"}]
        result = module.filter_report_rows(rows)
        assert result == rows
        assert result is not rows  # must be a copy

    def test_filter_report_rows_default_ignores_filters(self, module: _MinimalModule) -> None:
        """filter_report_rows() default passthrough ignores any filter dict."""
        rows = [{"a": 1}, {"b": 2}]
        result = module.filter_report_rows(rows, filters={"a": "1"})
        assert result == rows

    @pytest.mark.asyncio
    async def test_seed_data_default_noop(self, module: _MinimalModule) -> None:
        """seed_data() defaults to a no-op that returns None."""
        result = await module.seed_data(session=MagicMock())
        assert result is None

    def test_route_specs_default_empty_list(self, module: _MinimalModule) -> None:
        """route_specs() defaults to [] for modules without HTTP routes."""
        result = module.route_specs()
        assert result == []

    @pytest.mark.asyncio
    async def test_system_summary_default_empty_dict(self, module: _MinimalModule) -> None:
        """system_summary() defaults to {} for modules without system data."""
        result = await module.system_summary(system_id=1, session=MagicMock())
        assert result == {}

    @pytest.mark.asyncio
    async def test_system_findings_default_empty_result(self, module: _MinimalModule) -> None:
        """system_findings() defaults to {'items': [], 'total': 0}."""
        result = await module.system_findings(
            system_id=1, system_name="test", session=MagicMock(),
        )
        assert result == {"items": [], "total": 0}

    @pytest.mark.asyncio
    async def test_report_count_default_empty_dict(self, module: _MinimalModule) -> None:
        """report_count() defaults to {} for modules without reports."""
        result = await module.report_count(run_id="run-123", session=MagicMock())
        assert result == {}

    def test_health_checks_default_empty_dict(self, module: _MinimalModule) -> None:
        """health_checks() defaults to {} for modules without health checks."""
        result = module.health_checks()
        assert result == {}

    def test_minimal_module_isinstance_protocol(self, module: _MinimalModule) -> None:
        """A minimal class with only required methods passes isinstance(ModuleProtocol)."""
        assert isinstance(module, ModuleProtocol)


# ---------------------------------------------------------------------------
# Class 2: Module compliance (vulnerability + hello_world)
# ---------------------------------------------------------------------------


class TestModuleCompliance:
    """Both vulnerability and hello_world modules satisfy ModuleProtocol."""

    def test_vulnerability_isinstance(self) -> None:
        """VulnerabilityModule passes isinstance(ModuleProtocol)."""
        from aila.modules.vulnerability.module import VulnerabilityModule

        module = VulnerabilityModule()
        assert isinstance(module, ModuleProtocol)

    def test_hello_world_isinstance(self) -> None:
        """HelloWorldModule passes isinstance(ModuleProtocol)."""
        from aila.modules.hello_world.module import HelloWorldModule

        module = HelloWorldModule()
        assert isinstance(module, ModuleProtocol)

    def test_vulnerability_all_protocol_methods_present(self) -> None:
        """VulnerabilityModule has every method defined on ModuleProtocol."""
        from aila.modules.vulnerability.module import VulnerabilityModule

        module = VulnerabilityModule()
        protocol_methods = [
            "capability_profiles", "required_tools", "report_filter_keys",
            "register_tools", "build_runtime", "filter_report_rows",
            "seed_data", "route_specs", "system_summary", "system_findings",
            "report_count", "health_checks",
        ]
        for method_name in protocol_methods:
            assert hasattr(module, method_name), f"Missing: {method_name}"
            assert callable(getattr(module, method_name)), f"Not callable: {method_name}"

    def test_hello_world_all_protocol_methods_present(self) -> None:
        """HelloWorldModule has every method defined on ModuleProtocol."""
        from aila.modules.hello_world.module import HelloWorldModule

        module = HelloWorldModule()
        protocol_methods = [
            "capability_profiles", "required_tools", "report_filter_keys",
            "register_tools", "build_runtime", "filter_report_rows",
            "seed_data", "route_specs", "system_summary", "system_findings",
            "report_count", "health_checks",
        ]
        for method_name in protocol_methods:
            assert hasattr(module, method_name), f"Missing: {method_name}"
            assert callable(getattr(module, method_name)), f"Not callable: {method_name}"

    def test_vulnerability_capability_profiles_non_empty(self) -> None:
        """VulnerabilityModule.capability_profiles() returns at least one profile."""
        from aila.modules.vulnerability.module import VulnerabilityModule

        profiles = VulnerabilityModule().capability_profiles()
        assert len(profiles) >= 1
        assert all(isinstance(p, ModuleCapabilityProfile) for p in profiles)

    def test_hello_world_capability_profiles_non_empty(self) -> None:
        """HelloWorldModule.capability_profiles() returns at least one profile."""
        from aila.modules.hello_world.module import HelloWorldModule

        profiles = HelloWorldModule().capability_profiles()
        assert len(profiles) >= 1
        assert all(isinstance(p, ModuleCapabilityProfile) for p in profiles)

    def test_vulnerability_route_specs_returns_module_route_spec(self) -> None:
        """VulnerabilityModule.route_specs() returns list of ModuleRouteSpec."""
        from aila.modules.vulnerability.module import VulnerabilityModule

        specs = VulnerabilityModule().route_specs()
        assert isinstance(specs, list)
        assert len(specs) >= 1
        for spec in specs:
            assert isinstance(spec, ModuleRouteSpec)
            assert spec.prefix
            assert callable(spec.router_factory)

    def test_hello_world_route_specs_returns_module_route_spec(self) -> None:
        """HelloWorldModule.route_specs() returns list of ModuleRouteSpec."""
        from aila.modules.hello_world.module import HelloWorldModule

        specs = HelloWorldModule().route_specs()
        assert isinstance(specs, list)
        assert len(specs) >= 1
        for spec in specs:
            assert isinstance(spec, ModuleRouteSpec)
            assert spec.prefix
            assert callable(spec.router_factory)


# ---------------------------------------------------------------------------
# Class 3: ModuleRouteSpec contract completeness
# ---------------------------------------------------------------------------


class TestRouteSpecContract:
    """ModuleRouteSpec has all fields consumed by _mount_module_routers()."""

    def test_has_prefix_field(self) -> None:
        """ModuleRouteSpec has a prefix field (used by include_router)."""
        spec = ModuleRouteSpec(prefix="/test", router_factory=lambda: None)
        assert spec.prefix == "/test"

    def test_has_router_factory_field(self) -> None:
        """ModuleRouteSpec has a router_factory field (used by include_router)."""
        factory = lambda: None  # noqa: E731
        spec = ModuleRouteSpec(prefix="/test", router_factory=factory)
        assert spec.router_factory is factory

    def test_has_tool_keys_metadata(self) -> None:
        """ModuleRouteSpec has tool_keys for module tool metadata."""
        spec = ModuleRouteSpec(
            prefix="/test",
            router_factory=lambda: None,
            tool_keys=("tool.a", "tool.b"),
        )
        assert spec.tool_keys == ("tool.a", "tool.b")

    def test_has_config_namespace_metadata(self) -> None:
        """ModuleRouteSpec has config_namespace for module config metadata."""
        spec = ModuleRouteSpec(
            prefix="/test",
            router_factory=lambda: None,
            config_namespace="test_ns",
        )
        assert spec.config_namespace == "test_ns"

    def test_has_payload_type_metadata(self) -> None:
        """ModuleRouteSpec has payload_type for discriminated union metadata."""
        spec = ModuleRouteSpec(
            prefix="/test",
            router_factory=lambda: None,
            payload_type="TestPayload",
        )
        assert spec.payload_type == "TestPayload"

    def test_no_tags_field(self) -> None:
        """ModuleRouteSpec does NOT have a tags field.

        Tags are set by the router_factory itself (ownership boundary).
        The platform does not need to inject tags from the spec.
        """
        spec = ModuleRouteSpec(prefix="/test", router_factory=lambda: None)
        assert not hasattr(spec, "tags")

    def test_no_dependencies_field(self) -> None:
        """ModuleRouteSpec does NOT have a dependencies field.

        Dependencies (auth) are platform-level concerns added at mount time.
        Modules do not declare their own auth dependencies.
        """
        spec = ModuleRouteSpec(prefix="/test", router_factory=lambda: None)
        assert not hasattr(spec, "dependencies")

    def test_frozen_rejects_mutation(self) -> None:
        """ModuleRouteSpec is frozen -- mutation raises FrozenInstanceError."""
        spec = ModuleRouteSpec(prefix="/test", router_factory=lambda: None)
        with pytest.raises(FrozenInstanceError):
            spec.prefix = "/changed"  # type: ignore[misc]

    def test_slots_enabled(self) -> None:
        """ModuleRouteSpec uses slots for memory efficiency."""
        spec = ModuleRouteSpec(prefix="/test", router_factory=lambda: None)
        assert hasattr(type(spec), "__slots__")
