"""Hello-world module smoke test suite (Phase 63-04).

Proves the module contract works end-to-end for a fresh module scaffolded
from _template. The hello_world module registers routes, tools, and config
at the API without touching any platform code.

16 tests covering:
  - Layout and factory validation
  - Module identity and protocol compliance
  - Auto-discovery without platform edits
  - Route spec and router factory
  - Tool registration
  - Capability profiles
  - Default method behavior (system_summary, report_count, health_checks)
  - Runtime construction
  - Zero platform code coupling
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi import APIRouter

from aila.modules.hello_world.module import create_module
from aila.platform.modules.protocol import ModuleProtocol
from aila.platform.modules.standard import build_module_factory, validate_module_layout

__all__ = ["TestHelloWorldModuleSmoke"]

_SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "aila"


class TestHelloWorldModuleSmoke:
    """Prove the module system works end-to-end for a fresh module."""

    @pytest.fixture()
    def module(self):
        """Return a fresh HelloWorldModule instance via create_module()."""
        return create_module()

    # 1. Layout validation
    def test_layout_validation(self):
        """validate_module_layout('aila.modules.hello_world') does not raise."""
        validate_module_layout("aila.modules.hello_world")

    # 2. Factory validation
    def test_factory_validation(self):
        """build_module_factory returns a callable producing a ModuleProtocol instance."""
        factory = build_module_factory("aila.modules.hello_world")
        assert callable(factory)
        instance = factory()
        assert isinstance(instance, ModuleProtocol)

    # 3. Module ID matches folder
    def test_module_id_matches_folder(self, module):
        """module_id must be 'hello_world' (matching the package directory)."""
        assert module.module_id == "hello_world"

    # 4. isinstance ModuleProtocol
    def test_isinstance_module_protocol(self, module):
        """Module instance must satisfy the runtime-checkable ModuleProtocol."""
        assert isinstance(module, ModuleProtocol)

    # 5. Auto-discovery includes hello_world
    def test_auto_discovery_includes_hello_world(self):
        """builtin_module_factories() discovers hello_world without platform edits.

        Must clear lru_cache first to ensure fresh discovery.
        """
        from aila.platform.modules.builtin import (
            _discover_feature_module_factories,
            builtin_module_factories,
        )

        # Clear caches to force rediscovery
        builtin_module_factories.cache_clear()
        _discover_feature_module_factories.cache_clear()

        try:
            factories = builtin_module_factories()
            module_ids = []
            for factory in factories:
                try:
                    m = factory()
                    module_ids.append(getattr(m, "module_id", None))
                except Exception:  # noqa: BLE001
                    continue
            assert "hello_world" in module_ids, (
                f"hello_world not found in auto-discovered modules: {module_ids}"
            )
        finally:
            # Clear caches again to avoid poisoning other tests
            builtin_module_factories.cache_clear()
            _discover_feature_module_factories.cache_clear()

    # 6. Route specs non-empty
    def test_route_specs_non_empty(self, module):
        """module.route_specs() returns at least one spec."""
        specs = module.route_specs()
        assert len(specs) >= 1

    # 7. Route spec prefix
    def test_route_spec_prefix(self, module):
        """spec.prefix must be '/hello_world'."""
        specs = module.route_specs()
        assert specs[0].prefix == "/hello_world"

    # 8. Router factory returns APIRouter
    def test_router_factory_returns_router(self, module):
        """spec.router_factory() returns a FastAPI APIRouter."""
        specs = module.route_specs()
        router = specs[0].router_factory()
        assert isinstance(router, APIRouter)

    # 9. Router has routes
    def test_router_has_routes(self, module):
        """The returned router has at least one route."""
        specs = module.route_specs()
        router = specs[0].router_factory()
        assert len(router.routes) >= 1

    # 10. Tool registration
    @pytest.mark.asyncio
    async def test_tool_registration(self, module):
        """register_tools registers the tool under 'hello_world.greet' key."""
        mock_registry = MagicMock()
        mock_settings = MagicMock()
        await module.register_tools(mock_registry, mock_settings)
        mock_registry.register.assert_called_once()
        call_args = mock_registry.register.call_args
        assert call_args[0][0] == "hello_world.greet"
    # 11. Capability profiles
    def test_capability_profiles(self, module):
        """Non-empty profiles with matching module_id and correct action_id prefix."""
        profiles = module.capability_profiles()
        assert len(profiles) >= 1
        for profile in profiles:
            assert profile.module_id == "hello_world"
            assert profile.action_id.startswith("hello_world.")

    # 12. System summary default
    @pytest.mark.asyncio
    async def test_system_summary_default(self, module):
        """system_summary returns {} with system_id=0, session=None."""
        result = await module.system_summary(system_id=0, session=None)
        assert result == {}

    # 13. Report count default
    @pytest.mark.asyncio
    async def test_report_count_default(self, module):
        """report_count returns {} with run_id='x', session=None."""
        result = await module.report_count(run_id="x", session=None)
        assert result == {}

    # 14. Health checks default
    def test_health_checks_default(self, module):
        """health_checks returns {}."""
        result = module.health_checks()
        assert result == {}

    # 15. Build runtime
    def test_build_runtime(self, module):
        """build_runtime returns a ModuleRuntime with handle() method."""
        mock_context = MagicMock()
        # The module ignores context (del context), so mock is fine
        runtime = module.build_runtime(mock_context)
        assert hasattr(runtime, "module_id")
        assert runtime.module_id == "hello_world"
        assert hasattr(runtime, "handle")
        assert callable(runtime.handle)

    # 16. No platform code modified
    def test_no_platform_code_modified(self):
        """No file under src/aila/platform/ or src/aila/api/ contains 'hello_world'.

        This proves zero platform edits were needed to register this module.
        """
        for search_dir in (_SRC_ROOT / "platform", _SRC_ROOT / "api"):
            if not search_dir.is_dir():
                continue
            for py_file in search_dir.rglob("*.py"):
                content = py_file.read_text(encoding="utf-8")
                assert "hello_world" not in content, (
                    f"Platform/API file {py_file.relative_to(_SRC_ROOT)} "
                    f"contains 'hello_world' -- module should register without platform edits"
                )
