"""ModuleRegistry.unregister test for issue #41.

Proves the registry supports a symmetric unregister: a registered module can be
removed and, when the caller passes the shared ToolRegistry, every tool key the
module owns is stripped from that registry too. Platform-owned tool keys
declared by the module (e.g. ``module_status``) are left alone -- unregistering
them would break every other registered module.

Route surface: routes returned by ``route_specs()`` are collected at startup by
the FastAPI mount pass, so the observable behaviour after ``unregister`` is
that ``ModuleRegistry.modules`` and ``capability_profiles()`` no longer see
the module -- any subsequent enumeration of route specs runs over the reduced
membership. The test asserts this shape.
"""
from __future__ import annotations

import pytest

from aila.platform.modules import (
    ModuleCapabilityProfile,
    ModuleProtocol,
    ModuleRegistry,
    ModuleRouteSpec,
    action_id_for,
)
from aila.platform.runtime import ToolRegistry
from aila.platform.runtime.builder import PLATFORM_TOOL_KEYS


class _FakeTool:
    """Minimal ToolProtocol implementation used only inside this test."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.description = f"fake tool {name}"

    def forward(self, *_args: object, **_kwargs: object) -> str:
        return self.name


class _FakeModule(ModuleProtocol):
    """Fake module that declares one owned tool key plus one platform tool key.

    The registry unregister path must drop the owned key but leave the platform
    key untouched.
    """

    module_id = "fake_ext"
    owned_tool_key = "fake_ext.echo"
    action = action_id_for("fake_ext", "echo")

    def capability_profiles(self) -> list[ModuleCapabilityProfile]:
        return [
            ModuleCapabilityProfile(
                module_id=self.module_id,
                action_id=self.action,
                description="Echoes input back for the unregister test.",
                tools=[self.owned_tool_key],
                examples=["echo hello"],
            )
        ]

    def required_tools(self) -> list[str]:
        # One owned key + one platform key. Only the owned key should disappear.
        return [self.owned_tool_key, "module_status"]

    def route_specs(self) -> list[ModuleRouteSpec]:
        def factory() -> object:  # pragma: no cover - never called in this test
            raise AssertionError("route factory should not be invoked")

        return [
            ModuleRouteSpec(
                prefix="/fake_ext",
                router_factory=factory,
                tool_keys=(self.owned_tool_key,),
            )
        ]

    async def register_tools(
        self, tool_registry, settings, registry=None, schema_registry=None,
    ) -> None:
        del settings, registry, schema_registry
        tool_registry.register(self.owned_tool_key, _FakeTool(self.owned_tool_key))

    def build_runtime(self, context):  # pragma: no cover - unused here
        raise AssertionError("build_runtime should not be invoked")


def _seed_platform_and_module_tools() -> tuple[ToolRegistry, _FakeModule]:
    tool_registry = ToolRegistry()
    tool_registry.register("module_status", _FakeTool("module_status"))
    module = _FakeModule()
    tool_registry.register(module.owned_tool_key, _FakeTool(module.owned_tool_key))
    assert "module_status" in PLATFORM_TOOL_KEYS  # invariant this test relies on
    return tool_registry, module


def test_unregister_returns_module_and_removes_from_registry() -> None:
    registry = ModuleRegistry()
    module = _FakeModule()
    registry.register(module)

    removed = registry.unregister(module.module_id)

    assert removed is module
    assert registry.modules == []
    with pytest.raises(KeyError):
        registry.require(module.module_id)


def test_unregister_hides_capability_profiles_and_route_specs() -> None:
    registry = ModuleRegistry()
    module = _FakeModule()
    registry.register(module)

    registry.unregister(module.module_id)

    # capability profiles are collected across registered modules -- an
    # unregistered module contributes nothing.
    assert registry.capability_profiles() == []
    # No registered module can still contribute the route spec either.
    route_specs: list[ModuleRouteSpec] = []
    for surviving in registry.modules:
        route_specs.extend(surviving.route_specs())
    assert route_specs == []


def test_unregister_strips_owned_tools_and_preserves_platform_tools() -> None:
    tool_registry, module = _seed_platform_and_module_tools()
    registry = ModuleRegistry()
    registry.register(module)

    registry.unregister(module.module_id, tool_registry=tool_registry)

    assert module.owned_tool_key not in tool_registry.keys
    assert "module_status" in tool_registry.keys, (
        "PLATFORM_TOOL_KEYS entries must survive module unregister -- "
        "they are shared by every other module."
    )


def test_unregister_unknown_module_id_raises() -> None:
    registry = ModuleRegistry()
    with pytest.raises(KeyError):
        registry.unregister("no_such_module")


def test_unregister_is_idempotent_after_first_call() -> None:
    registry = ModuleRegistry()
    registry.register(_FakeModule())
    registry.unregister("fake_ext")
    with pytest.raises(KeyError):
        registry.unregister("fake_ext")


def test_unregister_survives_missing_tool_registry_entry() -> None:
    """Owned key that was never registered must not raise on unregister."""
    tool_registry = ToolRegistry()
    tool_registry.register("module_status", _FakeTool("module_status"))
    # NOTE: skip registering module.owned_tool_key on purpose.
    registry = ModuleRegistry()
    module = _FakeModule()
    registry.register(module)

    # Should silently skip the missing key rather than raising KeyError from
    # the tool_registry.
    registry.unregister(module.module_id, tool_registry=tool_registry)

    assert module.owned_tool_key not in tool_registry.keys
    assert "module_status" in tool_registry.keys


def test_register_after_unregister_reuses_module_id() -> None:
    registry = ModuleRegistry()
    module = _FakeModule()
    registry.register(module)
    registry.unregister(module.module_id)

    # Registering the same module again after unregister must succeed --
    # the ID slot is free.
    registry.register(_FakeModule())
    assert [m.module_id for m in registry.modules] == ["fake_ext"]


def test_tool_registry_unregister_returns_tool() -> None:
    tool_registry = ToolRegistry()
    tool = _FakeTool("standalone")
    tool_registry.register("standalone", tool)

    removed = tool_registry.unregister("standalone")

    assert removed is tool
    assert "standalone" not in tool_registry.keys
    with pytest.raises(KeyError):
        tool_registry.unregister("standalone")

