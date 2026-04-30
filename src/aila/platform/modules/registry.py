from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any

from ..config import ApplicationSettings
from ..runtime.tools import ToolRegistry
from .protocol import ModuleCapabilityProfile, ModuleContext, ModuleProtocol, ModuleRuntime

if TYPE_CHECKING:
    from ...storage.registry import ConfigRegistry, SchemaRegistry


class ModuleRegistry:
    """The single source of truth for all modules registered in a platform instance.

    Modules are registered once at startup via register(). After registration,
    the registry is used to resolve capability profiles for routing, build
    module-scoped tool registries, and dispatch requests to the correct runtime.
    Duplicate or invalid module IDs are rejected at registration time.
    """

    def __init__(self) -> None:
        self._modules: dict[str, ModuleProtocol] = {}

    def register(self, module: ModuleProtocol) -> ModuleProtocol:
        """Validate and add a module to the registry.

        Validates the module's ID format, capability profiles, and required tool
        declarations before storing. Raises ValueError if the module ID is already
        registered or fails any validation check.
        """
        self._validate_module(module)
        if module.module_id in self._modules:
            raise ValueError(f"Module {module.module_id!r} is already registered.")
        self._modules[module.module_id] = module
        return module

    @property
    def modules(self) -> list[ModuleProtocol]:
        return list(self._modules.values())

    def require(self, module_id: str) -> ModuleProtocol:
        """Return the registered module for the given ID, raising KeyError if absent."""
        if module_id not in self._modules:
            available = ", ".join(sorted(self._modules))
            raise KeyError(f"Module {module_id!r} is not registered. Available: {available}.")
        return self._modules[module_id]

    def capability_profiles(self) -> list[ModuleCapabilityProfile]:
        """Return capability profiles for all registered modules in registration order.

        Consumed by ModuleRouter to build the routing prompt. The combined list
        covers every action the platform can dispatch.
        """
        profiles: list[ModuleCapabilityProfile] = []
        for module in self.modules:
            profiles.extend(module.capability_profiles())
        return profiles

    async def register_tools(
        self,
        tool_registry: Any,
        settings: ApplicationSettings,
        registry: ConfigRegistry | None = None,
        schema_registry: SchemaRegistry | None = None,
    ) -> None:
        """Call register_tools() on every registered module in registration order.

        Runs once at platform startup to populate the global tool registry with
        all module-specific tools. Platform-level tools are registered separately
        by build_platform_runtime().
        """
        for module in self.modules:
            await module.register_tools(tool_registry, settings, registry, schema_registry)

    def build_runtimes(self, context: ModuleContext, tool_registry: ToolRegistry) -> dict[str, ModuleRuntime]:
        """Build and return a runtime instance for every registered module.

        Each module receives a tool scope restricted to its declared required_tools()
        merged with PLATFORM_TOOL_KEYS. This is the per-module isolation boundary —
        a module cannot call tools it has not declared.
        """
        from aila.platform.runtime.builder import PLATFORM_TOOL_KEYS  # local import avoids circular
        runtimes: dict[str, ModuleRuntime] = {}
        for module in self.modules:
            # Merge platform tool keys with module-declared keys (per D-06, D-07).
            # Deduplication is handled by dict.fromkeys inside tool_registry.scope().
            merged_keys = [*PLATFORM_TOOL_KEYS, *module.required_tools()]
            module_scope = tool_registry.scope(*merged_keys)
            module_context = replace(context, tool_registry=module_scope)
            runtimes[module.module_id] = module.build_runtime(module_context)
        return runtimes

    @staticmethod
    def _validate_module(module: ModuleProtocol) -> None:
        module_id = str(getattr(module, "module_id", "")).strip()
        if not _is_valid_module_id(module_id):
            raise ValueError(
                f"Module id '{module_id}' is invalid. "
                "Use lowercase letters, digits, and underscore, starting with a letter."
            )

        profiles = list(module.capability_profiles())
        if not profiles:
            raise ValueError(f"Module '{module_id}' must declare at least one capability profile.")
        seen_actions: set[str] = set()
        for profile in profiles:
            if profile.module_id != module_id:
                raise ValueError(
                    f"Module '{module_id}' capability profile '{profile.action_id}' declares module_id="
                    f"'{profile.module_id}', which is inconsistent."
                )
            if not profile.action_id.startswith(module_id + "."):
                raise ValueError(
                    f"Module '{module_id}' action id '{profile.action_id}' must start with '{module_id}.'"
                )
            if profile.action_id in seen_actions:
                raise ValueError(f"Module '{module_id}' has duplicate action id '{profile.action_id}'.")
            seen_actions.add(profile.action_id)
            if not profile.description.strip():
                raise ValueError(
                    f"Module '{module_id}' capability profile '{profile.action_id}' must include a description."
                )

        required_tool_keys = list(module.required_tools())
        if not required_tool_keys:
            raise ValueError(f"Module '{module_id}' must declare required_tools().")
        seen_tool_keys: set[str] = set()
        for tool_key in required_tool_keys:
            normalized = str(tool_key).strip()
            if not normalized:
                raise ValueError(f"Module '{module_id}' contains an empty required tool key.")
            if normalized in seen_tool_keys:
                raise ValueError(f"Module '{module_id}' repeats required tool key '{normalized}'.")
            seen_tool_keys.add(normalized)


def _is_valid_module_id(module_id: str) -> bool:
    if not module_id:
        return False
    first = module_id[0]
    if not ("a" <= first <= "z"):
        return False
    for character in module_id:
        if ("a" <= character <= "z") or ("0" <= character <= "9") or character == "_":
            continue
        return False
    return True
