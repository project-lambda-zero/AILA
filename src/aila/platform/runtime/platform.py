from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..modules.protocol import ModuleRuntime
from ..modules.registry import ModuleRegistry
from .tools import ToolRegistry

if TYPE_CHECKING:
    from ...storage.registry import ConfigRegistry
    from ..llm import AilaLLMClient


@dataclass(slots=True)
class PlatformRuntime:
    """The assembled runtime state of a running platform instance.

    Produced by build_platform_runtime() and held by AILAPlatform for the
    lifetime of the process. Carries the module registry (for capability profile
    lookups during routing), individual module runtimes (for dispatch), the
    global tool registry, the shared LLM model instance, and the config registry.
    """

    module_registry: ModuleRegistry
    modules: dict[str, ModuleRuntime]
    tool_registry: ToolRegistry
    runtime_model: AilaLLMClient
    config_registry: ConfigRegistry | None = field(default=None)

    def require_module(self, module_id: str) -> ModuleRuntime:
        """Return the active runtime for the given module ID.

        Raises KeyError if the module is not present, listing available modules
        so callers can produce actionable error messages.
        """
        if module_id not in self.modules:
            available = ", ".join(sorted(self.modules))
            raise KeyError(f"Module {module_id!r} is not active. Available: {available}.")
        return self.modules[module_id]
