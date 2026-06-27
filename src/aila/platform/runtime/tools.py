from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, TypeVar, runtime_checkable


@runtime_checkable
class ToolProtocol(Protocol):
    """The minimum interface any platform-registered tool must satisfy.

    Defines name, description, and forward() as the standard tool contract.
    Platform tools inherit from Tool base class; this Protocol allows
    testing with simple mock objects without inheritance.
    """

    name: str
    description: str

    def forward(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the tool's action and return the result."""
        ...


TTool = TypeVar("TTool", bound=ToolProtocol)


@runtime_checkable
class ToolAccess(Protocol):
    """Read-only view into a set of registered tools for use inside module runtimes.

    Implemented by both ToolRegistry (full registry) and ToolScope (per-module
    restricted subset). Module runtimes receive a ToolScope so they can only
    access the tools they declared in required_tools().
    """

    @property
    def keys(self) -> list[str]:
        """Return the tool keys available in this access context."""
        ...

    def require(self, key: str, expected_type: type[TTool] | None = None) -> ToolProtocol | TTool:
        """Return the tool registered under key, optionally asserting its concrete type."""
        ...


@dataclass(frozen=True, slots=True)
class ToolScope:
    """An immutable, per-module restricted view into the global tool registry.

    Created by ToolRegistry.scope() using the tool keys declared in a module's
    required_tools() merged with PLATFORM_TOOL_KEYS. Modules receive a ToolScope
    in their ModuleContext so they cannot access tools they have not declared.
    """

    _tools: dict[str, ToolProtocol]

    @property
    def tools(self) -> list[ToolProtocol]:
        return list(self._tools.values())

    @property
    def keys(self) -> list[str]:
        return list(self._tools.keys())

    def require(self, key: str, expected_type: type[TTool] | None = None) -> ToolProtocol | TTool:
        if key not in self._tools:
            available = ", ".join(sorted(self._tools))
            raise KeyError(f"Tool {key!r} is not available in this scope. Available: {available}.")
        tool = self._tools[key]
        if expected_type is not None and not isinstance(tool, expected_type):
            raise TypeError(
                f"Tool {key!r} is {type(tool).__name__}, expected {expected_type.__name__}."
            )
        return tool


class ToolRegistry:
    """The global registry of all platform and module tools for a runtime instance.

    Tools are registered once at startup via register(). Modules never access
    the registry directly -- they receive a ToolScope built from their declared
    required_tools() via scope(). This enforces tool access isolation: a module
    cannot call a tool it has not declared.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolProtocol] = {}

    @property
    def keys(self) -> list[str]:
        """Return all registered tool keys."""
        return list(self._tools.keys())

    def register(self, key: str, tool: ToolProtocol) -> ToolProtocol:
        """Register a tool under the given key.

        Raises ValueError if the key is already taken, preventing silent overwrites
        of platform tools by module tools or vice versa.
        """
        if key in self._tools:
            raise ValueError(f"Tool key {key!r} is already registered.")
        self._tools[key] = tool
        return tool

    def require(self, key: str, expected_type: type[TTool] | None = None) -> ToolProtocol | TTool:
        """Return the registered tool for key, optionally asserting its concrete type.

        Raises KeyError if the key is not registered and TypeError if the tool's
        type does not match expected_type.
        """
        if key not in self._tools:
            available = ", ".join(sorted(self._tools))
            raise KeyError(f"Tool {key!r} is not registered. Available: {available}.")
        tool = self._tools[key]
        if expected_type is not None and not isinstance(tool, expected_type):
            raise TypeError(
                f"Tool {key!r} is {type(tool).__name__}, expected {expected_type.__name__}."
            )
        return tool

    def scope(self, *keys: str) -> ToolScope:
        """Build an immutable ToolScope restricted to the given keys.

        Deduplicates keys using dict.fromkeys to preserve declaration order.
        Raises KeyError if any requested key is not registered, so missing tool
        declarations are caught at startup rather than at first use.
        """
        unique_keys = list(dict.fromkeys(keys))
        missing = [key for key in unique_keys if key not in self._tools]
        if missing:
            available = ", ".join(sorted(self._tools))
            raise KeyError(f"Tool scope includes unknown keys: {missing}. Available: {available}.")
        scoped = {key: self._tools[key] for key in unique_keys}
        return ToolScope(scoped)
