"""Adapter base types — AdapterContext + AdapterFn + AdapterResult."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from aila.modules.vr.contracts import PayloadKind

__all__ = [
    "AdapterContext",
    "AdapterFn",
    "AdapterResult",
    "get_read_tools",
    "is_read_tool",
    "register_read_tool",
]


@dataclass(slots=True)
class AdapterContext:
    """Metadata threaded through every adapter call for traceability."""

    mcp_server_id: str
    tool_name: str
    investigation_id: str
    branch_id: str
    call_id: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AdapterResult:
    """One adapter's output: a typed message payload + observables delta.

    The executor writes a new ENGINE message with ``payload_kind`` +
    ``payload`` for the operator UI, and merges ``observables_delta``
    into the branch's ReasoningCaseState so the next reasoning turn
    sees the tool result.
    """

    payload_kind: PayloadKind
    payload: dict[str, Any]
    observables_delta: dict[str, Any] = field(default_factory=dict)
    summary: str = ""


AdapterFn = Callable[[dict[str, Any], AdapterContext], AdapterResult]
"""Pure function: (raw MCP response, context) -> AdapterResult.

Adapters MUST be pure — no DB writes, no MCP calls, no side effects.
The executor (tool_executor.py) owns dispatch + persistence.
"""


# fix §200 — registry of "read source / trace flow" tools, used by the
# tool_executor to decide whether the current call satisfies an
# outstanding survey-streak pivot directive. Populated at import time
# by the ``@is_read_tool(server, tool)`` decorator applied to each
# specialised adapter, plus any tools registered explicitly via
# :func:`register_read_tool` (e.g. generic-adapter-backed entries).
#
# Falling back to the hardcoded list lives in tool_executor itself so
# that an environment which never imported the adapter modules (e.g. a
# narrow unit test) still gets the correct behaviour.
_REGISTERED_READ_TOOLS: set[tuple[str, str]] = set()

F = TypeVar("F", bound=Callable[..., Any])


def is_read_tool(server_id: str, tool_name: str) -> Callable[[F], F]:
    """Decorator marking an adapter as a "read source / trace flow" tool.

    The tool_executor's pivot directive (``_directive.pivot``) is only
    cleared when one of these tools is called — surveys, metadata
    lookups, and search-only lookups do not satisfy the directive.
    Registration happens once at module import time; the decorator
    leaves the wrapped function unmodified.
    """

    def decorator(fn: F) -> F:
        _REGISTERED_READ_TOOLS.add((server_id, tool_name))
        return fn

    return decorator


def register_read_tool(server_id: str, tool_name: str) -> None:
    """Imperative counterpart to ``@is_read_tool`` for tools that use
    the generic adapter and therefore have no dedicated function to
    decorate."""
    _REGISTERED_READ_TOOLS.add((server_id, tool_name))


def get_read_tools() -> frozenset[tuple[str, str]]:
    """Snapshot of every (server, tool) pair marked as a read tool."""
    return frozenset(_REGISTERED_READ_TOOLS)
