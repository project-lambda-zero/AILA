"""Adapter base types — AdapterContext + AdapterFn + AdapterResult."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from aila.modules.vr.contracts import PayloadKind

__all__ = [
    "AdapterContext",
    "AdapterFn",
    "AdapterResult",
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
