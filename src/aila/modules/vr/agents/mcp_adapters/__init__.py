"""MCP adapters (M3.R-3).

Per the no-overengineering rule: AILA does not implement enrichment
heuristics. The MCP servers (IDA Headless MCP, audit-mcp) already do
the analysis. Adapters here are TINY pure functions that convert one
raw MCP response into:

  1. A typed D-44 message payload for the operator UI (or PayloadKind.TEXT
     when no specific kind fits — see M3.R-3 notes on TOOL_RESULT
     payload kind addition deferred).
  2. An ``observables`` delta merged into the branch's
     ReasoningCaseState so the next reasoning turn sees the result.

Only the adapters actually used by the v0.3 audit prompt ship in this
commit. Add new adapters per-tool when an investigation actually
invokes them. Don't pre-build adapters for tools nobody calls yet.
"""
from __future__ import annotations

from .base import (
    AdapterContext,
    AdapterFn,
    AdapterResult,
)
from .registry import get_adapter, registered_tools

__all__ = [
    "AdapterContext",
    "AdapterFn",
    "AdapterResult",
    "get_adapter",
    "registered_tools",
]
