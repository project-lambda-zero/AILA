"""MCP adapters (M3.R-3 + v0.3 v2 expansion).

Per the no-overengineering rule: AILA does not implement enrichment
heuristics. The MCP servers (IDA Headless MCP, audit-mcp) already do
the analysis. Adapters here are TINY pure functions that convert one
raw MCP response into:

  1. A typed D-44 ``PayloadKind`` message for the operator UI
     (DECOMPILED_FUNCTION / XREF_VIEW / TAINT_FLOW / GRAPH_VIEW /
     CODE_POINTER / PATCH_DIFF / TEXT).
  2. An ``observables`` delta merged into the branch's
     ReasoningCaseState so the next reasoning turn sees a bounded
     summary of the result (not the whole 50KB blob).

Coverage (v0.3 v2):

  - **Specialized adapters** for ~25 tools where structured rendering
    materially helps (decompile, xrefs, taint, call graphs, diffs,
    mitigations, ...).
  - **Generic adapter** for the remaining ~110 tools across the two MCP
    servers — every tool in ``KNOWN_TOOLS`` is callable immediately;
    structured rendering is added per-tool as real investigations need it.
"""
from __future__ import annotations

from .base import (
    AdapterContext,
    AdapterFn,
    AdapterResult,
)
from .known_tools import AUDIT_MCP_TOOLS, IDA_HEADLESS_TOOLS, KNOWN_TOOLS
from .registry import get_adapter, registered_tools, specialized_tools

__all__ = [
    "AUDIT_MCP_TOOLS",
    "AdapterContext",
    "AdapterFn",
    "AdapterResult",
    "IDA_HEADLESS_TOOLS",
    "KNOWN_TOOLS",
    "get_adapter",
    "registered_tools",
    "specialized_tools",
]
