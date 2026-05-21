"""Adapter registry — resolves (mcp_server_id, tool_name) -> AdapterFn.

Resolution order:

  1. Specialized adapter explicitly registered in ``_SPECIALIZED``
     (e.g. ``ida_headless.decompile`` -> ``adapt_decompile``).
  2. Generic adapter ``adapt_generic`` when the tool name is in
     ``KNOWN_TOOLS[server_id]`` but no specialized adapter exists.
  3. ``None`` when the tool name is unknown — tool_executor surfaces a
     loud error message back to the engine so it can retry with a
     correct name.

This means the engine can invoke any of the 135 MCP tools immediately;
tools with high-value structured rendering get specialized adapters as
they become useful in real investigations.
"""
from __future__ import annotations

from .audit_mcp import (
    adapt_attack_surface,
    adapt_callees_of,
    adapt_callers_of,
    adapt_complexity_hotspots,
    adapt_diff_codebases,
    adapt_export_graph,
    adapt_fuzzing_targets,
    adapt_paths_between,
    adapt_read_function,
    adapt_search_constants,
    adapt_search_functions,
    adapt_search_macros,
    adapt_search_source,
    adapt_search_types,
    adapt_taint_paths_to,
)
from .base import AdapterFn
from .generic import adapt_generic
from .ida_headless import (
    adapt_call_chain,
    adapt_call_graph,
    adapt_capa_scan,
    adapt_checksec,
    adapt_classify_behavior,
    adapt_decompile,
    adapt_def_use,
    adapt_diff_function,
    adapt_disassemble_function,
    adapt_find_api_call_sites,
    adapt_get_microcode,
    adapt_interprocedural_taint,
    adapt_pseudocode_slice_view,
    adapt_trace_dataflow,
    adapt_xrefs_from,
    adapt_xrefs_to,
)
from .known_tools import KNOWN_TOOLS

__all__ = [
    "get_adapter",
    "registered_tools",
    "specialized_tools",
]


# Specialized adapters. Keys: (server_id, tool_name).
_SPECIALIZED: dict[tuple[str, str], AdapterFn] = {
    # ida_headless — DECOMPILED_FUNCTION
    ("ida_headless", "decompile"): adapt_decompile,
    # ida_headless — XREF_VIEW family
    ("ida_headless", "find_api_call_sites"): adapt_find_api_call_sites,
    ("ida_headless", "xrefs_to"): adapt_xrefs_to,
    ("ida_headless", "xrefs_from"): adapt_xrefs_from,
    # ida_headless — TAINT_FLOW family
    ("ida_headless", "interprocedural_taint"): adapt_interprocedural_taint,
    ("ida_headless", "trace_dataflow"): adapt_trace_dataflow,
    ("ida_headless", "def_use"): adapt_def_use,
    # ida_headless — GRAPH_VIEW family
    ("ida_headless", "call_graph"): adapt_call_graph,
    ("ida_headless", "call_chain"): adapt_call_chain,
    # ida_headless — CODE_POINTER family
    ("ida_headless", "disassemble_function"): adapt_disassemble_function,
    ("ida_headless", "get_microcode"): adapt_get_microcode,
    ("ida_headless", "pseudocode_slice_view"): adapt_pseudocode_slice_view,
    # ida_headless — PATCH_DIFF family
    ("ida_headless", "diff_function"): adapt_diff_function,
    # ida_headless — TEXT specializations
    ("ida_headless", "checksec"): adapt_checksec,
    ("ida_headless", "classify_behavior"): adapt_classify_behavior,
    ("ida_headless", "capa_scan"): adapt_capa_scan,
    # audit_mcp — DECOMPILED_FUNCTION
    ("audit_mcp", "read_function"): adapt_read_function,
    # audit_mcp — XREF_VIEW family
    ("audit_mcp", "callers_of"): adapt_callers_of,
    ("audit_mcp", "callees_of"): adapt_callees_of,
    # audit_mcp — TAINT_FLOW family
    ("audit_mcp", "taint_paths_to"): adapt_taint_paths_to,
    ("audit_mcp", "paths_between"): adapt_paths_between,
    # audit_mcp — GRAPH_VIEW
    ("audit_mcp", "export_graph"): adapt_export_graph,
    # audit_mcp — PATCH_DIFF
    ("audit_mcp", "diff_codebases"): adapt_diff_codebases,
    # audit_mcp — TEXT specializations
    ("audit_mcp", "attack_surface"): adapt_attack_surface,
    ("audit_mcp", "complexity_hotspots"): adapt_complexity_hotspots,
    ("audit_mcp", "fuzzing_targets"): adapt_fuzzing_targets,
    # audit_mcp — search_* family (dense file:line:text rendering;
    # replaces generic JSON-dump path which capped at 2000 chars =
    # ~8 matches and routinely truncated past the load-bearing region)
    ("audit_mcp", "search_source"): adapt_search_source,
    ("audit_mcp", "search_macros"): adapt_search_macros,
    ("audit_mcp", "search_constants"): adapt_search_constants,
    ("audit_mcp", "search_types"): adapt_search_types,
    ("audit_mcp", "search_functions"): adapt_search_functions,
}


def get_adapter(server_id: str, tool_name: str) -> AdapterFn | None:
    """Return the adapter for one MCP tool, or None when unknown.

    Specialized adapters take priority. Falls back to ``adapt_generic``
    when the tool is in ``KNOWN_TOOLS[server_id]``. Returns ``None`` for
    completely unknown server/tool combinations so the executor can
    surface a 'no such tool' error to the engine.
    """
    specific = _SPECIALIZED.get((server_id, tool_name))
    if specific is not None:
        return specific
    if tool_name in KNOWN_TOOLS.get(server_id, frozenset()):
        return adapt_generic
    return None


def registered_tools() -> list[str]:
    """List every callable '<server>.<tool>' identifier (specialized OR generic).

    Used by the system prompt builder so the engine sees the complete
    callable surface, not just specialized tools.
    """
    seen: set[str] = set()
    for server, tools in KNOWN_TOOLS.items():
        for tool in tools:
            seen.add(f"{server}.{tool}")
    return sorted(seen)


def specialized_tools() -> list[str]:
    """List only tools with custom (non-generic) adapters.

    Useful for diagnostics and for the prompt builder to indicate which
    tools produce structured payloads vs raw TEXT.
    """
    return sorted(f"{s}.{t}" for s, t in _SPECIALIZED)
