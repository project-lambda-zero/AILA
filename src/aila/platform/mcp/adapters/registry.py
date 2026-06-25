"""Adapter registry — resolves (mcp_server_id, tool_name) -> AdapterFn.

Resolution order:

  1. Specialized adapter explicitly registered in ``_SPECIALIZED``
     (e.g. ``ida_headless.decompile`` -> ``adapt_decompile``).
  2. Generic adapter ``adapt_generic`` when the tool name is present
     in the **effective** catalog for ``server_id`` — i.e. the union
     of the static ``KNOWN_TOOLS[server_id]`` set and the runtime
     catalog populated by :func:`register_bridge_tools` from each
     bridge's live ``/tools`` response (fix §244). Stopping at the
     static list meant adding a tool on the bridge but forgetting to
     extend ``KNOWN_TOOLS`` caused silent feature drops: the bridge
     accepted the call, the adapter resolution returned ``None``, and
     the agent's tool result never reached the message store.
  3. ``None`` when the tool name is unknown — tool_executor surfaces a
     loud error message back to the engine so it can retry with a
     correct name.

This means the engine can invoke any of the 135 MCP tools immediately;
tools with high-value structured rendering get specialized adapters as
they become useful in real investigations.
"""
from __future__ import annotations

import logging

from .audit_mcp import (
    adapt_attack_surface,
    adapt_callees_of,
    adapt_callers_of,
    adapt_complexity_hotspots,
    adapt_diff_codebases,
    adapt_export_graph,
    adapt_find_related,
    adapt_fuzzing_targets,
    adapt_paths_between,
    adapt_read_function,
    adapt_read_lines,
    adapt_search_constants,
    adapt_search_functions,
    adapt_search_macros,
    adapt_search_source,
    adapt_search_types,
    adapt_semantic_search,
    adapt_taint_paths_to,
)
from .base import AdapterFn, register_read_tool
from .generic import adapt_generic
from .ida_headless import (
    adapt_call_chain,
    adapt_call_graph,
    adapt_capa_scan,
    adapt_checksec,
    adapt_classify_behavior,
    adapt_classify_strings,
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
from .known_tools import _VIRTUAL_TOOLS, KNOWN_TOOLS

__all__ = [
    "get_adapter",
    "register_bridge_tools",
    "registered_tools",
    "specialized_tools",
]

_log = logging.getLogger(__name__)


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
    # ida_headless \u2014 TEXT specializations
    ("ida_headless", "checksec"): adapt_checksec,
    ("ida_headless", "classify_behavior"): adapt_classify_behavior,
    ("ida_headless", "classify_strings"): adapt_classify_strings,
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
    # audit_mcp — semantic_search + find_related (chunk-based dense
    # rendering; old generic path json-dumped + truncated at 15KB so the
    # agent saw escaped quotes around partial content fields. Now full
    # `content` fields surface as readable source blocks under a 50KB
    # cap suitable for the chunk shape these tools return).
    ("audit_mcp", "semantic_search"): adapt_semantic_search,
    ("audit_mcp", "find_related"): adapt_find_related,
    # Bridge-side virtual tool: raw file slice by line range.
    ("audit_mcp", "read_lines"): adapt_read_lines,
}

# fix §200 — generic-adapter-backed read tools registered explicitly.
# These tools have no specialised adapter (they fall through to
# ``adapt_generic``) so there is no function for ``@is_read_tool`` to
# decorate; register them imperatively at import time instead.
for _server, _tool in (
    ("audit_mcp", "extract_class"),
    ("audit_mcp", "entrypoint_paths_to"),
):
    register_read_tool(_server, _tool)
del _server, _tool


# fix §244 — runtime catalog of tools the engine may invoke, populated
# by each bridge's live ``/tools`` response (see
# ``vuln_researcher._fetch_tool_specs`` for the wiring). The static
# ``KNOWN_TOOLS`` set remains as the import-time fallback so the
# registry still works when no bridge has been polled yet (tests,
# narrow imports). Once a bridge has spoken, ``effective_tools(server)``
# returns the union — additions on the bridge side appear here
# automatically and the manual ``KNOWN_TOOLS`` list stops being the
# bottleneck for "is this tool callable?".
_RUNTIME_BRIDGE_TOOLS: dict[str, set[str]] = {}


def register_bridge_tools(server_id: str, tool_names: object) -> None:
    """Append a bridge's live tool catalog to the runtime registry.

    Called by the bridge spec fetcher once per process (each
    ``BridgeTool.list_tool_specs`` is cached at the class level so the
    second call is a no-op). ``tool_names`` is any iterable of strings;
    invalid entries are silently dropped — a bridge returning an
    unusable schema shouldn't crash the agent registry.
    """
    if not server_id:
        return
    bucket = _RUNTIME_BRIDGE_TOOLS.setdefault(server_id, set())
    try:
        for name in tool_names or ():
            if isinstance(name, str) and name:
                bucket.add(name)
    except TypeError as exc:
        _log.warning("register_bridge_tools FAILED reason=%s", exc)
        return


def _effective_tools(server_id: str) -> frozenset[str]:
    """Union of the static + runtime catalogs for one server."""
    static = KNOWN_TOOLS.get(server_id, frozenset())
    runtime = _RUNTIME_BRIDGE_TOOLS.get(server_id) or set()
    if not runtime:
        return static
    return frozenset(static | runtime)


def get_adapter(server_id: str, tool_name: str) -> AdapterFn | None:
    """Return the adapter for one MCP tool, or None when unknown.

    Specialized adapters take priority. Falls back to ``adapt_generic``
    when the tool is in :func:`_effective_tools` (static ``KNOWN_TOOLS``
    plus any names registered via :func:`register_bridge_tools` —
    fix §244). Returns ``None`` for completely unknown server/tool
    combinations so the executor can surface a 'no such tool' error
    to the engine.
    """
    specific = _SPECIALIZED.get((server_id, tool_name))
    if specific is not None:
        return specific
    if tool_name in _effective_tools(server_id):
        return adapt_generic
    return None


def registered_tools() -> list[str]:
    """List every callable '<server>.<tool>' identifier (specialized OR generic).

    Used by diagnostics and as the upper bound for ``specialized_tools``:
    every specialized entry MUST appear here. Includes upstream MCP tools
    listed in ``KNOWN_TOOLS`` AND bridge-side virtual tools listed in
    ``_VIRTUAL_TOOLS`` (e.g. ``audit_mcp.read_lines``) AND any names
    appended at runtime by :func:`register_bridge_tools` (fix §244),
    since the agent can call any of them via the same ``tool_run``
    surface.
    """
    seen: set[str] = set()
    for server, tools in KNOWN_TOOLS.items():
        for tool in tools:
            seen.add(f"{server}.{tool}")
    for server, tools in _VIRTUAL_TOOLS.items():
        for tool in tools:
            seen.add(f"{server}.{tool}")
    for server, tools in _RUNTIME_BRIDGE_TOOLS.items():
        for tool in tools:
            seen.add(f"{server}.{tool}")
    return sorted(seen)


def specialized_tools() -> list[str]:
    """List only tools with custom (non-generic) adapters.

    Useful for diagnostics and for the prompt builder to indicate which
    tools produce structured payloads vs raw TEXT.
    """
    return sorted(f"{s}.{t}" for s, t in _SPECIALIZED)
