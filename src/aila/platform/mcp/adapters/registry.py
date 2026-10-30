"""Adapter registry -- resolves (mcp_server_id, tool_name) -> AdapterFn.

Resolution order:

  1. Specialized adapter explicitly registered in ``_SPECIALIZED``
     (e.g. ``audit_mcp.read_function`` -> ``adapt_read_function``).
  2. Generic adapter ``adapt_generic`` when the tool name is present
     in the **effective** catalog for ``server_id`` -- i.e. the union
     of the static ``KNOWN_TOOLS[server_id]`` set and the runtime
     catalog populated by :func:`register_bridge_tools` from each
     bridge's live ``/tools`` response (fix §244). Stopping at the
     static list meant adding a tool on the bridge but forgetting to
     extend ``KNOWN_TOOLS`` caused silent feature drops: the bridge
     accepted the call, the adapter resolution returned ``None``, and
     the agent's tool result never reached the message store.
  3. ``None`` when the tool name is unknown -- tool_executor surfaces a
     loud error message back to the engine so it can retry with a
     correct name.

This means the engine can invoke any catalogued MCP tool immediately;
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
from .dynamic_symbolic import adapt_dynamic_run, adapt_symbolic_explore
from .generic import adapt_generic
from .known_tools import (
    _ALWAYS_SUPPRESS,
    _VIRTUAL_TOOLS,
    KNOWN_TOOLS,
    canonicalize_tool_id,
)
from .rea import (
    adapt_rea_analyze_function,
    adapt_rea_binary_overview,
    adapt_rea_byte_entropy,
    adapt_rea_call_graph,
    adapt_rea_compare_functions,
    adapt_rea_disassembly,
    adapt_rea_list_procedures,
    adapt_rea_list_segments,
    adapt_rea_list_strings,
    adapt_rea_native_exports,
    adapt_rea_open_binary,
    adapt_rea_pe_imports,
    adapt_rea_procedure_callees,
    adapt_rea_procedure_callers,
    adapt_rea_procedure_info,
    adapt_rea_procedure_references,
    adapt_rea_pseudocode,
    adapt_rea_read_bytes,
    adapt_rea_search_bytes,
    adapt_rea_trace_call_path,
    adapt_rea_xrefs,
)

__all__ = [
    "get_adapter",
    "register_bridge_tools",
    "registered_tools",
    "specialized_tools",
]

_log = logging.getLogger(__name__)


# Specialized adapters. Keys: (server_id, tool_name).
_SPECIALIZED: dict[tuple[str, str], AdapterFn] = {
    # audit_mcp -- DECOMPILED_FUNCTION
    ("audit_mcp", "read_function"): adapt_read_function,
    # audit_mcp -- XREF_VIEW family
    ("audit_mcp", "callers_of"): adapt_callers_of,
    ("audit_mcp", "callees_of"): adapt_callees_of,
    # audit_mcp -- TAINT_FLOW family
    ("audit_mcp", "taint_paths_to"): adapt_taint_paths_to,
    ("audit_mcp", "paths_between"): adapt_paths_between,
    # audit_mcp -- GRAPH_VIEW
    ("audit_mcp", "export_graph"): adapt_export_graph,
    # audit_mcp -- PATCH_DIFF
    ("audit_mcp", "diff_codebases"): adapt_diff_codebases,
    # audit_mcp -- TEXT specializations
    ("audit_mcp", "attack_surface"): adapt_attack_surface,
    ("audit_mcp", "complexity_hotspots"): adapt_complexity_hotspots,
    ("audit_mcp", "fuzzing_targets"): adapt_fuzzing_targets,
    # audit_mcp -- search_* family (dense file:line:text rendering;
    # replaces generic JSON-dump path which capped at 2000 chars =
    # ~8 matches and routinely truncated past the load-bearing region)
    ("audit_mcp", "search_source"): adapt_search_source,
    ("audit_mcp", "search_macros"): adapt_search_macros,
    ("audit_mcp", "search_constants"): adapt_search_constants,
    ("audit_mcp", "search_types"): adapt_search_types,
    ("audit_mcp", "search_functions"): adapt_search_functions,
    # audit_mcp -- semantic_search + find_related (chunk-based dense
    # rendering; old generic path json-dumped + truncated at 15KB so the
    # agent saw escaped quotes around partial content fields. Now full
    # `content` fields surface as readable source blocks under a 50KB
    # cap suitable for the chunk shape these tools return).
    ("audit_mcp", "semantic_search"): adapt_semantic_search,
    ("audit_mcp", "find_related"): adapt_find_related,
    # Bridge-side virtual tool: raw file slice by line range.
    ("audit_mcp", "read_lines"): adapt_read_lines,
    # Issue #148: VR dynamic-analysis tools. Both project the colon-keyed
    # observable (``symbolic:<fn>:reached`` / ``dynamic:<target>:
    # coverage_delta``) the kill-criteria evaluator scans.
    ("symbolic", "explore"): adapt_symbolic_explore,
    ("dynamic", "run_dynamic"): adapt_dynamic_run,
    # REA (morluto/rea) -- first MCP-native server. Evidence records map
    # onto the payload kinds the audit_mcp adapters established. Shapes
    # verified live against rea-agents 6.8.0 + Ghidra (see rea.py header).
    ("rea", "procedure_pseudo_code"): adapt_rea_pseudocode,
    ("rea", "analyze_function"): adapt_rea_analyze_function,
    ("rea", "procedure_assembly"): adapt_rea_disassembly,
    ("rea", "get_call_graph"): adapt_rea_call_graph,
    ("rea", "trace_call_path"): adapt_rea_trace_call_path,
    ("rea", "xrefs"): adapt_rea_xrefs,
    ("rea", "procedure_callers"): adapt_rea_procedure_callers,
    ("rea", "procedure_callees"): adapt_rea_procedure_callees,
    ("rea", "procedure_references"): adapt_rea_procedure_references,
    ("rea", "search_bytes"): adapt_rea_search_bytes,
    ("rea", "compare_functions"): adapt_rea_compare_functions,
    ("rea", "open_binary"): adapt_rea_open_binary,
    ("rea", "binary_overview"): adapt_rea_binary_overview,
    ("rea", "list_procedures"): adapt_rea_list_procedures,
    ("rea", "list_strings"): adapt_rea_list_strings,
    ("rea", "list_segments"): adapt_rea_list_segments,
    ("rea", "procedure_info"): adapt_rea_procedure_info,
    ("rea", "read_bytes"): adapt_rea_read_bytes,
    ("rea", "inspect_pe_imports"): adapt_rea_pe_imports,
    ("rea", "inspect_native_exports"): adapt_rea_native_exports,
    ("rea", "inspect_byte_entropy"): adapt_rea_byte_entropy,
}

# fix §200 -- generic-adapter-backed read tools registered explicitly.
# These tools have no specialised adapter (they fall through to
# ``adapt_generic``) so there is no function for ``@is_read_tool`` to
# decorate; register them imperatively at import time instead.
for _server, _tool in (
    ("audit_mcp", "extract_class"),
    ("audit_mcp", "entrypoint_paths_to"),
):
    register_read_tool(_server, _tool)
del _server, _tool


# fix §244 -- runtime catalog of tools the engine may invoke, populated
# by each bridge's live ``/tools`` response (see
# ``vuln_researcher._fetch_tool_specs`` for the wiring). The static
# ``KNOWN_TOOLS`` set remains as the import-time fallback so the
# registry still works when no bridge has been polled yet (tests,
# narrow imports). Once a bridge has spoken, ``effective_tools(server)``
# returns the union -- additions on the bridge side appear here
# automatically and the manual ``KNOWN_TOOLS`` list stops being the
# bottleneck for "is this tool callable?".
_RUNTIME_BRIDGE_TOOLS: dict[str, set[str]] = {}


def register_bridge_tools(server_id: str, tool_names: object) -> None:
    """Append a bridge's live tool catalog to the runtime registry.

    Called by the bridge spec fetcher once per process (each
    ``BridgeTool.list_tool_specs`` is cached at the class level so the
    second call is a no-op). ``tool_names`` is any iterable of strings;
    invalid entries are silently dropped -- a bridge returning an
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
    """Union of the static + runtime catalogs for one server, minus
    :data:`_ALWAYS_SUPPRESS`.

    The runtime union (fix \u00a7244) ensures a tool added on the bridge
    side becomes callable without a static catalog edit. The
    suppression subtraction restores the inverse property: a tool
    DELETED from the static catalog (or explicitly listed in
    ``_ALWAYS_SUPPRESS``) stays uncallable even though the bridge's
    live ``/tools`` response still advertises it. Without this the
    agent learns the name from training data, dispatches it, and the
    bridge happily runs the deprecated tool.
    """
    static = KNOWN_TOOLS.get(server_id, frozenset())
    runtime = _RUNTIME_BRIDGE_TOOLS.get(server_id) or set()
    suppress = _ALWAYS_SUPPRESS.get(server_id, frozenset())
    base = static if not runtime else (static | runtime)
    if not suppress:
        return frozenset(base)
    return frozenset(t for t in base if t not in suppress)


def get_adapter(server_id: str, tool_name: str) -> AdapterFn | None:
    """Return the adapter for one MCP tool, or None when unknown.

    Suppressed tools (``_ALWAYS_SUPPRESS``) short-circuit to ``None``
    BEFORE the specialized-adapter lookup. The specialized table is
    additive; keep it free of deprecated tool names so
    ``specialized_tools()`` never reports a name the catalog rejects.

    After the suppression gate: specialized adapters take priority.
    Falls back to ``adapt_generic`` when the tool is in
    :func:`_effective_tools` (static ``KNOWN_TOOLS`` plus any names
    registered via :func:`register_bridge_tools` -- fix \u00a7244, minus
    ``_ALWAYS_SUPPRESS``). Returns ``None`` for completely unknown
    server/tool combinations so the executor can surface a 'no such
    tool' error to the engine.
    """
    # Issue #251 / doc #15 sec 1.2 -- collapse spelling drift
    # (``audit-mcp.foo``, ``audit_mcp:foo``, bare ``foo``) to the
    # canonical ``(server_id, tool_name)`` at the adapter boundary so
    # the specialised-adapter table, ``_effective_tools`` catalog, and
    # every downstream observable key see one identity per tool.
    server_id, tool_name = canonicalize_tool_id(server_id, tool_name)
    if not server_id or not tool_name:
        return None
    if tool_name in _ALWAYS_SUPPRESS.get(server_id, frozenset()):
        return None
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
        suppress = _ALWAYS_SUPPRESS.get(server, frozenset())
        for tool in tools:
            if tool in suppress:
                continue
            seen.add(f"{server}.{tool}")
    for server, tools in _VIRTUAL_TOOLS.items():
        suppress = _ALWAYS_SUPPRESS.get(server, frozenset())
        for tool in tools:
            if tool in suppress:
                continue
            seen.add(f"{server}.{tool}")
    for server, tools in _RUNTIME_BRIDGE_TOOLS.items():
        suppress = _ALWAYS_SUPPRESS.get(server, frozenset())
        for tool in tools:
            if tool in suppress:
                continue
            seen.add(f"{server}.{tool}")
    return sorted(seen)


def specialized_tools() -> list[str]:
    """List only tools with custom (non-generic) adapters.

    Useful for diagnostics and for the prompt builder to indicate which
    tools produce structured payloads vs raw TEXT. Suppressed tools
    (``_ALWAYS_SUPPRESS``) are filtered out so the listing stays
    consistent with :func:`registered_tools` and the agent surface.
    """
    out: list[str] = []
    for server, tool in _SPECIALIZED:
        if tool in _ALWAYS_SUPPRESS.get(server, frozenset()):
            continue
        out.append(f"{server}.{tool}")
    return sorted(out)
