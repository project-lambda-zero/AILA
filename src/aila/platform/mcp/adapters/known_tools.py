"""Canonical inventory of every MCP tool the engine may invoke.

Derived directly from:
  - audit_mcp server (54 tools as of 2026-05-14)
  - android_mcp server (24 tools as of 2026-06-08)
  - REA (rea-agents) MCP-native server (binary reverse engineering)

Reasons to enumerate explicitly rather than auto-discover at runtime:
  1. Unknown tool names should fail loud -- typos in engine output, not
     silent network errors at dispatch time.
  2. The system prompt enumerates available tools per turn (so the
     engine doesn't guess names). That enumeration MUST be deterministic
     and not depend on whether the bridge happens to be reachable.
  3. Adapter-coverage tests can iterate the set and confirm every tool
     resolves (specialized OR generic).

If a new MCP tool ships upstream, add its name here. The next
investigation turn will then surface it in the prompt and accept it as
a tool_run command.
"""
from __future__ import annotations

__all__ = [
    "ANDROID_MCP_TOOLS",
    "AUDIT_MCP_TOOLS",
    "KNOWN_TOOLS",
    "LANGUAGE_UNRELIABLE_TOOLS",
    "REA_TOOLS",
    "REVERSER_BELT_TOOLS",
    "canonical_tool_id",
    "canonicalize_tool_id",
    "tools_for_language",
]


# Server-id aliases seen in the wild (issue #251/#248, doc #15 sec 1.2).
# The agent stream emits the same audit_mcp tool under three spellings:
# ``audit_mcp.semantic_search`` (canonical), ``audit-mcp.semantic_search``
# (hyphen legacy), and the bare ``semantic_search`` alone. Downstream the
# adapter registry, obs-key generator, and dedup keys all consume the
# split ``(server_id, tool_name)`` tuple, so a spelling drift produces
# duplicate observable keys, dedup misses, and one wasted turn per
# mis-namespaced call. We collapse every spelling to the canonical
# ``(server_id, tool_name)`` at the adapter boundary via
# :func:`canonicalize_tool_id`; the caller sees the normalised tuple
# before adapter dispatch, observable-key generation, and any dedup
# lookup.
_SERVER_ID_ALIASES: dict[str, str] = {
    "audit-mcp": "audit_mcp",
    "auditmcp": "audit_mcp",
    "android-mcp": "android_mcp",
    "androidmcp": "android_mcp",
}


def canonicalize_tool_id(
    server_id: str | None, tool_name: str | None,
) -> tuple[str, str]:
    """Collapse spelling variants of one MCP tool to a canonical tuple.

    Handles the three drifts measured across the tool-call corpus
    (doc #15 sec 1.2, issue #251):

      * Server-id hyphen vs underscore (``audit-mcp`` -> ``audit_mcp``)
        and legacy suffix spellings collapsed via
        :data:`_SERVER_ID_ALIASES`.
      * A leading ``<server>:`` or ``<server>.`` prefix duplicated onto
        ``tool_name`` (``audit_mcp:semantic_search`` -> the split tuple
        ``("audit_mcp", "semantic_search")``).
      * A bare ``tool_name`` with an empty or wrong ``server_id`` when
        the tool name uniquely identifies its server via ``KNOWN_TOOLS``
        (``("", "semantic_search")`` -> ``("audit_mcp",
        "semantic_search")``).

    Returns a ``(canonical_server, canonical_tool)`` tuple. Empty
    strings when nothing resolves; the caller decides whether to treat
    that as "unknown tool" (adapter registry returns ``None``, executor
    surfaces a loud error) or to pass through untouched.
    """
    srv = (server_id or "").strip().lower()
    tool = (tool_name or "").strip()
    # Absorb any ``<server>:tool`` or ``<server>.tool`` prefix duplicated
    # onto the tool name. We honour whichever separator produces a known
    # server-id; a bare tool with an unrelated dot in its name (rare, but
    # e.g. ``knowledge.retrieve`` in the wild) is left alone.
    for sep in (":", "."):
        if sep in tool:
            head, _, tail = tool.partition(sep)
            head_norm = head.strip().lower()
            candidate = _SERVER_ID_ALIASES.get(head_norm, head_norm)
            if candidate in KNOWN_TOOLS:
                srv = candidate
                tool = tail.strip()
                break
    srv = _SERVER_ID_ALIASES.get(srv, srv)
    # Bare tool + empty/unknown server: try to resolve from the static
    # catalog. Ambiguous names (same tool published by two servers) fall
    # through unchanged so the caller can decide.
    if tool and (not srv or srv not in KNOWN_TOOLS):
        owners = [s for s, catalog in KNOWN_TOOLS.items() if tool in catalog]
        if len(owners) == 1:
            srv = owners[0]
    return srv, tool


# Legacy alias -- some callers imported the earlier spelling before the
# helper's final name landed. Both names refer to the same function; the
# alias avoids a churn commit across sibling adapters.
canonical_tool_id = canonicalize_tool_id


AUDIT_MCP_TOOLS: frozenset[str] = frozenset({
    # Indexing / cache
    "index_codebase",
    "poll_index",
    "list_indexes",
    "detect_languages",
    "supported_languages",
    "cache_stats",
    "clear_cache",
    "memory_usage",
    "plan_partitions",
    "poll_task",
    "list_tasks",
    # Summary / preanalysis
    "summary",
    "preanalysis",
    # Call graph
    "callers_of",
    "callees_of",
    "ancestors_of",
    "children_of",
    "reachable_from",
    "paths_between",
    "entrypoint_paths_to",
    "includers_of",
    # Surface / hotspots / fuzz
    "attack_surface",
    "complexity_hotspots",
    "fuzzing_targets",
    "fuzz_generators",
    "attack_surface_diff",
    # Semble -- hybrid semantic + BM25 chunk retrieval (PREFERRED over
    # search_source for natural-language / intent queries; falls back
    # to literal search_* when you need exact regex / symbol matching)
    "semantic_search",
    "find_related",
    "semble_stats",
    # Search -- literal / symbol / regex
    "search_functions",
    "search_constants",
    "search_types",
    "search_assertions",
    "search_bitfields",
    "search_macros",
    "search_source",
    "search_narrowing_casts",
    "read_function",
    "extract_class",
    "cross_reference_bitfields",
    # Taint / reachability
    "taint_paths_to",
    "dead_code",
    "unreachable_from_entrypoints",
    "functions_that_raise",
    # Diff
    "diff_codebases",
    # Annotations
    "annotate_function",
    "annotations_of",
    "nodes_with_annotation",
    "clear_annotations",
    # Findings / scanners
    "findings",
    "augment_sarif",
    "list_scanners",
    "run_scanner",
    "scan_and_correlate",
    # Graph export
    "export_graph",
    # Browser smoke
    "test_in_browser",
    "browser_info",
})


ANDROID_MCP_TOOLS: frozenset[str] = frozenset({
    # APK unpacking / decompilation
    "apktool_decode",
    "jadx_decompile",
    # Signing-scheme verification
    "verify_apk_signing",
    # Component / permission auditing
    "drozer_scan_apk",
    # Static rule scanners
    # Native shared-object analysis
    "analyze_native_libs",
    # YARA over decompiled tree
    "yara_scan_dir",
    # Frida-driven runtime helpers (operator runs frida-server externally)
    "frida_list_running_devices",
    "frida_dump_process_modules",
    "frida_attach_and_trace_calls",
    # Objection (gadget injection + exploration REPL)
    "objection_patch_apk",
    "objection_explore",
    # adb facade
    "adb_devices",
    "adb_install",
    "adb_uninstall",
    "adb_logcat_capture",
    "adb_dumpsys",
    # Composite handlers -- mirror audit-mcp's higher-level layer
    "verify_capabilities",
    "classify_behavior",
    "compute_risk_score",
    "find_secrets",
})


# RFC-12: the in-process knowledge bridge exposes exactly one read-only
# tool -- knowledge.retrieve -- so a reasoning agent can pull prior
# workspace-scoped knowledge on demand. No mutating tool exists on this
# server; the generic adapter renders the {status, route, count, results}
# response.
KNOWLEDGE_TOOLS: frozenset[str] = frozenset({
    "retrieve",
})


# Issue #245: the in-process, SSH-backed PoC runner exposed to
# exploit-dev agents during dispatch-hub phases. Each action drives a
# remote analysis/PoC workstation over SSH to compile, run, verify, and
# tear down reproducers; the generic adapter renders the
# {status, ...} dicts the tool returns.
POC_RUNNER_TOOLS: frozenset[str] = frozenset({
    "compile_poc",
    "run_poc",
    "verify_reliability",
    "cleanup_workspace",
})


# Issue #148: the in-process platform dynamic-analysis drivers exposed
# to the VR reasoning agent. ``symbolic.explore`` runs a bounded concolic
# walk of one function; ``dynamic.run_dynamic`` runs a target once in the
# sandbox with coverage + crash capture. Each has a specialised adapter
# (``dynamic_symbolic.py``) that projects the colon-keyed observable the
# kill-criteria evaluator scans (``symbolic:<fn>:reached`` /
# ``dynamic:<target>:coverage_delta``).
SYMBOLIC_TOOLS: frozenset[str] = frozenset({
    "explore",
})
DYNAMIC_TOOLS: frozenset[str] = frozenset({
    "run_dynamic",
})


# REA (morluto/rea) -- the first external MCP-native server. Static
# fallback catalog so the adapter registry resolves ``rea.<tool>``
# before any live ``tools/list`` has been fetched; the runtime bridge
# catalog (``register_bridge_tools``) is authoritative once the server
# has spoken. This list is exactly the tool surface the REA bridge
# exposes -- the REA-side equivalents of the archived binary-analysis
# tools (see docs/MCP_ARSENAL.md for the mapping):
# decompile -> procedure_pseudo_code, disassemble_function ->
# procedure_assembly, xrefs_to/xrefs_from -> xrefs / procedure_callers
# / procedure_callees / procedure_references, list_functions ->
# list_procedures, search_pattern -> search_bytes, imports/exports ->
# inspect_pe_imports / inspect_native_exports, segments -> list_segments,
# binary_metadata -> binary_overview, read_memory -> read_bytes,
# build_call_tree -> get_call_graph, entropy_analysis ->
# inspect_byte_entropy, stack_frame -> procedure_info. Tools REA lacks
# are served by the external ``reverser_belt`` server (separate catalog).
REA_TOOLS: frozenset[str] = frozenset({
    "open_binary",
    "binary_overview",
    "list_procedures",
    "list_strings",
    "list_segments",
    "procedure_info",
    "procedure_pseudo_code",
    "procedure_assembly",
    "analyze_function",
    "xrefs",
    "procedure_callers",
    "procedure_callees",
    "procedure_references",
    "get_call_graph",
    "trace_call_path",
    "compare_functions",
    "search_bytes",
    "search_strings",
    "search_procedures",
    "build_call_path",
    "read_bytes",
    "inspect_pe_imports",
    "inspect_native_exports",
    "inspect_byte_entropy",
})


# reverser_belt -- external reverser-belt-mcp server
# (``python -m reverser_belt_mcp.server``, stdio; Kuna decompiler
# backend). Static fallback catalog resolved before the live
# tools/list. This is the exact 84-tool surface the server
# serves. Handle-based: open_binary(path) -> binary_id; the
# ReverserBeltMiddleware translates the module-injected
# target_path into that binary_id per call.
REVERSER_BELT_TOOLS: frozenset[str] = frozenset({
    "assess_exploitability",
    "batch_cff_scan",
    "batch_decompile",
    "binary_metadata",
    "binary_survey",
    "build_call_tree",
    "call_chain",
    "call_graph",
    "capa_scan",
    "checksec",
    "classify_behavior",
    "classify_strings",
    "close_binary",
    "constrained_reachability",
    "cross_binary_similarity",
    "decompile",
    "decrypt_binary_strings",
    "decrypt_function_strings",
    "def_use",
    "deflat_function",
    "detect_anti_analysis",
    "detect_control_flow_obfuscation",
    "detect_crypto_primitives",
    "detect_dynamic_resolution",
    "detect_library_functions",
    "detect_obfuscation",
    "detect_protocol_state_machine",
    "detect_stack_strings",
    "diff_binary",
    "diff_function",
    "diff_survey",
    "disassemble_function",
    "emulate_concrete",
    "entropy_analysis",
    "exports",
    "find_api_call_sites",
    "find_paths",
    "find_similar_functions",
    "generate_yara_rule",
    "get_generation",
    "get_microcode",
    "get_string_at",
    "hexrays_warnings",
    "imports",
    "interprocedural_taint",
    "list_binaries",
    "list_functions",
    "list_strings",
    "miasm_disassemble",
    "miasm_emulate",
    "miasm_lift_ir",
    "miasm_simplify_expression",
    "open_binary",
    "patch_assemble",
    "patch_bytes",
    "patch_cff",
    "path_feasibility",
    "poll_analysis",
    "poll_mutation",
    "prove_bounds_sufficient",
    "prove_equivalence",
    "prove_overflow",
    "prove_predicate_opaque",
    "pseudocode_slice_view",
    "query_ctree",
    "read_memory",
    "recover_cfg",
    "recover_class_hierarchy",
    "rename_function",
    "rename_variable",
    "resolve_api_hashes",
    "search_pattern",
    "segments",
    "set_comment",
    "set_function_type",
    "set_variable_type",
    "stack_frame",
    "trace_dataflow",
    "trace_hash_xrefs",
    "value_ranges",
    "verify_capabilities",
    "worker_status",
    "xrefs_from",
    "xrefs_to",
})


# Indexed by server_id used by the bridge dispatch.
KNOWN_TOOLS: dict[str, frozenset[str]] = {
    "audit_mcp": AUDIT_MCP_TOOLS,
    "android_mcp": ANDROID_MCP_TOOLS,
    "knowledge": KNOWLEDGE_TOOLS,
    "poc_runner": POC_RUNNER_TOOLS,
    "symbolic": SYMBOLIC_TOOLS,
    "dynamic": DYNAMIC_TOOLS,
    "rea": REA_TOOLS,
    "reverser_belt": REVERSER_BELT_TOOLS,
}


# Tools whose contract assumes a textually-explicit static call graph
# and therefore lie systematically on languages with heavy implicit
# dispatch (virtual methods via vtable, template instantiation, RAII
# destructors, static initializers, callbacks/function pointers,
# operator overloads, etc.). For these languages the audit-mcp
# call-graph builder sees only direct-name calls and reports huge
# fractions of the codebase as "dead" or "unreachable" when in fact
# the runtime reaches them through indirect dispatch.
#
# Symptom in production (firefox, primary_language=cpp):
#   dead_code      → ~70%+ of functions flagged, virtually all false
#   unreachable_*  → same problem; entrypoint BFS can't cross vtables
#
# Languages listed here disable the tools entirely for that target so
# the agent neither sees them in the prompt nor wastes reasoning
# budget chasing the false signal.
_DYNAMIC_DISPATCH_HEAVY_LANGUAGES: frozenset[str] = frozenset({
    # vtable-by-default OO languages: every method call is a virtual
    # dispatch unless the method is final/static. Static call graphs
    # see at most ~10–20% of real edges.
    "cpp", "c++", "cxx",
    "java",
    "kotlin",
    "csharp", "c#", "cs",
    "swift",  # class methods virtual by default; structs are static
    "objective-c", "objc", "objectivec",
    "scala",
    # NOT included: rust (static dispatch + monomorphization by default --
    # cargo's own dead_code lint works reliably), go (interfaces are
    # vtable-dispatched but concrete-type calls dominate), c (only direct
    # calls and function pointers -- the latter is a small minority).
})

_CALL_GRAPH_FRAGILE_TOOLS: frozenset[str] = frozenset({
    "dead_code",
    "unreachable_from_entrypoints",
})

# Tools suppressed regardless of language. search_source stays banned
# because agents loop on zero-result regex retries; the real path for
# "read these specific lines" is the bridge-side `read_lines` tool that
# resolves index_id → root_path via list_indexes and slices the file
# directly from disk. For "find code that does X" use semantic_search.
_ALWAYS_SUPPRESS: dict[str, frozenset[str]] = {
    "audit_mcp": frozenset({"search_source"}),
}

# Bridge-side virtual tools added on top of the live MCP catalog.
# These must be listed here so tools_for_language doesn't filter them
# out. The bridge intercepts the action before HTTP dispatch.
_VIRTUAL_TOOLS: dict[str, frozenset[str]] = {
    "audit_mcp": frozenset({"read_lines"}),
}

LANGUAGE_UNRELIABLE_TOOLS: dict[str, frozenset[str]] = {
    # primary_language (normalized lowercase) → audit_mcp tool names
    # we MUST suppress because their result is systematically wrong
    # covering that language. Keys are matched against the normalized
    # lowercase form of ``VRTargetRecord.primary_language``.
    lang: _CALL_GRAPH_FRAGILE_TOOLS
    for lang in _DYNAMIC_DISPATCH_HEAVY_LANGUAGES
}


def tools_for_language(
    server_id: str,
    primary_language: str | None,
) -> frozenset[str]:
    """Return the subset of ``KNOWN_TOOLS[server_id]`` that produces
    reliable output for a target whose ``primary_language`` is given.

    Always-suppress tools (``_ALWAYS_SUPPRESS``) are dropped regardless
    of language. Language-specific suppressions stack on top.

    When ``primary_language`` is None / empty / unknown, only the
    always-suppress set applies.
    """
    base = KNOWN_TOOLS.get(server_id, frozenset())
    always = _ALWAYS_SUPPRESS.get(server_id, frozenset())
    virtual = _VIRTUAL_TOOLS.get(server_id, frozenset())
    filtered = frozenset(t for t in base if t not in always)
    # Union with virtual tools so bridge-side helpers (read_lines)
    # show up in the agent's allowed set even though they aren't in
    # the live MCP catalog.
    filtered = filtered | virtual
    if not primary_language:
        return filtered
    lang = primary_language.strip().lower()
    suppress = LANGUAGE_UNRELIABLE_TOOLS.get(lang, frozenset())
    if not suppress:
        return filtered
    return frozenset(t for t in filtered if t not in suppress)
