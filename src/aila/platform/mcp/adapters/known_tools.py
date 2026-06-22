"""Canonical inventory of every MCP tool the engine may invoke.

Derived directly from:
  - ida_headless_mcp server (81 tools as of 2026-05-14)
  - audit_mcp server (54 tools as of 2026-05-14)
  - android_mcp server (24 tools as of 2026-06-08)

Reasons to enumerate explicitly rather than auto-discover at runtime:
  1. Unknown tool names should fail loud — typos in engine output, not
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
    "IDA_HEADLESS_TOOLS",
    "KNOWN_TOOLS",
    "LANGUAGE_UNRELIABLE_TOOLS",
    "tools_for_language",
]


IDA_HEADLESS_TOOLS: frozenset[str] = frozenset({
    # Lifecycle / metadata
    "open_binary",
    "close_binary",
    "list_binaries",
    "binary_metadata",
    "binary_survey",
    "poll_analysis",
    "poll_mutation",
    "worker_status",
    "get_generation",
    # Inventory
    "list_functions",
    "exports",
    "imports",
    "segments",
    "stack_frame",
    # Decompilation / disassembly
    "decompile",
    "batch_decompile",
    "disassemble_function",
    "get_microcode",
    "pseudocode_slice_view",
    "query_ctree",
    "hexrays_warnings",
    # miasm
    "miasm_disassemble",
    "miasm_lift_ir",
    "miasm_emulate",
    "miasm_simplify_expression",
    # Cross-references / call graphs
    "xrefs_to",
    "xrefs_from",
    "call_graph",
    "call_chain",
    "build_call_tree",
    "find_api_call_sites",
    "find_paths",
    "find_similar_functions",
    # Taint / dataflow / proofs
    "trace_dataflow",
    "trace_hash_xrefs",
    "interprocedural_taint",
    "def_use",
    "value_ranges",
    "path_feasibility",
    "constrained_reachability",
    "prove_equivalence",
    "prove_predicate_opaque",
    "prove_overflow",
    "prove_bounds_sufficient",
    "assess_exploitability",
    # Obfuscation / CFF
    "detect_obfuscation",
    "detect_control_flow_obfuscation",
    "batch_cff_scan",
    "deflat_function",
    "recover_cfg",
    "patch_cff",
    # Anti-analysis / strings / crypto
    "detect_anti_analysis",
    "detect_stack_strings",
    "detect_dynamic_resolution",
    "detect_crypto_primitives",
    "classify_strings",
    "decrypt_function_strings",
    "decrypt_binary_strings",
    "resolve_api_hashes",
    # Library / classification
    "detect_library_functions",
    "classify_behavior",
    "verify_capabilities",
    "capa_scan",
    "checksec",
    "entropy_analysis",
    "recover_class_hierarchy",
    "detect_protocol_state_machine",
    # Search / diff
    "search_pattern",
    "diff_function",
    "diff_binary",
    "diff_survey",
    "cross_binary_similarity",
    # Emulation
    "emulate_concrete",
    # Mutations
    "rename_function",
    "rename_variable",
    "set_comment",
    "set_function_type",
    "set_variable_type",
    "patch_bytes",
    "patch_assemble",
    # YARA
    "generate_yara_rule",
})


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
    # Semble — hybrid semantic + BM25 chunk retrieval (PREFERRED over
    # search_source for natural-language / intent queries; falls back
    # to literal search_* when you need exact regex / symbol matching)
    "semantic_search",
    "find_related",
    "semble_stats",
    # Search — literal / symbol / regex
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
    # androguard static analysis
    "androguard_summary",
    # MobSF orchestration
    "mobsf_scan",
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
    # Composite handlers — mirror audit-mcp's higher-level layer
    "verify_capabilities",
    "classify_behavior",
    "compute_risk_score",
    "find_secrets",
})


# Indexed by server_id used by the bridge dispatch.
KNOWN_TOOLS: dict[str, frozenset[str]] = {
    "ida_headless": IDA_HEADLESS_TOOLS,
    "audit_mcp": AUDIT_MCP_TOOLS,
    "android_mcp": ANDROID_MCP_TOOLS,
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
    # NOT included: rust (static dispatch + monomorphization by default —
    # cargo's own dead_code lint works reliably), go (interfaces are
    # vtable-dispatched but concrete-type calls dominate), c (only direct
    # calls and function pointers — the latter is a small minority).
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
