"""Target enrichment subpackage.

Per the M3.T scope: AILA does not implement
heuristics. The IDA Headless MCP and audit-mcp servers already implement
graph-aware enrichment (fuzzing_targets, attack_surface, capa_scan,
find_api_call_sites, assess_exploitability, etc.). This subpackage
contains thin DISPATCHERS that route by target kind, collect MCP
outputs, normalize into unified schemas, and persist into
``vr_targets.capability_profile_json``.

Rule: if the planned Python work is 'wrap an MCP tool' or 'call N MCP
tools in sequence,' it's plumbing — not enrichment. Real enrichment
produces output that doesn't exist in any single tool's response.

Mitigation refresh: NOT implemented here — already done inline in
``workflow/states/setup.py`` ``_persist_setup`` via the ida_bridge
checksec call. M3.T-2 was dropped after MCP capability audit.
"""
