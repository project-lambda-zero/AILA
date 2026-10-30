"""MCP adapter unit tests -- registry, family adapters, generic fallback.

Adapters are pure functions. Tests stub the raw MCP response and verify
the (payload_kind, payload, observables_delta) output shape.
"""
from __future__ import annotations

import json

from aila.platform.mcp.adapters import (
    ANDROID_MCP_TOOLS,
    AUDIT_MCP_TOOLS,
    KNOWN_TOOLS,
    AdapterContext,
    get_adapter,
    registered_tools,
    specialized_tools,
)
from aila.platform.mcp.adapters.audit_mcp import (
    adapt_attack_surface,
    adapt_callees_of,
    adapt_callers_of,
    adapt_complexity_hotspots,
    adapt_diff_codebases,
    adapt_export_graph,
    adapt_fuzzing_targets,
    adapt_paths_between,
    adapt_read_function,
    adapt_taint_paths_to,
)
from aila.platform.mcp.adapters.generic import adapt_generic
from aila.platform.mcp.adapters.known_tools import REA_TOOLS, RE_ANALYTICS_TOOLS
from aila.platform.mcp.adapters.rea import (
    adapt_rea_analyze_function,
    adapt_rea_binary_overview,
    adapt_rea_byte_entropy,
    adapt_rea_call_graph,
    adapt_rea_compare_functions,
    adapt_rea_disassembly,
    adapt_rea_list_procedures,
    adapt_rea_pseudocode,
    adapt_rea_xrefs,
)
from aila.modules.vr.agents.tool_executor import ToolExecutor
from aila.platform.agents.tool_execution import parse_command
from aila.modules.vr.contracts import PayloadKind


def _ctx(server: str = "rea", tool: str = "procedure_pseudo_code", **extra) -> AdapterContext:
    return AdapterContext(
        mcp_server_id=server,
        tool_name=tool,
        investigation_id="inv-1",
        branch_id="br-1",
        call_id="call-1",
        args=extra,
    )


# ----------------------------------------------------------------------
# Registry + KNOWN_TOOLS coverage
# ----------------------------------------------------------------------


class TestRegistry:
    def test_known_tools_complete(self) -> None:
        # Every server in KNOWN_TOOLS has tools registered
        assert "rea" in KNOWN_TOOLS
        assert "re_analytics" in KNOWN_TOOLS
        assert "audit_mcp" in KNOWN_TOOLS
        assert "android_mcp" in KNOWN_TOOLS
        assert len(REA_TOOLS) >= 20
        assert len(RE_ANALYTICS_TOOLS) >= 60
        assert len(AUDIT_MCP_TOOLS) >= 50
        assert len(ANDROID_MCP_TOOLS) >= 20

    def test_registered_tools_includes_all_known(self) -> None:
        from aila.platform.mcp.adapters.known_tools import _ALWAYS_SUPPRESS

        tools = set(registered_tools())
        for name in REA_TOOLS:
            if name in _ALWAYS_SUPPRESS.get("rea", frozenset()):
                continue
            assert f"rea.{name}" in tools
        for name in RE_ANALYTICS_TOOLS:
            if name in _ALWAYS_SUPPRESS.get("re_analytics", frozenset()):
                continue
            assert f"re_analytics.{name}" in tools
        for name in AUDIT_MCP_TOOLS:
            if name in _ALWAYS_SUPPRESS.get("audit_mcp", frozenset()):
                continue
            assert f"audit_mcp.{name}" in tools
        for name in ANDROID_MCP_TOOLS:
            if name in _ALWAYS_SUPPRESS.get("android_mcp", frozenset()):
                continue
            assert f"android_mcp.{name}" in tools

    def test_every_known_tool_resolves_to_some_adapter(self) -> None:
        # The point of KNOWN_TOOLS: every entry must be callable,
        # either via specialized or generic adapter -- UNLESS it has
        # been explicitly suppressed (``_ALWAYS_SUPPRESS``), in which
        # case ``get_adapter`` must return ``None`` so dispatch fails
        # at the executor instead of silently running a deprecated
        # tool through the generic fallback.
        from aila.platform.mcp.adapters.known_tools import _ALWAYS_SUPPRESS

        for server, names in KNOWN_TOOLS.items():
            suppress = _ALWAYS_SUPPRESS.get(server, frozenset())
            for name in names:
                if name in suppress:
                    assert get_adapter(server, name) is None, (
                        f"{server}.{name} is in _ALWAYS_SUPPRESS but "
                        f"get_adapter still returned an adapter"
                    )
                    continue
                assert get_adapter(server, name) is not None, (
                    f"no adapter for {server}.{name}"
                )

    def test_specialized_takes_priority_over_generic(self) -> None:
        # procedure_pseudo_code has a specialized adapter
        adapter = get_adapter("rea", "procedure_pseudo_code")
        assert adapter is adapt_rea_pseudocode
        # inspect_byte_entropy also specialized
        assert get_adapter("rea", "inspect_byte_entropy") is adapt_rea_byte_entropy

    def test_unknown_tool_returns_none(self) -> None:
        assert get_adapter("rea", "bogus_tool_name") is None
        # A tool name that no catalog owns stays unknown even when the
        # server_id is garbage. (A REAL rea tool name cannot be used
        # here: ``canonicalize_tool_id`` deliberately collapses an
        # unknown server + uniquely-owned tool onto its owner -- so
        # ``("nonexistent_server", "procedure_pseudo_code")`` resolves
        # to the rea adapter by design, issue #251.)
        assert get_adapter("nonexistent_server", "bogus_tool_name") is None

    def test_suppressed_tools_absent_from_registered_tools(self) -> None:
        # ``registered_tools()`` is used by diagnostics + the prompt
        # builder fallback. A suppressed tool that still shows up in
        # the listing is just another way for the agent to learn the
        # name and try to dispatch it.
        listed = set(registered_tools())
        assert "audit_mcp.search_source" not in listed

    def test_specialized_tools_lists_only_specialized(self) -> None:
        spec = set(specialized_tools())
        # Sanity: spec is a proper subset of all registered tools
        assert spec.issubset(set(registered_tools()))
        # Known specialized tools are in
        assert "rea.procedure_pseudo_code" in spec
        assert "audit_mcp.taint_paths_to" in spec
        # Tools without specialized adapters are NOT in
        assert "rea.search_strings" not in spec
        assert "audit_mcp.cache_stats" not in spec


# ----------------------------------------------------------------------
# F-1 android_mcp dispatch wiring (ToolExecutor + KNOWN_TOOLS + parser)
# ----------------------------------------------------------------------


class TestAndroidMcpDispatch:
    """Cover the F-1 wiring: an investigation against an ``android_apk``
    target must be able to issue ``tool_run`` commands of the form
    ``android_mcp.<tool>`` and have them reach the ``AndroidMcpBridgeTool``.

    These tests are intentionally DB-free. They cover the three failure
    modes the old code-path produced silently:

      1. ``get_adapter("android_mcp", "<known>")`` returned ``None`` --
         the executor would emit "no tool 'android_mcp.<x>'" before
         dispatch.
      2. ``ToolExecutor.__init__`` did not accept an ``android_mcp``
         parameter and ``self._bridges`` had no ``"android_mcp"`` key --
         the executor would emit "No bridge configured for MCP server
         'android_mcp'" at the bridge lookup step.
      3. The ``parse_command`` JSON parser rejected the dotted tool id
         -- same failure mode as (1) one step earlier.
    """

    def test_android_mcp_known_tools_resolve_to_generic_adapter(self) -> None:
        # Every documented android-mcp tool must produce a non-None
        # adapter so the executor's get_adapter() lookup succeeds.
        for tool in ANDROID_MCP_TOOLS:
            adapter = get_adapter("android_mcp", tool)
            assert adapter is not None, f"no adapter for android_mcp.{tool}"
            # No specialized adapters registered yet; everything falls
            # through to adapt_generic. When the next iteration adds a
            # specialized adapter this assertion changes, not the wiring.
            assert adapter is adapt_generic

    def test_android_mcp_unknown_tool_returns_none(self) -> None:
        # Loud failure for hallucinated tool names -- the executor uses
        # this to surface "no such tool" instead of a silent 404.
        assert get_adapter("android_mcp", "bogus_handler") is None

    def test_jadx_decompile_parses_as_android_mcp_call(self) -> None:
        command = json.dumps({
            "tool": "android_mcp.jadx_decompile",
            "args": {"apk_path": "/tmp/sample.apk"},
        })
        parsed = parse_command(command)
        assert parsed is not None
        tool_id, args = parsed
        assert tool_id == "android_mcp.jadx_decompile"
        server_id, _, tool_name = tool_id.partition(".")
        assert server_id == "android_mcp"
        assert tool_name == "jadx_decompile"
        assert args == {"apk_path": "/tmp/sample.apk"}

    def test_tool_executor_registers_android_mcp_bridge(self) -> None:
        # The bridge lookup in ToolExecutor.execute() reads
        # self._bridges[server_id]; this test ensures the constructor
        # actually wires android_mcp into that dict, which is the
        # mechanical contract F-1 establishes.


        class _FakeBridge:
            name = "fake"

            async def forward(self, action: str | None = None, **kwargs):
                return {"status": "ready", "action": action, "kwargs": kwargs}

        ida = _FakeBridge()
        audit = _FakeBridge()
        android = _FakeBridge()
        executor = ToolExecutor(rea=ida, audit_mcp=audit, android_mcp=android)
        # RFC-11 Tier C: _bridge_for() is the dispatch surface inside
        # execute(); an injected bridge is returned as an override so the
        # "No bridge configured" path never fires for a wired server.
        assert executor._bridge_for("rea") is ida
        assert executor._bridge_for("audit_mcp") is audit
        assert executor._bridge_for("android_mcp") is android

    def test_android_mcp_composite_handlers_registered(self) -> None:
        # The composite layer (verify_capabilities / classify_behavior /
        # compute_risk_score / find_secrets) is what VR personas mostly
        # call. They must be present even though the same names also
        # appear on the re_analytics surface -- KNOWN_TOOLS is keyed by
        # server_id so collisions resolve by server.
        for composite in (
            "verify_capabilities",
            "classify_behavior",
            "compute_risk_score",
            "find_secrets",
        ):
            assert composite in ANDROID_MCP_TOOLS
            assert get_adapter("android_mcp", composite) is adapt_generic

# ----------------------------------------------------------------------
# Generic fallback
# ----------------------------------------------------------------------


class TestAdaptGeneric:
    def test_packages_raw_as_text(self) -> None:
        raw = {"status": "ready", "count": 5, "results": [1, 2, 3]}
        ctx = _ctx(server="rea", tool="search_strings")
        out = adapt_generic(raw, ctx)
        assert out.payload_kind == PayloadKind.TEXT
        assert out.payload["tool"] == "rea.search_strings"
        assert out.payload["data"] is raw
        assert out.payload["source_provenance"]["call_id"] == "call-1"

    def test_observable_includes_full_preview(self) -> None:
        # The generic adapter no longer truncates per-call (commit
        # 7ee32a7 -- MAX_OBS_DUMP_CHARS bumped to 100MB). Inputs well
        # below the cap surface verbatim in the observable so the
        # agent never has to issue a follow-up read to see the tail.
        raw = {"results": ["X" * 100 for _ in range(100)]}
        out = adapt_generic(raw, _ctx(tool="search_bytes"))
        assert len(out.observables_delta) == 1
        obs = next(iter(out.observables_delta.values()))
        assert "truncated" not in obs
        # All 100 entries \u00d7 100 X's land in the JSON dump verbatim.
        assert obs.count("X" * 100) == 100

    def test_summary_includes_status_and_counts(self) -> None:
        raw = {"status": "ready", "total": 42}
        out = adapt_generic(raw, _ctx(tool="list_procedures"))
        assert "status=ready" in out.summary
        assert "total=42" in out.summary

    def test_error_response_summary(self) -> None:
        raw = {"status": "error", "error": "binary not found"}
        out = adapt_generic(raw, _ctx(tool="binary_overview"))
        assert "error" in out.summary
        assert "binary not found" in out.summary

    def test_non_dict_response(self) -> None:
        # Defensive: not all MCP tools return dicts
        out = adapt_generic("just a string", _ctx())  # type: ignore[arg-type]
        assert out.payload_kind == PayloadKind.TEXT
        assert "non-dict" in out.summary


# ----------------------------------------------------------------------
# DECOMPILED_FUNCTION adapters (REA)
# ----------------------------------------------------------------------


class TestAdaptReaPseudocode:
    def test_basic(self) -> None:
        raw = {
            "normalized_result": "int main() {\n  return 0;\n}\n",
            "evidence_id": "e1",
        }
        ctx = _ctx(tool="procedure_pseudo_code",
                   procedure="main", address="0x140012345")
        out = adapt_rea_pseudocode(raw, ctx)
        assert out.payload_kind == PayloadKind.DECOMPILED_FUNCTION
        assert out.payload["function_name"] == "main"
        assert out.payload["address"] == "0x140012345"
        assert out.payload["pseudocode"] == "int main() {\n  return 0;\n}"
        assert out.payload["line_count"] == 3
        # New global-namespaced obs key: <server>.<tool>.<suffix>
        key = "rea.procedure_pseudo_code.decompiled.main"
        assert key in out.observables_delta
        assert "int main()" in out.observables_delta[key]

    def test_preserves_long_pseudocode_verbatim(self) -> None:
        # Per the 2026-05-24 "remove per-tool-call observable truncation"
        # decision (commit 7ee32a7), per-value caps were bumped to 100MB
        # so the agent never sees a truncated load-bearing branch. The
        # observable carries the full body verbatim -- no truncation
        # marker, no banner -- up to that hard floor.
        raw = {"normalized_result": "X" * 5000}
        out = adapt_rea_pseudocode(raw, _ctx(tool="procedure_pseudo_code", procedure="huge"))
        obs = out.observables_delta["rea.procedure_pseudo_code.decompiled.huge"]
        assert "truncated" not in obs
        assert obs == "X" * 5000

    def test_missing_fields_recover(self) -> None:
        raw = {"normalized_result": None, "evidence_id": "e1"}
        out = adapt_rea_pseudocode(raw, _ctx(tool="procedure_pseudo_code"))
        assert out.payload["function_name"] == "<unknown>"
        assert out.payload["address"] == ""
        assert out.payload["pseudocode"] == ""
        assert out.payload["line_count"] == 0
        key = "rea.procedure_pseudo_code.decompiled.<unknown>"
        assert key in out.observables_delta


class TestAdaptReaAnalyzeFunction:
    def test_dossier(self) -> None:
        raw = {
            "normalized_result": {
                "procedure": {"name": "main", "address": "0x140000000"},
                "pseudocode": "int main() {\n  return 0;\n}\n",
                "callers": [{"name": "start", "address": "0x14000f000"}],
                "callees": [{"name": "puts", "address": "0x14000a000"}],
                "unresolved_calls": [],
                "incoming_references": [{"source_address": "0x14000f000"}],
                "outgoing_references": [],
                "referenced_strings": [{"address": "0x2000", "value": "hello"}],
            },
            "evidence_id": "e1",
        }
        ctx = _ctx(tool="analyze_function", procedure="main")
        out = adapt_rea_analyze_function(raw, ctx)
        assert out.payload_kind == PayloadKind.DECOMPILED_FUNCTION
        assert out.payload["function_name"] == "main"
        assert out.payload["address"] == "0x140000000"
        assert "int main()" in out.payload["pseudocode"]
        assert out.payload["caller_count"] == 1
        assert out.payload["callee_count"] == 1
        assert out.payload["referenced_string_count"] == 1
        key = "rea.analyze_function.decompiled.main"
        assert "int main()" in out.observables_delta[key]

    def test_summary_projection_reports_parent(self) -> None:
        # Default detail on some providers returns an
        # inspect_analysis_view projection (kind/view/parent_evidence_id/
        # coverage/summary) with NO dossier content -- the adapter must
        # say so and point at the retained parent evidence instead of
        # faking a body.
        raw = {
            "normalized_result": {
                "kind": "inspect_analysis_view",
                "parent_evidence_id": "e-parent",
                "summary": {"row_count": 3},
            },
            "evidence_id": "e1",
        }
        ctx = _ctx(tool="analyze_function", procedure="main")
        out = adapt_rea_analyze_function(raw, ctx)
        assert out.payload_kind == PayloadKind.DECOMPILED_FUNCTION
        assert out.payload["summary_projection"] is True
        assert out.payload["parent_evidence_id"] == "e-parent"
        assert out.payload["pseudocode"] == ""
        assert out.payload["line_count"] == 0
        key = "rea.analyze_function.dossier.main"
        assert key in out.observables_delta


class TestAdaptReadFunction:
    def test_basic(self) -> None:
        raw = {
            "function_name": "ngx_http_parse_request_line",
            "source": "ngx_int_t ngx_http_parse_request_line(...) {\n  ...\n}\n",
            "language": "c",
            "file": "src/http/ngx_http_parse.c",
            "line": 142,
        }
        ctx = _ctx(server="audit_mcp", tool="read_function",
                   function="ngx_http_parse_request_line")
        out = adapt_read_function(raw, ctx)
        assert out.payload_kind == PayloadKind.DECOMPILED_FUNCTION
        assert out.payload["language"] == "c"
        assert "src/http/ngx_http_parse.c:142" in out.payload["address"]


# ----------------------------------------------------------------------
# XREF_VIEW adapters
# ----------------------------------------------------------------------


class TestAdaptReaXrefs:
    def test_basic(self) -> None:
        # Live shape: normalized_result is a bare list of hex address
        # strings referencing the queried address (REA's xrefs_to
        # analogue).
        raw = {
            "normalized_result": ["0x140001000", "0x140002000"],
            "evidence_id": "e1",
        }
        ctx = _ctx(tool="xrefs", address="0x140000000")
        out = adapt_rea_xrefs(raw, ctx)
        assert out.payload_kind == PayloadKind.XREF_VIEW
        assert out.payload["target_address"] == "0x140000000"
        assert out.payload["xrefs"] == ["0x140001000", "0x140002000"]
        key = "rea.xrefs.xrefs_to.0x140000000"
        obs = out.observables_delta[key]
        assert "2 referencing addresses for 0x140000000" in obs
        assert "0x140001000" in obs
        assert "0x140002000" in obs

    def test_empty(self) -> None:
        raw = {"normalized_result": [], "evidence_id": "e1"}
        out = adapt_rea_xrefs(raw, _ctx(tool="xrefs", address="0x140000000"))
        key = "rea.xrefs.xrefs_to.0x140000000"
        assert "(none)" in out.observables_delta[key]


class TestAdaptCallersOf:
    def test_basic(self) -> None:
        raw = {
            "callers": [
                {"function_name": "do_recv", "file": "net.c", "line": 50},
                {"function_name": "handle_packet", "file": "net.c", "line": 99},
            ],
        }
        ctx = _ctx(server="audit_mcp", tool="callers_of", function="parse_header")
        out = adapt_callers_of(raw, ctx)
        assert out.payload_kind == PayloadKind.XREF_VIEW
        assert out.payload["total"] == 2
        key = "audit_mcp.callers_of.callers_of.parse_header"
        assert "do_recv @ net.c:50" in out.observables_delta[key]


class TestAdaptCalleesOf:
    def test_basic(self) -> None:
        raw = {"callees": [{"name": "memcpy"}, {"name": "strlen"}]}
        ctx = _ctx(server="audit_mcp", tool="callees_of", function="parse_header")
        out = adapt_callees_of(raw, ctx)
        assert out.payload_kind == PayloadKind.XREF_VIEW
        assert out.payload["total"] == 2


# ----------------------------------------------------------------------
# TAINT_FLOW adapters
# ----------------------------------------------------------------------


class TestAdaptTaintPathsTo:
    def test_basic(self) -> None:
        raw = {
            "paths": [
                {"source": "http_request", "sink": "system", "hops": 4},
            ],
        }
        ctx = _ctx(server="audit_mcp", tool="taint_paths_to", sink="system")
        out = adapt_taint_paths_to(raw, ctx)
        assert out.payload_kind == PayloadKind.TAINT_FLOW
        assert out.payload["sink"] == "system"
        assert out.payload["total"] == 1

    def test_empty(self) -> None:
        ctx = _ctx(server="audit_mcp", tool="taint_paths_to", sink="exec")
        out = adapt_taint_paths_to({"paths": []}, ctx)
        assert "(no taint paths)" in out.observables_delta["audit_mcp.taint_paths_to.taint.exec"]

    def test_reads_entrypoint_paths_and_path_count(self) -> None:
        # Real audit-mcp shape: call chains live under ``entrypoint_paths``
        # (list-of-lists) with an authoritative ``path_count``. The adapter
        # previously read only ``paths`` / ``results`` / ``taint_paths`` and
        # so reported 0 for every real result.
        raw = {
            "sink": "create_test_session",
            "is_tainted": False,
            "path_count": 7,
            "caller_count": 5,
            "exploitable": False,
            "entrypoint_paths": [
                ["m:main", "m:test_backend", "m:create_test_session"],
                ["m:main", "m:test_resource", "m:create_test_session"],
            ],
        }
        ctx = _ctx(
            server="audit_mcp", tool="taint_paths_to",
            name="create_test_session",
        )
        out = adapt_taint_paths_to(raw, ctx)
        assert out.payload_kind == PayloadKind.TAINT_FLOW
        # authoritative path_count, NOT len(entrypoint_paths)
        assert out.payload["total"] == 7
        assert out.payload["caller_count"] == 5
        assert out.payload["sink"] == "create_test_session"
        obs = out.observables_delta[
            "audit_mcp.taint_paths_to.taint.create_test_session"
        ]
        assert "7 path(s)" in obs
        # the call chain is rendered, not skipped as a non-dict
        assert "m:main" in obs and "create_test_session" in obs


class TestAdaptPathsBetween:
    def test_basic(self) -> None:
        raw = {"paths": [{"source": "A", "sink": "B", "hops": 2}]}
        ctx = _ctx(server="audit_mcp", tool="paths_between",
                   **{"from": "A", "to": "B"})
        out = adapt_paths_between(raw, ctx)
        assert out.payload_kind == PayloadKind.TAINT_FLOW


# ----------------------------------------------------------------------
# GRAPH_VIEW adapters
# ----------------------------------------------------------------------


class TestAdaptReaCallGraph:
    def test_basic(self) -> None:
        # Live shape: normalized_result.graph maps depth -> node list;
        # each node is {address, status, calls: [address...]}.
        raw = {
            "normalized_result": {
                "graph": {
                    "0": [
                        {"address": "0x140000000", "status": "ok",
                         "calls": ["0x140001000"]},
                    ],
                    "1": [
                        {"address": "0x140001000", "status": "ok", "calls": []},
                    ],
                },
            },
            "evidence_id": "e1",
        }
        ctx = _ctx(tool="get_call_graph", address="0x140000000")
        out = adapt_rea_call_graph(raw, ctx)
        assert out.payload_kind == PayloadKind.GRAPH_VIEW
        assert out.payload["root"] == "0x140000000"
        assert out.payload["direction"] == "forward"
        assert out.payload["total"] == 2
        assert out.payload["depth_counts"] == {"0": 1, "1": 1}
        key = "rea.get_call_graph.call_graph.0x140000000"
        obs = out.observables_delta[key]
        assert '"total":2' in obs
        assert "0x140001000" in obs


class TestAdaptExportGraph:
    def test_basic(self) -> None:
        raw = {"nodes": [1, 2, 3], "edges": [[1, 2], [2, 3]], "format": "json"}
        ctx = _ctx(server="audit_mcp", tool="export_graph")
        out = adapt_export_graph(raw, ctx)
        assert out.payload_kind == PayloadKind.GRAPH_VIEW
        assert out.payload["node_count"] == 3
        assert out.payload["edge_count"] == 2
        assert out.payload["format"] == "json"


# ----------------------------------------------------------------------
# CODE_POINTER adapters
# ----------------------------------------------------------------------


class TestAdaptReaDisassembly:
    def test_basic(self) -> None:
        # Live shape: normalized_result is assembly text, one
        # "<addr>: <ins>" line per instruction.
        raw = {
            "normalized_result": (
                "0x140001000: push rbp\n"
                "0x140001001: mov rbp, rsp\n"
                "0x140001002: ret\n"
            ),
            "evidence_id": "e1",
        }
        ctx = _ctx(tool="procedure_assembly", procedure="main")
        out = adapt_rea_disassembly(raw, ctx)
        assert out.payload_kind == PayloadKind.CODE_POINTER
        assert out.payload["label"] == "assembly:main"
        assert out.payload["line_count"] == 3
        assert "push rbp" in out.payload["body"]
        key = "rea.procedure_assembly.asm.main"
        assert "push rbp" in out.observables_delta[key]

    def test_missing_result(self) -> None:
        raw = {"normalized_result": None, "evidence_id": "e1"}
        out = adapt_rea_disassembly(raw, _ctx(tool="procedure_assembly", procedure="foo"))
        assert out.payload["body"] == ""
        assert out.payload["line_count"] == 0
        key = "rea.procedure_assembly.asm.foo"
        assert "(no assembly returned)" in out.observables_delta[key]


# ----------------------------------------------------------------------
# PATCH_DIFF adapters
# ----------------------------------------------------------------------


class TestAdaptReaCompareFunctions:
    def test_basic(self) -> None:
        raw = {
            "normalized_result": {
                "verdict": "identical",
                "dimensions": [
                    {"dimension": "bytes", "status": "identical"},
                    {"dimension": "pseudocode", "status": "changed"},
                ],
            },
            "evidence_id": "e1",
        }
        ctx = _ctx(tool="compare_functions",
                   procedure_a="main", procedure_b="main_patched")
        out = adapt_rea_compare_functions(raw, ctx)
        assert out.payload_kind == PayloadKind.PATCH_DIFF
        assert out.payload["verdict"] == "identical"
        assert len(out.payload["dimensions"]) == 2
        assert "1/2 dimensions changed" in out.summary
        key = "rea.compare_functions.compare_functions"
        assert key in out.observables_delta
        assert '"verdict":"identical"' in out.observables_delta[key]


class TestAdaptDiffCodebases:
    def test_basic(self) -> None:
        raw = {
            "changes": [
                {"change": "added", "path": "new.c"},
                {"change": "removed", "path": "old.c"},
                {"change": "modified", "path": "main.c"},
            ],
        }
        ctx = _ctx(server="audit_mcp", tool="diff_codebases")
        out = adapt_diff_codebases(raw, ctx)
        assert out.payload_kind == PayloadKind.PATCH_DIFF
        assert out.payload["added"] == 1
        assert out.payload["removed"] == 1
        assert out.payload["modified"] == 1


# ----------------------------------------------------------------------
# TEXT specializations
# ----------------------------------------------------------------------


class TestAdaptReaBinaryOverview:
    def test_basic(self) -> None:
        raw = {
            "normalized_result": {
                "document": "sample.exe",
                "image_base": "0x140000000",
                "segments": [
                    {"name": ".text", "start": "0x140001000",
                     "end": "0x140010000"},
                ],
                "segment_count": 1,
                "procedure_count": 42,
                "string_count": 128,
            },
            "evidence_id": "e1",
        }
        ctx = _ctx(tool="binary_overview")
        out = adapt_rea_binary_overview(raw, ctx)
        assert out.payload_kind == PayloadKind.TEXT
        assert out.payload["document"] == "sample.exe"
        assert out.payload["image_base"] == "0x140000000"
        assert out.payload["segment_count"] == 1
        assert out.payload["procedure_count"] == 42
        assert out.payload["string_count"] == 128
        key = "rea.binary_overview.overview"
        obs = out.observables_delta[key]
        assert "sample.exe" in obs
        assert "42 procedures" in obs
        assert ".text" in obs


class TestAdaptReaListProcedures:
    def test_basic(self) -> None:
        # Live shape: list of {address, value, symbol, procedure} rows;
        # EXTERNAL:0xN pseudo-addresses mark imported procedures.
        raw = {
            "normalized_result": [
                {"address": "0x140001000", "value": "main",
                 "symbol": "main", "procedure": "main"},
                {"address": "EXTERNAL:0x1", "value": "puts",
                 "symbol": "puts", "procedure": "puts"},
            ],
            "evidence_id": "e1",
        }
        ctx = _ctx(tool="list_procedures")
        out = adapt_rea_list_procedures(raw, ctx)
        assert out.payload_kind == PayloadKind.TEXT
        assert out.payload["total"] == 2
        assert out.payload["external_count"] == 1
        assert out.payload["internal_count"] == 1
        key = "rea.list_procedures.procedures"
        obs = out.observables_delta[key]
        assert "main" in obs
        assert "2 total (1 external imports)" in obs


class TestAdaptFuzzingTargets:
    def test_basic(self) -> None:
        raw = {
            "targets": [
                {"function_name": "parse_pdu", "risk_score": 9.0,
                 "blast_radius": 80, "complexity": 22},
                {"function_name": "validate_token", "risk_score": 5.0},
            ],
        }
        ctx = _ctx(server="audit_mcp", tool="fuzzing_targets", index_id="abc")
        out = adapt_fuzzing_targets(raw, ctx)
        assert out.payload_kind == PayloadKind.TEXT
        assert out.payload["total"] == 2
        assert len(out.observables_delta) == 1
        obs = next(iter(out.observables_delta.values()))
        assert "parse_pdu" in obs
        assert "blast=80" in obs

    def test_alternative_results_key(self) -> None:
        raw = {"results": [{"name": "x", "score": 1.0}]}
        out = adapt_fuzzing_targets(raw, _ctx(server="audit_mcp", tool="fuzzing_targets"))
        assert out.payload["total"] == 1


class TestAdaptAttackSurface:
    def test_basic(self) -> None:
        # Canonical audit_mcp shape: ``entrypoints`` list with
        # ``node_id``/``kind``/``trust_level``/``asset_value``/``description``.
        # The adapter groups by ``kind`` and renders a per-kind section
        # with trust/asset distribution. Legacy ``surfaces|entries|results``
        # keys still parse through ``_list_or_empty`` for older fixtures.
        raw = {
            "entrypoints": [
                {"node_id": "http_handle_request", "kind": "http_route",
                 "trust_level": "untrusted", "asset_value": "high",
                 "description": "primary HTTP request entry"},
                {"node_id": "rpc_dispatch", "kind": "rpc_handler",
                 "trust_level": "internal", "asset_value": "medium"},
            ],
        }
        ctx = _ctx(server="audit_mcp", tool="attack_surface", index_id="x")
        out = adapt_attack_surface(raw, ctx)
        assert out.payload_kind == PayloadKind.TEXT
        assert len(out.observables_delta) == 1
        obs = next(iter(out.observables_delta.values()))
        # Header line: total count + by-kind breakdown
        assert "2 entry point(s) across 2 kind(s)" in obs
        # Per-kind section heading
        assert "## http_route (1)" in obs
        assert "## rpc_handler (1)" in obs
        # Both entries rendered with their node_id
        assert "http_handle_request" in obs
        assert "rpc_dispatch" in obs
        # Trust / asset surfaced per kind
        assert "untrusted" in obs
        assert "high" in obs
        # Payload exposes total + by_kind aggregation for downstream UI
        assert out.payload["total"] == 2
        assert out.payload["by_kind"] == {"http_route": 1, "rpc_handler": 1}


class TestAdaptComplexityHotspots:
    def test_basic(self) -> None:
        raw = {
            "hotspots": [
                {"function_name": "ngx_http_parse_request_line",
                 "cyclomatic": 42, "cognitive": 65,
                 "file": "ngx_http_parse.c", "line": 142},
            ],
        }
        ctx = _ctx(server="audit_mcp", tool="complexity_hotspots", index_id="x")
        out = adapt_complexity_hotspots(raw, ctx)
        assert out.payload_kind == PayloadKind.TEXT
        assert len(out.observables_delta) == 1
        obs = next(iter(out.observables_delta.values()))
        assert "ngx_http_parse_request_line" in obs
        assert "cyc=42" in obs
        assert "cog=65" in obs


# ----------------------------------------------------------------------
# Tool-executor command parser (unchanged)
# ----------------------------------------------------------------------


class TestCommandParser:
    def test_valid_command(self) -> None:
        raw = json.dumps({"tool": "rea.procedure_pseudo_code",
                          "args": {"procedure": "main", "address": "0x140000000"}})
        parsed = parse_command(raw)
        assert parsed is not None
        tool_id, args = parsed
        assert tool_id == "rea.procedure_pseudo_code"
        assert args == {"procedure": "main", "address": "0x140000000"}

    def test_empty_string(self) -> None:
        assert parse_command("") is None
        assert parse_command("   ") is None

    def test_invalid_json(self) -> None:
        assert parse_command("not json") is None
        assert parse_command("{incomplete") is None

    def test_non_dict_top_level(self) -> None:
        assert parse_command("[]") is None
        assert parse_command('"just a string"') is None
        assert parse_command("42") is None

    def test_missing_tool_field(self) -> None:
        assert parse_command(json.dumps({"args": {}})) is None

    def test_missing_args_defaults_empty(self) -> None:
        raw = json.dumps({"tool": "rea.procedure_pseudo_code"})
        parsed = parse_command(raw)
        assert parsed is not None
        assert parsed[1] == {}

    def test_wrong_args_type(self) -> None:
        raw = json.dumps({"tool": "x.y", "args": "not a dict"})
        assert parse_command(raw) is None
