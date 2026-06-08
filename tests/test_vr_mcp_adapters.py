"""MCP adapter unit tests — registry, family adapters, generic fallback.

Adapters are pure functions. Tests stub the raw MCP response and verify
the (payload_kind, payload, observables_delta) output shape.
"""
from __future__ import annotations

import json

from aila.modules.vr.agents.mcp_adapters import (
    ANDROID_MCP_TOOLS,
    AUDIT_MCP_TOOLS,
    IDA_HEADLESS_TOOLS,
    KNOWN_TOOLS,
    AdapterContext,
    get_adapter,
    registered_tools,
    specialized_tools,
)
from aila.modules.vr.agents.mcp_adapters.audit_mcp import (
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
from aila.modules.vr.agents.mcp_adapters.generic import adapt_generic
from aila.modules.vr.agents.mcp_adapters.ida_headless import (
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
from aila.modules.vr.agents.tool_executor import ToolExecutor, _parse_command
from aila.modules.vr.contracts import PayloadKind


def _ctx(server: str = "ida_headless", tool: str = "decompile", **extra) -> AdapterContext:
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
        assert "ida_headless" in KNOWN_TOOLS
        assert "audit_mcp" in KNOWN_TOOLS
        assert "android_mcp" in KNOWN_TOOLS
        assert len(IDA_HEADLESS_TOOLS) >= 80
        assert len(AUDIT_MCP_TOOLS) >= 50
        assert len(ANDROID_MCP_TOOLS) >= 22

    def test_registered_tools_includes_all_known(self) -> None:
        tools = set(registered_tools())
        for name in IDA_HEADLESS_TOOLS:
            assert f"ida_headless.{name}" in tools
        for name in AUDIT_MCP_TOOLS:
            assert f"audit_mcp.{name}" in tools
        for name in ANDROID_MCP_TOOLS:
            assert f"android_mcp.{name}" in tools

    def test_every_known_tool_resolves_to_some_adapter(self) -> None:
        # The point of KNOWN_TOOLS: every entry must be callable, either
        # via specialized or generic adapter.
        for server, names in KNOWN_TOOLS.items():
            for name in names:
                assert get_adapter(server, name) is not None, (
                    f"no adapter for {server}.{name}"
                )

    def test_specialized_takes_priority_over_generic(self) -> None:
        # decompile has a specialized adapter
        adapter = get_adapter("ida_headless", "decompile")
        assert adapter is adapt_decompile
        # checksec also specialized
        assert get_adapter("ida_headless", "checksec") is adapt_checksec

    def test_unknown_tool_returns_none(self) -> None:
        assert get_adapter("ida_headless", "bogus_tool_name") is None
        assert get_adapter("nonexistent_server", "decompile") is None

    def test_specialized_tools_lists_only_specialized(self) -> None:
        spec = set(specialized_tools())
        # Sanity: spec is a proper subset of all registered tools
        assert spec.issubset(set(registered_tools()))
        # Known specialized tools are in
        assert "ida_headless.decompile" in spec
        assert "audit_mcp.taint_paths_to" in spec
        # Tools without specialized adapters are NOT in
        assert "ida_headless.list_binaries" not in spec
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

      1. ``get_adapter("android_mcp", "<known>")`` returned ``None`` —
         the executor would emit "no tool 'android_mcp.<x>'" before
         dispatch.
      2. ``ToolExecutor.__init__`` did not accept an ``android_mcp``
         parameter and ``self._bridges`` had no ``"android_mcp"`` key —
         the executor would emit "No bridge configured for MCP server
         'android_mcp'" at the bridge lookup step.
      3. The ``_parse_command`` JSON parser rejected the dotted tool id
         — same failure mode as (1) one step earlier.
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
        # Loud failure for hallucinated tool names — the executor uses
        # this to surface "no such tool" instead of a silent 404.
        assert get_adapter("android_mcp", "bogus_handler") is None

    def test_androguard_summary_parses_as_android_mcp_call(self) -> None:
        command = json.dumps({
            "tool": "android_mcp.androguard_summary",
            "args": {"apk_path": "/tmp/sample.apk"},
        })
        parsed = _parse_command(command)
        assert parsed is not None
        tool_id, args = parsed
        assert tool_id == "android_mcp.androguard_summary"
        server_id, _, tool_name = tool_id.partition(".")
        assert server_id == "android_mcp"
        assert tool_name == "androguard_summary"
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
        executor = ToolExecutor(ida=ida, audit_mcp=audit, android_mcp=android)
        # The private dict is the dispatch surface inside execute(); a
        # KeyError here at runtime would surface as the "No bridge
        # configured" string the engine sees in its next turn.
        assert executor._bridges["ida_headless"] is ida
        assert executor._bridges["audit_mcp"] is audit
        assert executor._bridges["android_mcp"] is android

    def test_android_mcp_composite_handlers_registered(self) -> None:
        # The composite layer (verify_capabilities / classify_behavior /
        # compute_risk_score / find_secrets) is what VR personas mostly
        # call. They must be present even though the same names also
        # appear on the ida_headless surface — KNOWN_TOOLS is keyed by
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
        ctx = _ctx(server="ida_headless", tool="list_binaries")
        out = adapt_generic(raw, ctx)
        assert out.payload_kind == PayloadKind.TEXT
        assert out.payload["tool"] == "ida_headless.list_binaries"
        assert out.payload["data"] is raw
        assert out.payload["source_provenance"]["call_id"] == "call-1"

    def test_observables_bounded(self) -> None:
        raw = {"results": ["X" * 100 for _ in range(100)]}
        out = adapt_generic(raw, _ctx(tool="search_pattern"))
        obs = out.observables_delta["ida_headless.search_pattern"]
        assert "truncated" in obs
        assert len(obs) < 6000

    def test_summary_includes_status_and_counts(self) -> None:
        raw = {"status": "ready", "total": 42}
        out = adapt_generic(raw, _ctx(tool="list_functions"))
        assert "status=ready" in out.summary
        assert "total=42" in out.summary

    def test_error_response_summary(self) -> None:
        raw = {"status": "error", "error": "binary not found"}
        out = adapt_generic(raw, _ctx(tool="binary_metadata"))
        assert "error" in out.summary
        assert "binary not found" in out.summary

    def test_non_dict_response(self) -> None:
        # Defensive: not all MCP tools return dicts
        out = adapt_generic("just a string", _ctx())  # type: ignore[arg-type]
        assert out.payload_kind == PayloadKind.TEXT
        assert "non-dict" in out.summary


# ----------------------------------------------------------------------
# DECOMPILED_FUNCTION adapters
# ----------------------------------------------------------------------


class TestAdaptDecompile:
    def test_basic(self) -> None:
        raw = {
            "status": "ready",
            "function_name": "main",
            "address": "0x140012345",
            "pseudocode": "int main() {\n  return 0;\n}\n",
        }
        ctx = _ctx(tool="decompile", binary_id="abc", address_or_name="main")
        out = adapt_decompile(raw, ctx)
        assert out.payload_kind == PayloadKind.DECOMPILED_FUNCTION
        assert out.payload["function_name"] == "main"
        assert out.payload["address"] == "0x140012345"
        assert out.payload["line_count"] == 4
        # New global-namespaced obs key: <server>.<tool>.<suffix>
        key = "ida_headless.decompile.decompiled.main"
        assert key in out.observables_delta
        assert "int main()" in out.observables_delta[key]

    def test_truncates_long_pseudocode(self) -> None:
        raw = {"function_name": "huge", "pseudocode": "X" * 5000}
        out = adapt_decompile(raw, _ctx())
        obs = out.observables_delta["ida_headless.decompile.decompiled.huge"]
        assert "truncated" in obs
        assert len(obs) < 5000

    def test_missing_fields_recover(self) -> None:
        raw = {"status": "ready"}
        out = adapt_decompile(raw, _ctx(address_or_name="main"))
        assert out.payload["function_name"] == "<unknown>"
        assert out.payload["address"] == "main"


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


class TestAdaptFindApiCallSites:
    def test_basic(self) -> None:
        raw = {
            "api_name": "strcpy",
            "call_sites": [
                {"function_name": "parse_input", "function_address": "0x401200"},
                {"function_name": "handle_request", "function_address": "0x401500"},
            ],
        }
        ctx = _ctx(tool="find_api_call_sites", api_name="strcpy")
        out = adapt_find_api_call_sites(raw, ctx)
        assert out.payload_kind == PayloadKind.XREF_VIEW
        assert out.payload["total"] == 2
        key = "ida_headless.find_api_call_sites.callsites.strcpy"
        assert "parse_input @ 0x401200" in out.observables_delta[key]

    def test_truncates_large_lists(self) -> None:
        raw = {
            "api_name": "memcpy",
            "call_sites": [
                {"function_name": f"f{i}", "function_address": f"0x{i:x}"}
                for i in range(100)
            ],
        }
        out = adapt_find_api_call_sites(raw, _ctx(tool="find_api_call_sites", api_name="memcpy"))
        assert out.payload["total"] == 100
        key = "ida_headless.find_api_call_sites.callsites.memcpy"
        assert "and 75 more" in out.observables_delta[key]


class TestAdaptXrefsTo:
    def test_basic(self) -> None:
        raw = {
            "xrefs": [
                {"function_name": "init", "address": "0x100", "type": "call"},
                {"function_name": "destroy", "address": "0x200", "type": "call"},
            ],
        }
        ctx = _ctx(tool="xrefs_to", address_or_name="0x4040")
        out = adapt_xrefs_to(raw, ctx)
        assert out.payload_kind == PayloadKind.XREF_VIEW
        assert out.payload["target"] == "0x4040"
        assert out.payload["total"] == 2
        key = "ida_headless.xrefs_to.xrefs_to.0x4040"
        assert "init @ 0x100" in out.observables_delta[key]


class TestAdaptXrefsFrom:
    def test_basic(self) -> None:
        raw = {"xrefs": [{"function_name": "puts", "address": "0x300"}]}
        ctx = _ctx(tool="xrefs_from", address_or_name="main")
        out = adapt_xrefs_from(raw, ctx)
        assert out.payload_kind == PayloadKind.XREF_VIEW
        assert out.payload["source"] == "main"
        assert out.payload["total"] == 1


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


class TestAdaptInterproceduralTaint:
    def test_basic(self) -> None:
        raw = {
            "chains": [
                {"source": "recv", "sink": "memcpy", "hops": 3},
                {"source": "read", "sink": "memcpy", "hops": 5},
            ],
        }
        ctx = _ctx(tool="interprocedural_taint", sink_function="memcpy")
        out = adapt_interprocedural_taint(raw, ctx)
        assert out.payload_kind == PayloadKind.TAINT_FLOW
        assert out.payload["total"] == 2
        key = "ida_headless.interprocedural_taint.itp_taint.memcpy"
        assert "recv → memcpy" in out.observables_delta[key]


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


class TestAdaptDefUse:
    def test_basic(self) -> None:
        raw = {"chains": [{"source": "alloca", "sink": "use", "hops": 1}]}
        ctx = _ctx(tool="def_use", address_or_name="vuln_fn")
        out = adapt_def_use(raw, ctx)
        assert out.payload_kind == PayloadKind.TAINT_FLOW


class TestAdaptTraceDataflow:
    def test_basic(self) -> None:
        raw = {"trace": [{"source": "input", "sink": "memcpy", "hops": 2}]}
        ctx = _ctx(tool="trace_dataflow", sink_function="memcpy")
        out = adapt_trace_dataflow(raw, ctx)
        assert out.payload_kind == PayloadKind.TAINT_FLOW


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


class TestAdaptCallGraph:
    def test_basic(self) -> None:
        raw = {"nodes": [{"id": "main"}, {"id": "foo"}],
               "edges": [{"src": "main", "dst": "foo"}]}
        ctx = _ctx(tool="call_graph", address_or_name="main")
        out = adapt_call_graph(raw, ctx)
        assert out.payload_kind == PayloadKind.GRAPH_VIEW
        assert out.payload["node_count"] == 2
        assert out.payload["edge_count"] == 1


class TestAdaptCallChain:
    def test_basic(self) -> None:
        raw = {"chain": [{"name": "A"}, {"name": "B"}]}
        ctx = _ctx(tool="call_chain", target_function="A", direction="callees")
        out = adapt_call_chain(raw, ctx)
        assert out.payload_kind == PayloadKind.GRAPH_VIEW
        assert out.payload["direction"] == "callees"
        assert out.payload["node_count"] == 2


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


class TestAdaptDisassembleFunction:
    def test_basic(self) -> None:
        raw = {"disassembly": "push rbp\nmov rbp, rsp\nret\n"}
        ctx = _ctx(tool="disassemble_function", address_or_name="main")
        out = adapt_disassemble_function(raw, ctx)
        assert out.payload_kind == PayloadKind.CODE_POINTER
        assert out.payload["line_count"] == 4
        key = "ida_headless.disassemble_function.disasm.main"
        assert "push rbp" in out.observables_delta[key]

    def test_lines_field_form(self) -> None:
        raw = {"lines": ["push rbp", "mov rbp, rsp", "ret"]}
        out = adapt_disassemble_function(raw, _ctx(
            tool="disassemble_function", address_or_name="foo"))
        assert "push rbp" in out.payload["body"]


class TestAdaptGetMicrocode:
    def test_basic(self) -> None:
        raw = {"microcode": "mov.4 t1, var_1\n"}
        ctx = _ctx(tool="get_microcode", address_or_name="bar", maturity="current")
        out = adapt_get_microcode(raw, ctx)
        assert out.payload_kind == PayloadKind.CODE_POINTER


class TestAdaptPseudocodeSliceView:
    def test_basic(self) -> None:
        raw = {"slices": "if (x) {\n  call();\n}\n"}
        ctx = _ctx(tool="pseudocode_slice_view", address_or_name="fn")
        out = adapt_pseudocode_slice_view(raw, ctx)
        assert out.payload_kind == PayloadKind.CODE_POINTER


# ----------------------------------------------------------------------
# PATCH_DIFF adapters
# ----------------------------------------------------------------------


class TestAdaptDiffFunction:
    def test_basic(self) -> None:
        raw = {"unified_diff": "-old\n+new\n"}
        ctx = _ctx(tool="diff_function",
                   address_or_name_old="0x100", address_or_name_new="0x200")
        out = adapt_diff_function(raw, ctx)
        assert out.payload_kind == PayloadKind.PATCH_DIFF
        assert out.payload["unified_diff"] == "-old\n+new\n"


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
        obs = out.observables_delta["audit_mcp.fuzzing_targets"]
        assert "parse_pdu" in obs
        assert "blast=80" in obs

    def test_alternative_results_key(self) -> None:
        raw = {"results": [{"name": "x", "score": 1.0}]}
        out = adapt_fuzzing_targets(raw, _ctx(server="audit_mcp", tool="fuzzing_targets"))
        assert out.payload["total"] == 1


class TestAdaptChecksec:
    def test_all_mitigations_on(self) -> None:
        raw = {"nx": True, "aslr": True, "pie": True, "canary": True,
               "cet": True, "cfi": True, "relro_full": True,
               "sanitizers": ["asan"]}
        ctx = _ctx(tool="checksec", binary_id="abc")
        out = adapt_checksec(raw, ctx)
        assert out.payload_kind == PayloadKind.TEXT
        obs = out.observables_delta["ida_headless.checksec"]
        assert "NX: ON" in obs
        assert "PIE: ON" in obs
        assert "RELRO: full" in obs
        assert "asan" in obs
        assert "7 mitigations ON" in out.summary

    def test_some_mitigations_off(self) -> None:
        raw = {"nx": True, "aslr": False, "pie": False, "canary": True,
               "cet": False, "cfi": False}
        out = adapt_checksec(raw, _ctx(tool="checksec"))
        obs = out.observables_delta["ida_headless.checksec"]
        assert "ASLR: OFF" in obs
        assert "PIE: OFF" in obs


class TestAdaptClassifyBehavior:
    def test_basic(self) -> None:
        raw = {
            "categories": {
                "process_injection": ["WriteProcessMemory", "CreateRemoteThread"],
                "persistence": ["RegSetValueEx"],
            },
        }
        ctx = _ctx(tool="classify_behavior", binary_id="abc")
        out = adapt_classify_behavior(raw, ctx)
        assert out.payload_kind == PayloadKind.TEXT
        obs = out.observables_delta["ida_headless.classify_behavior"]
        assert "process_injection: 2 API(s)" in obs
        assert "persistence: 1 API(s)" in obs


class TestAdaptCapaScan:
    def test_basic(self) -> None:
        raw = {
            "matches": [
                {"rule": "encrypt data using RC4", "attck": ["T1027"]},
                {"rule": "communicate over HTTP"},
            ],
        }
        ctx = _ctx(tool="capa_scan", binary_id="abc")
        out = adapt_capa_scan(raw, ctx)
        assert out.payload_kind == PayloadKind.TEXT
        obs = out.observables_delta["ida_headless.capa_scan"]
        assert "encrypt data using RC4" in obs
        assert "T1027" in obs


class TestAdaptAttackSurface:
    def test_basic(self) -> None:
        raw = {
            "surfaces": [
                {"name": "http_handle_request", "kind": "http_route",
                 "file": "main.c", "line": 100},
                {"name": "rpc_dispatch", "kind": "rpc_handler"},
            ],
        }
        ctx = _ctx(server="audit_mcp", tool="attack_surface", index_id="x")
        out = adapt_attack_surface(raw, ctx)
        assert out.payload_kind == PayloadKind.TEXT
        obs = out.observables_delta["audit_mcp.attack_surface"]
        assert "http_handle_request" in obs
        assert "main.c:100" in obs
        assert "[rpc_handler]" in obs


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
        obs = out.observables_delta["audit_mcp.complexity_hotspots"]
        assert "ngx_http_parse_request_line" in obs
        assert "cyc=42" in obs
        assert "cog=65" in obs


# ----------------------------------------------------------------------
# Tool-executor command parser (unchanged)
# ----------------------------------------------------------------------


class TestCommandParser:
    def test_valid_command(self) -> None:
        raw = json.dumps({"tool": "ida_headless.decompile",
                          "args": {"binary_id": "abc", "address_or_name": "main"}})
        parsed = _parse_command(raw)
        assert parsed is not None
        tool_id, args = parsed
        assert tool_id == "ida_headless.decompile"
        assert args == {"binary_id": "abc", "address_or_name": "main"}

    def test_empty_string(self) -> None:
        assert _parse_command("") is None
        assert _parse_command("   ") is None

    def test_invalid_json(self) -> None:
        assert _parse_command("not json") is None
        assert _parse_command("{incomplete") is None

    def test_non_dict_top_level(self) -> None:
        assert _parse_command("[]") is None
        assert _parse_command('"just a string"') is None
        assert _parse_command("42") is None

    def test_missing_tool_field(self) -> None:
        assert _parse_command(json.dumps({"args": {}})) is None

    def test_missing_args_defaults_empty(self) -> None:
        raw = json.dumps({"tool": "ida_headless.decompile"})
        parsed = _parse_command(raw)
        assert parsed is not None
        assert parsed[1] == {}

    def test_wrong_args_type(self) -> None:
        raw = json.dumps({"tool": "x.y", "args": "not a dict"})
        assert _parse_command(raw) is None
