"""M3.R-3 — MCP adapter unit tests + tool_executor parsing.

Adapters are pure functions. Tests stub the raw MCP response and
verify the (payload_kind, payload, observables_delta) output shape.
"""
from __future__ import annotations

import json

from aila.modules.vr.agents.mcp_adapters import (
    AdapterContext,
    get_adapter,
    registered_tools,
)
from aila.modules.vr.agents.mcp_adapters.audit_mcp import adapt_fuzzing_targets
from aila.modules.vr.agents.mcp_adapters.ida_headless import (
    adapt_decompile,
    adapt_find_api_call_sites,
)
from aila.modules.vr.agents.tool_executor import _parse_command
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


class TestRegistry:
    def test_three_tools_registered(self) -> None:
        tools = registered_tools()
        assert "ida_headless.decompile" in tools
        assert "ida_headless.find_api_call_sites" in tools
        assert "audit_mcp.fuzzing_targets" in tools

    def test_get_adapter_returns_callable(self) -> None:
        assert get_adapter("ida_headless", "decompile") is not None
        assert get_adapter("audit_mcp", "fuzzing_targets") is not None

    def test_unknown_returns_none(self) -> None:
        assert get_adapter("ida_headless", "bogus_tool") is None
        assert get_adapter("nonexistent_server", "decompile") is None


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
        assert "decompiled.main" in out.observables_delta
        assert "int main()" in out.observables_delta["decompiled.main"]
        assert "Decompiled main" in out.summary

    def test_truncates_long_pseudocode_in_observable(self) -> None:
        raw = {
            "status": "ready",
            "function_name": "huge",
            "pseudocode": "X" * 5000,
        }
        out = adapt_decompile(raw, _ctx())
        obs = out.observables_delta["decompiled.huge"]
        assert "truncated" in obs
        assert len(obs) < 5000

    def test_missing_fields_recover(self) -> None:
        raw = {"status": "ready"}
        out = adapt_decompile(raw, _ctx(address_or_name="main"))
        assert out.payload["function_name"] == "<unknown>"
        assert out.payload["address"] == "main"
        assert out.payload["pseudocode"] == ""


class TestAdaptFindApiCallSites:
    def test_basic(self) -> None:
        raw = {
            "status": "ready",
            "api_name": "strcpy",
            "call_sites": [
                {"function_name": "parse_input", "function_address": "0x401200"},
                {"function_name": "handle_request", "function_address": "0x401500"},
            ],
        }
        ctx = _ctx(tool="find_api_call_sites", binary_id="abc", api_name="strcpy")
        out = adapt_find_api_call_sites(raw, ctx)
        assert out.payload_kind == PayloadKind.XREF_VIEW
        assert out.payload["api_name"] == "strcpy"
        assert out.payload["total"] == 2
        obs = out.observables_delta["callsites.strcpy"]
        assert "parse_input @ 0x401200" in obs
        assert "handle_request @ 0x401500" in obs

    def test_truncates_large_lists(self) -> None:
        raw = {
            "status": "ready",
            "api_name": "memcpy",
            "call_sites": [
                {"function_name": f"f{i}", "function_address": f"0x{i:x}"}
                for i in range(100)
            ],
        }
        out = adapt_find_api_call_sites(raw, _ctx(api_name="memcpy"))
        assert out.payload["total"] == 100
        obs = out.observables_delta["callsites.memcpy"]
        assert "and 75 more" in obs

    def test_empty_list(self) -> None:
        raw = {"status": "ready", "api_name": "sscanf", "call_sites": []}
        out = adapt_find_api_call_sites(raw, _ctx(api_name="sscanf"))
        assert out.payload["total"] == 0
        assert "(none)" in out.observables_delta["callsites.sscanf"]


class TestAdaptFuzzingTargets:
    def test_basic(self) -> None:
        raw = {
            "status": "ready",
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
        assert "complexity=22" in obs
        assert "validate_token" in obs

    def test_empty(self) -> None:
        raw = {"status": "ready", "targets": []}
        out = adapt_fuzzing_targets(raw, _ctx(server="audit_mcp", tool="fuzzing_targets"))
        assert out.payload["total"] == 0
        assert "(none)" in out.observables_delta["audit_mcp.fuzzing_targets"]

    def test_alternative_result_field(self) -> None:
        # audit-mcp version variance — try the 'results' key too
        raw = {"status": "ready", "results": [{"name": "x", "score": 1.0}]}
        out = adapt_fuzzing_targets(raw, _ctx(server="audit_mcp", tool="fuzzing_targets"))
        assert out.payload["total"] == 1


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
