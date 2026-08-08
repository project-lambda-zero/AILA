"""Shared tool-execution primitives (RFC-03 Phase 4a).

Pure functions -- no DB. Pins the tool-command parser contract, the
contract-error classifier taxonomy, and the result dataclass shape so
both module executors bind the same behavior.
"""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from aila.platform.agents.tool_execution import (
    ToolExecutionResult,
    classify_contract_error,
    parse_command,
)
from aila.platform.contracts.reasoning import (
    ReasoningTurnDecision,
    coerce_tool_command,
)


def test_parse_valid_command() -> None:
    assert parse_command(
        json.dumps({"tool": "ida_headless.decompile", "args": {"name": "main"}}),
    ) == ("ida_headless.decompile", {"name": "main"})


def test_parse_missing_args_coerced_to_empty() -> None:
    assert parse_command(json.dumps({"tool": "x.y"})) == ("x.y", {})


def test_parse_null_args_coerced_to_empty() -> None:
    # An agent that explicitly sets args=null must not force-stop.
    assert parse_command('{"tool": "x.y", "args": null}') == ("x.y", {})


def test_parse_rejects_invalid_json() -> None:
    assert parse_command("not json at all") is None


# ---------------------------------------------------------------------------
# Natural function-call coercion (regression for the reasoning-loop stall:
# the model emits ``server.tool(k=v, ...)`` / ``server.tool({json})`` instead
# of canonical {"tool","args"} JSON; that is a complete emission, not a
# truncation, so it must be coerced, not force-stopped).
# ---------------------------------------------------------------------------


def test_parse_coerces_function_call_form() -> None:
    # The exact emission that stalled a live investigation at turn 1.
    raw = (
        "audit_mcp.read_function(file_path=libavformat/mov.c, "
        "index_id=747c9b9f92e5, name=mov_read_senc)"
    )
    assert parse_command(raw) == (
        "audit_mcp.read_function",
        {
            "file_path": "libavformat/mov.c",
            "index_id": "747c9b9f92e5",
            "name": "mov_read_senc",
        },
    )


def test_parse_coerces_json_arg_call_form() -> None:
    raw = 'audit_mcp.read_function({"file_path": "libavformat/hls.c", "name": "parse_playlist"})'
    assert parse_command(raw) == (
        "audit_mcp.read_function",
        {"file_path": "libavformat/hls.c", "name": "parse_playlist"},
    )


def test_coerce_scalar_types_and_quotes() -> None:
    raw = 'audit_mcp.semantic_search(query="use after free", limit=8, approved_only=true)'
    out = json.loads(coerce_tool_command(raw))
    assert out == {
        "tool": "audit_mcp.semantic_search",
        "args": {"query": "use after free", "limit": 8, "approved_only": True},
    }


def test_coerce_bare_tool_name_to_empty_args() -> None:
    # The model sometimes emits just the dotted tool id with no parens/args.
    assert json.loads(coerce_tool_command("audit_mcp.read_function")) == {
        "tool": "audit_mcp.read_function", "args": {},
    }
    assert parse_command("audit_mcp.attack_surface") == ("audit_mcp.attack_surface", {})
    d = ReasoningTurnDecision(
        reasoning="r", action="tool_run", command="audit_mcp.semantic_search",
    )
    assert json.loads(d.command) == {"tool": "audit_mcp.semantic_search", "args": {}}
    # Garbage with no dotted-tool shape is still rejected (truncation path).
    assert coerce_tool_command("NULL") is None
    assert coerce_tool_command("{") is None


def test_coerce_rejects_prose_and_bare_query_string() -> None:
    # Prose is not a function call.
    assert coerce_tool_command("I will read the function next.") is None
    # A bare key=value string has no tool name -- not safely coercible.
    assert coerce_tool_command("index_id=abc&name=mov_read_senc") is None


def test_validator_coerces_natural_command_and_normalizes() -> None:
    raw = "audit_mcp.callers_of(name=mov_read_trak, index_id=747c9b9f92e5)"
    d = ReasoningTurnDecision(reasoning="r", action="tool_run", command=raw)
    # The stored command is normalized to canonical JSON downstream can parse.
    assert json.loads(d.command) == {
        "tool": "audit_mcp.callers_of",
        "args": {"name": "mov_read_trak", "index_id": "747c9b9f92e5"},
    }


def test_validator_valid_json_command_passthrough_unchanged() -> None:
    good = '{"tool": "audit_mcp.callers_of", "args": {"name": "x"}}'
    d = ReasoningTurnDecision(reasoning="r", action="tool_run", command=good)
    assert d.command == good  # byte-identical: valid JSON is never rewritten


def test_validator_genuine_truncation_still_rejected() -> None:
    # A truncated emission is NOT a recognizable function call, so the
    # truncation diagnostics must still fire.
    with pytest.raises(ValidationError):
        ReasoningTurnDecision(reasoning="r", action="tool_run", command="{")


def test_parse_rejects_blank() -> None:
    assert parse_command("") is None
    assert parse_command("   ") is None


def test_parse_rejects_non_dict() -> None:
    assert parse_command(json.dumps([1, 2, 3])) is None


def test_parse_rejects_non_string_tool() -> None:
    assert parse_command(json.dumps({"tool": 123, "args": {}})) is None


def test_parse_rejects_oversized() -> None:
    big = json.dumps({"tool": "x.y", "args": {"blob": "z" * 70000}})
    assert len(big) > 65536
    assert parse_command(big) is None


def test_classify_unknown_kwarg() -> None:
    assert classify_contract_error(
        "TypeError: got an unexpected keyword argument 'foo'",
    ) == "unknown_kwarg"
    assert classify_contract_error("unknown kwarg: bar") == "unknown_kwarg"


def test_classify_missing_kwarg() -> None:
    assert classify_contract_error(
        "missing 1 required positional argument: 'name'",
    ) == "missing_kwarg"
    assert classify_contract_error(
        "audit_mcp.read_lines rejected: missing required kwarg(s) ['file_path', 'index_id'].",
    ) == "missing_kwarg"
    assert classify_contract_error(
        "index_id and file_path are required",
    ) == "missing_kwarg"


def test_classify_bad_arg_value() -> None:
    assert classify_contract_error(
        "read_lines: invalid range start=0 end=5 (must be 1-indexed, end >= start)",
    ) == "bad_arg_value"
    assert classify_contract_error(
        "read_lines: start and end must be integers",
    ) == "bad_arg_value"
    assert classify_contract_error(
        "read_lines: start=9999 exceeds file length 1200",
    ) == "bad_arg_value"


def test_classify_type_mismatch() -> None:
    assert classify_contract_error("argument of type 'int' is not iterable") == (
        "type_mismatch"
    )


def test_classify_resource_not_found() -> None:
    assert classify_contract_error("FileNotFoundError: /x") == "resource_not_found"
    assert classify_contract_error("index not found: abc") == "resource_not_found"
    assert classify_contract_error(
        "the apk does not exist at that path",
    ) == "resource_not_found"


def test_classify_unmatched_returns_none() -> None:
    assert classify_contract_error("some entirely unrelated message") is None
    # "does not exist" without a resource keyword is NOT resource_not_found.
    assert classify_contract_error("that hypothesis does not exist") is None


def test_result_defaults() -> None:
    r = ToolExecutionResult(
        server_id="s", tool_name="t", message_id=None, success=False,
    )
    assert r.error == ""
    assert r.success is False
