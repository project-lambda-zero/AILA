"""Shared tool-execution primitives (RFC-03 Phase 4a).

Pure functions -- no DB. Pins the tool-command parser contract, the
contract-error classifier taxonomy, and the result dataclass shape so
both module executors bind the same behavior.
"""
from __future__ import annotations

import json

from aila.platform.agents.tool_execution import (
    ToolExecutionResult,
    classify_contract_error,
    parse_command,
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
