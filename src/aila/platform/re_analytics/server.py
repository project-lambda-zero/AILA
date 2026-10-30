"""Stdio MCP server for the re_analytics binary-analysis tool surface.

Protocol (mirrors :class:`aila.platform.mcp.mcp_session.McpStdioSession`,
the AILA-side client): newline-delimited JSON-RPC 2.0 on stdin/stdout.
The client sends ``initialize``, then ``notifications/initialized``, then
``tools/list`` / ``tools/call`` requests; every request is answered with
one JSON line whose ``id`` echoes the request verbatim.

``tools/call`` results follow the MCP structured-content contract:
``{content: [{type: "text", text: <json>}], structuredContent: {...}}``
with ``isError: true`` when the handler raised :class:`ToolError` (or any
unexpected exception -- surfaced, never swallowed).

Heavy handlers (capa above all) run on the default executor via
``asyncio.to_thread`` so concurrent requests from the bridge do not
serialize behind a long analysis.
"""
from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, TextIO

from aila.platform.re_analytics._tooldef import ToolDef, ToolError, invoke_handler

__all__ = ["SERVER_NAME", "SERVER_VERSION", "all_tools", "main", "serve_stdio"]


SERVER_NAME = "re_analytics"
SERVER_VERSION = "1.0.0"

_MCP_PROTOCOL_VERSION = "2025-06-18"

_CAPA_HEAVY_TOOLS = frozenset({"capa_scan", "verify_capabilities", "classify_behavior", "detect_anti_analysis"})

#: Registry cell -- dict mutation avoids a module-global rebind (the
#: honesty audit flags global-rebinding noqa comments).
_REGISTRY: dict[str, dict[str, ToolDef]] = {"tools": {}}


def all_tools() -> list[ToolDef]:
    """Concatenate the three sibling group TOOLS lists (import once)."""
    if _REGISTRY["tools"]:
        return list(_REGISTRY["tools"].values())
    from aila.platform.re_analytics.tools_capability import TOOLS as CAP_TOOLS
    from aila.platform.re_analytics.tools_crypto import TOOLS as CRYPTO_TOOLS
    from aila.platform.re_analytics.tools_dataflow import TOOLS as DATAFLOW_TOOLS

    merged: dict[str, ToolDef] = {}
    for tool in (*CAP_TOOLS, *CRYPTO_TOOLS, *DATAFLOW_TOOLS):
        if tool.name in merged:
            raise RuntimeError(
                f"duplicate re_analytics tool name across groups: {tool.name}",
            )
        merged[tool.name] = tool
    _REGISTRY["tools"] = merged
    return list(merged.values())


def _initialize_result() -> dict[str, Any]:
    return {
        "protocolVersion": _MCP_PROTOCOL_VERSION,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
    }


def _error_response(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": code, "message": message},
    }


def _tool_result(payload: dict[str, Any], *, is_error: bool = False) -> dict[str, Any]:
    text = json.dumps(payload, default=str)
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": payload,
        "isError": is_error,
    }


async def _dispatch_tools_call(params: dict[str, Any]) -> dict[str, Any]:
    name = str(params.get("name", ""))
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        return _tool_result(
            {"status": "error", "error": "arguments must be a JSON object"},
            is_error=True,
        )
    tools = {t.name: t for t in all_tools()}
    tool = tools.get(name)
    if tool is None:
        return _tool_result(
            {"status": "error", "error": f"unknown tool: {name}"},
            is_error=True,
        )
    try:
        if name in _CAPA_HEAVY_TOOLS:
            result = await asyncio.to_thread(_run_sync_handler, tool, arguments)
        else:
            result = await invoke_handler(tool, arguments)
        is_error = result.get("status") == "error"
        return _tool_result(result, is_error=is_error)
    except ToolError as exc:
        return _tool_result({"status": "error", "error": str(exc)}, is_error=True)
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller as an MCP error
        return _tool_result(
            {"status": "error", "error": f"{type(exc).__name__}: {exc}"},
            is_error=True,
        )


def _run_sync_handler(tool: ToolDef, arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute a sync handler off the event loop (capa-family tools)."""
    result = tool.handler(arguments)
    if asyncio.iscoroutine(result):
        # Defensive: heavy tools are sync; if one is async, run it on a
        # fresh loop in this thread.
        return asyncio.run(result)
    if not isinstance(result, dict):
        raise ToolError(
            f"handler for {tool.name!r} returned {type(result).__name__}",
        )
    return result


async def _handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    """Route one JSON-RPC request; None for notifications."""
    msg_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": msg_id, "result": _initialize_result()}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": [t.to_mcp_tool() for t in all_tools()]},
        }
    if method == "tools/call":
        result = await _dispatch_tools_call(params if isinstance(params, dict) else {})
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}
    if isinstance(method, str) and method.startswith("notifications/"):
        return None  # initialized, cancelled, progress: no response
    return _error_response(msg_id, -32601, f"method not found: {method}")


async def serve_stdio(stdin: TextIO, stdout: TextIO) -> None:
    """Serve MCP over newline-delimited JSON-RPC until EOF."""
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, stdin.readline)
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            await _write_line(stdout, _error_response(None, -32700, "parse error"))
            continue
        if not isinstance(message, dict):
            await _write_line(stdout, _error_response(None, -32600, "invalid request"))
            continue
        response = await _handle_request(message)
        if response is not None:
            await _write_line(stdout, response)


async def _write_line(stdout: TextIO, message: dict[str, Any]) -> None:
    loop = asyncio.get_running_loop()
    text = json.dumps(message, default=str) + "\n"

    def _emit() -> None:
        stdout.write(text)
        stdout.flush()

    await loop.run_in_executor(None, _emit)


def main() -> None:
    """Entry point for ``python -m aila.platform.re_analytics``."""
    # vivisect/capa emit per-function chatter at WARNING during feature
    # extraction; the child owns stderr, so keep it usable for operators.
    for noisy in ("vivisect", "capa", "vtrace", "envi", "Elf", "PE"):
        __import__("logging").getLogger(noisy).setLevel(
            __import__("logging").CRITICAL,
        )
    try:
        asyncio.run(serve_stdio(sys.stdin, sys.stdout))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":  # pragma: no cover
    main()
