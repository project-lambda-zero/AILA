"""Shared tool-definition types for the ``re_analytics`` MCP server.

Three sibling modules -- :mod:`aila.platform.re_analytics.tools_capability`,
:mod:`aila.platform.re_analytics.tools_crypto`, and
:mod:`aila.platform.re_analytics.tools_dataflow` -- each export a
``TOOLS: list[ToolDef]`` constant. :mod:`aila.platform.re_analytics.server`
concatenates the three lists and serves them over stdio JSON-RPC MCP.

Handler contract
----------------
Each ``ToolDef.handler`` receives one positional argument -- the decoded
JSON object of the MCP ``tools/call`` ``arguments`` -- and returns a
JSON-serializable ``dict``. Handlers MAY be plain sync callables or
``async`` functions; the server normalises both.

Success results conventionally carry ``"status": "ok"`` plus the tool's
payload fields. Heuristic tools SHOULD include a ``"limitations"`` list
of human-readable precision caveats (repo rule: no hidden smartness --
state honestly what the analysis did not prove).

Tool-level failures (bad arguments, unreadable target, missing optional
dependency) MUST raise :class:`ToolError`; the server converts it into an
MCP ``isError`` result shaped
``{"status": "error", "error": "<message>"}``. Returning a fabricated
success shape for an analysis that did not run is forbidden.
"""
from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

__all__ = ["ToolDef", "ToolError", "invoke_handler"]


@dataclass(frozen=True)
class ToolDef:
    """One MCP tool: metadata plus the callable that executes it.

    ``input_schema`` is a JSON Schema object describing the tool's
    arguments (rendered verbatim as ``inputSchema`` in ``tools/list``).
    Every tool in this server takes ``target_path`` -- the absolute
    local filesystem path of the binary under analysis -- as its first
    argument (the AILA bridge forwards it as a real argument for this
    server, per the REA cutover contract).
    """

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], Awaitable[dict[str, Any]] | dict[str, Any]]

    def to_mcp_tool(self) -> dict[str, Any]:
        """Render as one entry of an MCP ``tools/list`` result."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class ToolError(RuntimeError):
    """Tool-level failure raised by handlers.

    The server catches this at the ``tools/call`` boundary and answers
    with ``isError: true`` plus ``{"status": "error", "error": str(exc)}``
    so the agent sees a normal MCP error rather than a transport fault.
    """


async def invoke_handler(
    tool: ToolDef, args: dict[str, Any],
) -> dict[str, Any]:
    """Run ``tool.handler`` accepting either sync or async callables."""
    result = tool.handler(args)
    if inspect.isawaitable(result):
        result = await result
    if not isinstance(result, dict):
        raise ToolError(
            f"handler for {tool.name!r} returned {type(result).__name__}, "
            "expected dict",
        )
    return result
