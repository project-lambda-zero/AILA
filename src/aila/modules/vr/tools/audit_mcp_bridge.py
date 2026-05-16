"""audit-mcp bridge — AILA Tool wrapping the audit-mcp HTTP API.

Mirrors ``IDABridgeTool``. The audit-mcp server (source code audit MCP,
51 tools, GPU-accelerated graph engine) runs at the URL configured by
``AUDIT_MCP_URL`` env var or ``vr.audit_mcp_url`` config key. Default
``http://127.0.0.1:18822`` (audit-mcp's default HTTP bind).

This bridge is the only place where the VR module touches the
audit-mcp HTTP surface. Use it for source-code targets the same way
``IDABridgeTool`` is used for binary targets.

Timeout: ``AUDIT_MCP_TIMEOUT`` env var, default 120 s (covers indexing
plus heavy graph queries like ``dead_code`` and ``scan_and_correlate``
which the server runs async — the bridge returns a task_id and the
caller polls with ``action='poll_task'``).
"""
from __future__ import annotations

import os
from typing import Any

import httpx

from aila.platform.tools._common import Tool

__all__ = ["AuditMcpBridgeTool"]


class AuditMcpBridgeTool(Tool):
    """Multi-action tool proxying audit-mcp's 51 MCP tools over HTTP.

    Every MCP tool name (``index_codebase``, ``attack_surface``,
    ``fuzzing_targets``, ``scan_and_correlate``, etc.) is a valid
    ``action``. Parameters forward as JSON body fields.

    Usage::

        tool.forward(action="index_codebase", path="/path/to/project")
        tool.forward(action="fuzzing_targets", index_id="a1b2c3")
        tool.forward(action="scan_and_correlate",
                     index_id="a1b2c3", scanner="semgrep")
    """

    name = "vr.audit_mcp_bridge"
    description = (
        "audit-mcp source code audit bridge. Supports 51+ tools: "
        "index_codebase, poll_index, attack_surface, preanalysis, "
        "fuzzing_targets, complexity_hotspots, taint_paths_to, "
        "entrypoint_paths_to, dead_code, scan_and_correlate, "
        "detect_languages, search_constants, search_macros, "
        "cross_reference_bitfields, diff_codebases, attack_surface_diff. "
        "Input: action (tool name) + tool-specific parameters. "
        "Output: tool result dict with status 'ready' or 'pending' "
        "(async tools return task_id; poll with action='poll_task')."
    )
    inputs = {
        "action": {"type": "string", "description": "audit-mcp tool name to invoke"},
    }
    output_type = "object"
    skip_forward_signature_validation = True

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self._base_url = (
            base_url
            or os.environ.get("AUDIT_MCP_URL", "http://127.0.0.1:18822")
        ).rstrip("/")
        self._timeout = timeout or float(
            os.environ.get("AUDIT_MCP_TIMEOUT", "120")
        )

    async def forward(self, action: str | None = None, **kwargs: Any) -> dict:
        """Dispatch to the audit-mcp HTTP API.

        Args:
            action: audit-mcp tool name (e.g., ``index_codebase``,
                ``fuzzing_targets``, ``scan_and_correlate``).
            **kwargs: Parameters forwarded as JSON body fields.

        Returns:
            Tool result dict. The ``status`` field is one of:
            ``ready`` (result available), ``pending`` (async — poll
            with ``action='poll_task'`` and ``task_id``), or ``error``.
        """
        if not action:
            return await self._list_tools()
        url = f"{self._base_url}/tools/{action}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, json=kwargs)
        except httpx.ConnectError:
            return {
                "status": "error",
                "error": (
                    f"Cannot reach audit-mcp at {self._base_url}. "
                    "Ensure the HTTP server is running "
                    "(audit-mcp --mode http or python -m audit_mcp --mode http)."
                ),
            }
        except httpx.TimeoutException:
            return {
                "status": "error",
                "error": f"Timeout ({self._timeout}s) calling {action}.",
            }
        try:
            return resp.json()
        except ValueError:
            return {
                "status": "error",
                "error": f"Non-JSON response from {action}: {resp.text[:200]}",
            }

    async def _list_tools(self) -> dict:
        """Return available audit-mcp tool names when called with no action."""
        url = f"{self._base_url}/tools"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
            tools = resp.json()
            return {
                "status": "ready",
                "tools": [t["name"] for t in tools],
                "count": len(tools),
            }
        except (httpx.ConnectError, httpx.TimeoutException, ValueError):
            return {
                "status": "error",
                "error": f"Cannot list tools from {self._base_url}/tools",
            }

    async def health(self) -> dict:
        """Quick reachability check for machine readiness verification."""
        url = f"{self._base_url}/health"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url)
            return resp.json()
        except (httpx.ConnectError, httpx.TimeoutException, ValueError):
            return {"status": "error", "error": f"Unreachable: {url}"}
