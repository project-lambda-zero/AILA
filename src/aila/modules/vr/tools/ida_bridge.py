"""IDA Headless MCP bridge — AILA Tool wrapping the HTTP API.

Translates AILA tool ``forward()`` calls into HTTP POST requests against
the IDA Headless MCP HTTP API.  The bridge is stateless: all binary state
lives in the MCP server's cache/lifecycle layer.

Configuration:
    ``IDA_HEADLESS_URL`` env var or ``vr.ida_headless_url`` config key.
    Default: ``http://127.0.0.1:18821``.

Timeout:
    ``IDA_HEADLESS_TIMEOUT`` env var or ``vr.ida_headless_timeout``.
    Default: 120 seconds (covers heavy decompilation).
"""
from __future__ import annotations

import os
from typing import Any

import httpx

from aila.platform.tools._common import Tool

__all__ = ["IDABridgeTool"]


class IDABridgeTool(Tool):
    """Multi-action tool proxying 81 MCP tools over HTTP.

    Every MCP tool name (``open_binary``, ``decompile``, ``checksec``, etc.)
    is a valid ``action``. Parameters are forwarded as JSON body fields.

    Usage::

        tool.forward(action="decompile",
                     binary_id="b_32070edcb21b",
                     address_or_name="main")
    """

    name = "vr.ida_bridge"
    description = (
        "IDA Pro headless binary analysis bridge. Supports 81+ tools: "
        "upload (upload binary for analysis), open_binary, decompile, "
        "list_functions, checksec, diff_binary, diff_function, xrefs_to, "
        "xrefs_from, call_graph, call_chain, batch_decompile, search_pattern, "
        "capa_scan, assess_exploitability, detect_obfuscation, "
        "detect_crypto_primitives, and more. "
        "Input: action (tool name) + tool-specific parameters. "
        "Output: tool result dict with status 'ready', 'pending', or 'error'."
    )
    inputs = {
        "action": {"type": "string", "description": "MCP tool name to invoke"},
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
            or os.environ.get("IDA_HEADLESS_URL", "http://127.0.0.1:18821")
        ).rstrip("/")
        self._timeout = timeout or float(
            os.environ.get("IDA_HEADLESS_TIMEOUT", "120")
        )

    def forward(self, action: str | None = None, **kwargs: Any) -> dict:
        """Dispatch to the MCP HTTP API.

        Args:
            action: MCP tool name (e.g., ``decompile``, ``open_binary``).
            **kwargs: Parameters forwarded to the tool as JSON body fields.

        Returns:
            Tool result dict. The ``status`` field is one of:
            ``ready`` (result available), ``pending`` (queued for processing),
            or ``error`` (failure with ``error`` message).
        """
        if not action:
            return self._list_tools()
        if action == "upload":
            return self._upload_binary(**kwargs)
        url = f"{self._base_url}/tools/{action}"
        try:
            resp = httpx.post(url, json=kwargs, timeout=self._timeout)
        except httpx.ConnectError:
            return {
                "status": "error",
                "error": (
                    f"Cannot reach IDA Headless MCP at {self._base_url}. "
                    "Ensure the HTTP server is running "
                    "(ida-headless-http or python -m ida_headless_mcp.http_api)."
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

    def _list_tools(self) -> dict:
        """Return available MCP tool names when called with no action."""
        url = f"{self._base_url}/tools"
        try:
            resp = httpx.get(url, timeout=10.0)
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

    def _upload_binary(self, file_path: str | None = None, **_extra: Any) -> dict:
        """Upload a local binary to the MCP server for analysis.

        The MCP server saves the file, hashes it, copies to workspace,
        and spawns IDA background analysis. Poll with
        ``action='poll_analysis'`` until state is READY/INDEXED.

        Args:
            file_path: Local filesystem path to the binary.

        Returns:
            open_binary result with binary_id, sha256, state.
        """
        if not file_path:
            return {"status": "error", "error": "file_path is required for upload"}
        from pathlib import Path
        target = Path(file_path)
        if not target.is_file():
            return {"status": "error", "error": f"File not found: {file_path}"}
        url = f"{self._base_url}/upload"
        try:
            with target.open("rb") as fh:
                resp = httpx.post(
                    url,
                    files={"file": (target.name, fh, "application/octet-stream")},
                    timeout=self._timeout,
                )
            return resp.json()
        except httpx.ConnectError:
            return {"status": "error", "error": f"Cannot reach {self._base_url}"}
        except httpx.TimeoutException:
            return {"status": "error", "error": f"Upload timeout ({self._timeout}s)"}
        except (ValueError, OSError) as exc:
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}

    def health(self) -> dict:
        """Quick reachability check for machine readiness verification."""
        url = f"{self._base_url}/health"
        try:
            resp = httpx.get(url, timeout=5.0)
            return resp.json()
        except (httpx.ConnectError, httpx.TimeoutException, ValueError):
            return {"status": "error", "error": f"Unreachable: {url}"}
