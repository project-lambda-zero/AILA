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
        # `base_url` if explicitly supplied wins forever (tests, DI).
        # Otherwise resolve per-call via env → ConfigRegistry → default
        # so operator PATCH /vr/mcp/servers/audit_mcp takes effect without
        # restart.
        self._fixed_base_url = base_url.rstrip("/") if base_url else None
        self._timeout = timeout or float(
            os.environ.get("AUDIT_MCP_TIMEOUT", "120"),
        )

    async def _resolve_base_url(self) -> str:
        if self._fixed_base_url is not None:
            return self._fixed_base_url
        env_value = os.environ.get("AUDIT_MCP_URL")
        if env_value:
            return env_value.rstrip("/")
        try:
            from aila.storage.registry import ConfigRegistry  # noqa: PLC0415  (lazy: avoid hot-path on cold init)

            cfg_value = await ConfigRegistry().get("vr", "audit_mcp_url")
            if isinstance(cfg_value, str) and cfg_value.strip():
                return cfg_value.rstrip("/")
        except (ValueError, RuntimeError, ImportError):
            pass
        return "http://127.0.0.1:18822"

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
        base = await self._resolve_base_url()
        url = f"{base}/tools/{action}"
        from aila.modules.vr.services.mcp_call_logger import record_call  # noqa: PLC0415

        async with record_call(server_id="audit_mcp", base_url=base, action=action) as ctx:
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(url, json=kwargs)
            except httpx.ConnectError as exc:
                ctx["status"] = "error"
                ctx["error_excerpt"] = str(exc)[:400]
                return {
                    "status": "error",
                    "error": (
                        f"Cannot reach audit-mcp at {base}. "
                        "Ensure the HTTP server is running "
                        "(audit-mcp --mode http or python -m audit_mcp --mode http)."
                    ),
                }
            except httpx.TimeoutException as exc:
                ctx["status"] = "error"
                ctx["error_excerpt"] = str(exc)[:400]
                return {
                    "status": "error",
                    "error": f"Timeout ({self._timeout}s) calling {action}.",
                }
            ctx["http_status"] = resp.status_code
            try:
                payload = resp.json()
            except ValueError as exc:
                ctx["status"] = "error"
                ctx["error_excerpt"] = str(exc)[:400]
                return {
                    "status": "error",
                    "error": f"Non-JSON response from {action}: {resp.text[:200]}",
                }
            payload_status = payload.get("status") if isinstance(payload, dict) else None
            if payload_status in ("ready", "pending", "error"):
                ctx["status"] = payload_status
            elif resp.status_code < 400:
                ctx["status"] = "ready"
            else:
                ctx["status"] = "error"
            if ctx["status"] == "error" and isinstance(payload, dict):
                err = payload.get("error")
                if isinstance(err, str):
                    ctx["error_excerpt"] = err[:400]
            return payload

    async def _list_tools(self) -> dict:
        """Return available audit-mcp tool names when called with no action."""
        base = await self._resolve_base_url()
        url = f"{base}/tools"
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
                "error": f"Cannot list tools from {url}",
            }

    async def health(self) -> dict:
        """Quick reachability check for machine readiness verification."""
        base = await self._resolve_base_url()
        url = f"{base}/health"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url)
            return resp.json()
        except (httpx.ConnectError, httpx.TimeoutException, ValueError):
            return {"status": "error", "error": f"Unreachable: {url}"}
