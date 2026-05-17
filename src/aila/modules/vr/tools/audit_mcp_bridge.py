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

import logging
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

    # ── LLM kwarg synonym map ─────────────────────────────────────────
    #
    # The reasoning agent doesn't see audit-mcp tool signatures; it
    # picks parameter names by feel. Most failures we observed are the
    # same handful of synonyms — translate them to the canonical names
    # the audit-mcp server accepts. Each entry is
    # {synonym: canonical}. We apply BEFORE forwarding so the server
    # never sees the alias.
    #
    # If the canonical name is already present we keep that value and
    # discard the synonym (operator-supplied overrides win).
    _KW_SYNONYMS: dict[str, str] = {
        "top_n": "limit",
        "top_k": "limit",
        "n": "limit",
        "count": "limit",
        "max_results": "limit",
        "complexity_threshold": "threshold",
        "min_complexity": "threshold",
        "function_name": "name",
        "function": "name",
        "fn_name": "name",
        "symbol_name": "symbol",
        "fn": "symbol",
    }

    @classmethod
    def _normalize_kwargs(
        cls, action: str, kwargs: dict[str, Any],
    ) -> tuple[dict[str, Any], list[str]]:
        """Rewrite known-synonym kwargs to their canonical names.

        Returns ``(normalized, notes)`` — ``notes`` is a list of human
        readable strings (one per rename) that the caller can log so
        the operator can see when the LLM is mis-naming params.
        """
        if not kwargs:
            return {}, []
        out: dict[str, Any] = {}
        notes: list[str] = []
        for key, value in kwargs.items():
            canonical = cls._KW_SYNONYMS.get(key)
            if canonical is None:
                out[key] = value
                continue
            if canonical in kwargs:
                # Operator already gave the canonical name; drop the alias.
                notes.append(
                    f"{action}: dropping kwarg '{key}' (alias for "
                    f"'{canonical}' which is already set)",
                )
                continue
            if canonical in out:
                # Two synonyms collided on the same canonical key — keep
                # the first, log the second.
                notes.append(
                    f"{action}: dropping kwarg '{key}' (alias for "
                    f"'{canonical}', already set by an earlier synonym)",
                )
                continue
            out[canonical] = value
            notes.append(
                f"{action}: rewrote kwarg '{key}' -> '{canonical}'",
            )
        return out, notes

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
        normalized_kwargs, kw_notes = self._normalize_kwargs(action, kwargs)
        for note in kw_notes:
            logging.getLogger(__name__).info("audit_mcp_bridge %s", note)
        base = await self._resolve_base_url()
        url = f"{base}/tools/{action}"
        from aila.modules.vr.services.mcp_call_logger import record_call  # noqa: PLC0415

        async with record_call(server_id="audit_mcp", base_url=base, action=action) as ctx:
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(url, json=normalized_kwargs)
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
