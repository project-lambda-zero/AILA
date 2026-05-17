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

import logging
import os
from typing import Any

import httpx

from aila.platform.tools._common import Tool

__all__ = ["IDABridgeTool"]


def _compact_spec(raw: dict[str, Any]) -> dict[str, Any]:
    """Project an MCP tool catalog entry into the form the prompt
    builder + agent need. See ``audit_mcp_bridge._compact_spec`` for
    rationale — duplicated rather than imported to keep tools/
    package free of cross-bridge coupling.
    """
    name = str(raw.get("name") or "")
    description = str(raw.get("description") or "").strip()
    schema = raw.get("parameters") or raw.get("inputSchema") or {}
    properties = schema.get("properties") or {}
    required = list(schema.get("required") or [])
    params: list[dict[str, Any]] = []
    for pname in sorted(properties.keys()):
        pspec = properties[pname] or {}
        entry: dict[str, Any] = {
            "name": pname,
            "type": pspec.get("type") or "any",
            "required": pname in required,
        }
        if "default" in pspec:
            entry["default"] = pspec["default"]
        pdesc = pspec.get("description")
        if pdesc:
            entry["description"] = str(pdesc)[:240]
        params.append(entry)
    return {
        "name": name,
        "description": description[:400],
        "params": params,
        "required": required,
    }


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
        self._fixed_base_url = base_url.rstrip("/") if base_url else None
        self._timeout = timeout or float(
            os.environ.get("IDA_HEADLESS_TIMEOUT", "120"),
        )

    async def _resolve_base_url(self) -> str:
        if self._fixed_base_url is not None:
            return self._fixed_base_url
        env_value = os.environ.get("IDA_HEADLESS_URL")
        if env_value:
            return env_value.rstrip("/")
        try:
            from aila.storage.registry import ConfigRegistry  # noqa: PLC0415  (lazy: avoid hot-path on cold init)

            cfg_value = await ConfigRegistry().get("vr", "ida_headless_url")
            if isinstance(cfg_value, str) and cfg_value.strip():
                return cfg_value.rstrip("/")
        except (ValueError, RuntimeError, ImportError):
            pass
        return "http://127.0.0.1:18821"

    # ── LLM kwarg synonym map (mirrors AuditMcpBridgeTool) ────────────
    _KW_SYNONYMS: dict[str, str] = {
        "top_n": "limit",
        "top_k": "limit",
        "n": "limit",
        "count": "limit",
        "max_results": "limit",
        "function_name": "address_or_name",
        "function": "address_or_name",
        "fn": "address_or_name",
        "name": "address_or_name",
        "addr": "address",
        "ea": "address",
    }

    @classmethod
    def _normalize_kwargs(
        cls, action: str, kwargs: dict[str, Any],
    ) -> tuple[dict[str, Any], list[str]]:
        if not kwargs:
            return {}, []
        out: dict[str, Any] = {}
        notes: list[str] = []
        for key, value in kwargs.items():
            canonical = cls._KW_SYNONYMS.get(key)
            if canonical is None:
                out[key] = value
                continue
            if canonical in kwargs or canonical in out:
                notes.append(
                    f"{action}: dropping kwarg '{key}' (alias for "
                    f"'{canonical}' already set)",
                )
                continue
            out[canonical] = value
            notes.append(f"{action}: rewrote kwarg '{key}' -> '{canonical}'")
        return out, notes

    async def forward(self, action: str | None = None, **kwargs: Any) -> dict:
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
            return await self._list_tools()
        if action == "upload":
            return await self._upload_binary(**kwargs)
        normalized_kwargs, kw_notes = self._normalize_kwargs(action, kwargs)
        for note in kw_notes:
            logging.getLogger(__name__).info("ida_bridge %s", note)
        base = await self._resolve_base_url()
        url = f"{base}/tools/{action}"
        from aila.modules.vr.services.mcp_call_logger import record_call  # noqa: PLC0415

        async with record_call(server_id="ida_headless", base_url=base, action=action) as ctx:
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(url, json=normalized_kwargs)
            except httpx.ConnectError as exc:
                ctx["status"] = "error"
                ctx["error_excerpt"] = str(exc)[:400]
                return {
                    "status": "error",
                    "error": (
                        f"Cannot reach IDA Headless MCP at {base}. "
                        "Ensure the HTTP server is running "
                        "(ida-headless-http or python -m ida_headless_mcp.http_api)."
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

    # Schema-driven tool catalog cache — race-safe because each fetch
    # writes the same value (idempotent).
    _SPEC_CACHE: list[dict[str, Any]] | None = None

    async def _list_tools(self) -> dict:
        """Return available MCP tool names + schemas."""
        specs = await self.list_tool_specs()
        return {
            "status": "ready",
            "tools": [s["name"] for s in specs],
            "count": len(specs),
            "specs": specs,
        }

    async def list_tool_specs(self) -> list[dict[str, Any]]:
        """Fetch the IDA MCP catalog with parsed schemas. Cached per process."""
        if self.__class__._SPEC_CACHE is not None:
            return self.__class__._SPEC_CACHE
        base = await self._resolve_base_url()
        url = f"{base}/tools"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
            raw = resp.json()
        except (httpx.ConnectError, httpx.TimeoutException, ValueError) as exc:
            logging.getLogger(__name__).warning(
                "ida_headless catalog fetch failed (%s) — agent will see "
                "name-only listing without schemas", exc,
            )
            self.__class__._SPEC_CACHE = []
            return []
        self.__class__._SPEC_CACHE = [_compact_spec(t) for t in raw]
        return self.__class__._SPEC_CACHE

    async def _upload_binary(self, file_path: str | None = None, **_extra: Any) -> dict:
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
        base = await self._resolve_base_url()
        url = f"{base}/upload"
        try:
            with target.open("rb") as fh:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(
                        url,
                        files={"file": (target.name, fh, "application/octet-stream")},
                    )
            return resp.json()
        except httpx.ConnectError:
            return {"status": "error", "error": f"Cannot reach {base}"}
        except httpx.TimeoutException:
            return {"status": "error", "error": f"Upload timeout ({self._timeout}s)"}
        except (ValueError, OSError) as exc:
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}

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
