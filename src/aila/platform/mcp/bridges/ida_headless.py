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

import asyncio
import logging
import os
import uuid
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.exc import SQLAlchemyError

from aila.platform.tools._common import Tool
from aila.storage.registry import ConfigRegistry

from ._kwarg_alias import build_alias_map, normalize_kwargs
from ._recorder import BridgeRecorder, noop_recorder

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
        recorder: BridgeRecorder | None = None,
    ) -> None:
        self._fixed_base_url = base_url.rstrip("/") if base_url else None
        self._timeout = timeout or float(
            os.environ.get("IDA_HEADLESS_TIMEOUT", "120"),
        )
        # fix §211 — per-instance schema cache + alias map. Class-level
        # storage leaked across instances (tests saw stale state) and
        # was never invalidated when the upstream IDA MCP server
        # reloaded its tool catalog.
        self._spec_cache: list[dict[str, Any]] | None = None
        self._auto_alias_map: dict[str, dict[str, str]] = {}
        # Optional per-call audit logger. See ``_recorder.py``; module
        # authors wire their own ``record_call`` here, tests + ad-hoc
        # callers omit it and get a no-op.
        self._recorder: BridgeRecorder = recorder or noop_recorder

    async def _resolve_base_url(self) -> str:
        if self._fixed_base_url is not None:
            return self._fixed_base_url
        env_value = os.environ.get("IDA_HEADLESS_URL")
        if env_value:
            return env_value.rstrip("/")
        try:
            cfg_value = await ConfigRegistry().get("vr", "ida_headless_url")
            if isinstance(cfg_value, str) and cfg_value.strip():
                return cfg_value.rstrip("/")
        except (SQLAlchemyError, OSError, RuntimeError, ImportError, ValueError, TypeError) as exc:
            # fix §212 — broadened from (ValueError, RuntimeError,
            # ImportError). SQLAlchemy errors from ConfigRegistry().get
            # used to propagate and crash the bridge call. URL
            # resolution is a config lookup — fail-safe to the default.
            # fix §350 — traceback added; mirror of audit_mcp_bridge §315
            # so a ConfigRegistry break is debuggable from either bridge.
            logging.getLogger(__name__).info(
                "ida_bridge: ConfigRegistry lookup failed "
                "(%s: %s) — falling back to default URL",
                type(exc).__name__, exc,
                exc_info=True,
            )
        return "http://127.0.0.1:18821"

    # ── LLM kwarg synonym map (data-driven; see _kwarg_alias.py) ──────
    #
    # IDA's catalog uses different canonicals than audit_mcp:
    #   * 28 tools take ``address_or_name`` (decompile, xrefs_to, ...)
    #     where audit_mcp uses plain ``name``. So the IDA `name` family
    #     INCLUDES address_or_name as a member; the family algorithm
    #     picks address_or_name as the canonical for every tool that
    #     accepts it, and aliases name/function/fn/function_name → it.
    #   * 8 tools take plain ``address`` (patch_assemble, set_comment).
    #     A separate `address` family aliases addr/ea → address for
    #     those. Tools with specialized address params (from_address +
    #     to_address, sink_address, etc.) accept two family members at
    #     once, so the algorithm correctly leaves those alone.
    #   * 7 tools take ``limit`` — same `how_many` shape as audit_mcp.
    #   * `depth` and `max_depth` co-exist (call_chain takes depth,
    #     interprocedural_taint takes max_depth) — same `depth` family.
    _KW_FAMILIES: dict[str, set[str]] = {
        "how_many": {
            "limit", "top_k", "top_n", "n", "count", "max_results",
            "k", "max_count", "num", "max_n", "max_items",
        },
        "depth": {
            "depth", "max_depth", "max_hops", "traversal_depth",
        },
        "name": {
            "address_or_name", "name", "function_name", "class_name",
            "sink_name", "symbol_name", "fn_name", "fn", "function",
            "symbol", "target_name",
        },
        "address": {
            "address", "addr", "ea",
        },
    }

    # Manual overrides — empty by design; everything is data-driven.
    _MANUAL_OVERRIDES: dict[str, dict[str, str]] = {}

    def _normalize_kwargs(
        self, action: str, kwargs: dict[str, Any],
    ) -> tuple[dict[str, Any], list[str]]:
        """Delegate to the shared resolver against the live alias map."""
        return normalize_kwargs(action, kwargs, self._auto_alias_map)

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

        async with self._recorder(
            server_id="ida_headless", base_url=base, action=action,
        ) as ctx:
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
            # fix §214 — whitelist known statuses explicitly; unknown values
            # used to fall through to "ready" when HTTP was 2xx, silently
            # turning {"status": "queued"} into a success in the call log.
            payload_status = payload.get("status") if isinstance(payload, dict) else None
            if payload_status in ("ready", "completed", "ok"):
                ctx["status"] = "ready"
            elif payload_status in ("pending", "queued", "running"):
                ctx["status"] = "pending"
            elif payload_status == "error":
                ctx["status"] = "error"
            elif payload_status is None and resp.status_code < 400:
                ctx["status"] = "ready"
            else:
                logging.getLogger(__name__).warning(
                    "ida_bridge %s: unknown payload status %r (HTTP %d) — "
                    "coercing to error",
                    action, payload_status, resp.status_code,
                )
                ctx["status"] = "error"
            if ctx["status"] == "error" and isinstance(payload, dict):
                err = payload.get("error")
                if isinstance(err, str):
                    ctx["error_excerpt"] = err[:400]
            return payload

    # fix §211 — _SPEC_CACHE moved to instance attr in __init__.

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
        """Fetch the IDA MCP catalog with parsed schemas. Cached per instance."""
        if self._spec_cache is not None:
            return self._spec_cache
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
            self._spec_cache = []
            return []
        self._spec_cache = [_compact_spec(t) for t in raw]
        # Derive the per-action alias map from the live schema. Every
        # subsequent _normalize_kwargs call resolves through this map.
        self._auto_alias_map = build_alias_map(
            self._spec_cache,
            self._KW_FAMILIES,
            self._MANUAL_OVERRIDES,
        )
        logging.getLogger(__name__).info(
            "ida_bridge: catalog loaded — %d tools, %d with alias maps",
            len(self._spec_cache),
            len(self._auto_alias_map),
        )
        return self._spec_cache

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
        target = Path(file_path)
        # is_file() does a sync stat — wrap so we don't stall the loop
        # when the file lives on a slow volume.
        if not await asyncio.to_thread(target.is_file):
            return {"status": "error", "error": f"File not found: {file_path}"}
        base = await self._resolve_base_url()
        url = f"{base}/upload"

        # fix §213 — stream the file in 64KB chunks instead of slurping
        # the entire binary into memory. The previous read_bytes()
        # approach required N bytes of resident worker RAM for an
        # N-byte upload; a 4GB binary could OOM the worker and kill
        # every in-flight investigation. We now build the multipart
        # envelope by hand and yield chunks from disk, capping memory
        # at one chunk regardless of binary size.
        chunk_size = 65536
        try:
            file_size = (await asyncio.to_thread(target.stat)).st_size
        except OSError as exc:
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
        boundary = uuid.uuid4().hex
        # Sanitize filename for the Content-Disposition header — double
        # quotes inside filenames would break the multipart framing.
        safe_name = target.name.replace('"', "_").replace("\r", "_").replace("\n", "_")
        preamble = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; '
            f'filename="{safe_name}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        epilogue = f"\r\n--{boundary}--\r\n".encode()
        total_length = len(preamble) + file_size + len(epilogue)

        async def _stream_body():  # type: ignore[no-untyped-def]
            yield preamble
            fh = await asyncio.to_thread(open, target, "rb")
            try:
                while True:
                    chunk = await asyncio.to_thread(fh.read, chunk_size)
                    if not chunk:
                        break
                    yield chunk
            finally:
                await asyncio.to_thread(fh.close)
            yield epilogue

        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(total_length),
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, content=_stream_body(), headers=headers)
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
