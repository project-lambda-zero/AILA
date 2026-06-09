"""android-mcp bridge — AILA Tool wrapping the android-mcp HTTP API.

Sibling of :class:`AuditMcpBridgeTool` (for source-graph audits) and
:class:`IDABridgeTool` (for binary disassembly). The android-mcp server
exposes Android-specific tools (apktool, jadx, androguard, MobSF, drozer,
QARK, AndroBugs, LIEF, YARA-over-decompiled, apksigner, objection, frida,
adb, plus composite handlers) at the URL configured by the
``ANDROID_MCP_URL`` env var or ``vr.android_mcp_url`` config key. Default
``http://127.0.0.1:18823`` (android-mcp's documented HTTP bind).

Scope: this bridge is the ONLY place where AILA's VR module touches the
android-mcp HTTP surface. The ``TargetAnalysisService`` android branch
(PRD §C-20 + F-3) uses it to drive the APK_DECODE / JADX_DECOMPILE /
STATIC_SUMMARY / MOBSF_SCAN stages against an uploaded APK. (The fifth
stage, INDEX_DECOMPILED, is driven through the audit-mcp bridge, not
this one, since it calls audit-mcp's ``index_codebase`` on the jadx
output rather than an android-mcp tool.)

Timeout: ``ANDROID_MCP_TIMEOUT`` env var, default 1800 s (30 min — covers
MobSF static scan upper bound; per-stage StageTracker timeouts in
``services/stage_tracker.py`` apply a tighter bound where each individual
tool runs faster). The bridge timeout is the absolute network ceiling;
the stage tracker timeout is the per-stage budget.

Deliberately slim compared to ``AuditMcpBridgeTool`` — no pre-warm
fan-out (android-mcp runs single-worker by default), no kwarg alias
map, no JSON-schema kwarg validation, no virtual tools. The C-20
ingestion code uses a fixed, small set of actions with known
parameters and surfaces upstream errors verbatim.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from aila.platform.tools._common import Tool
from aila.storage.registry import ConfigRegistry

__all__ = ["AndroidMcpBridgeTool"]

_log = logging.getLogger(__name__)


def _compact_spec(raw: dict[str, Any]) -> dict[str, Any]:
    """Project an MCP tool catalog entry into the shape the prompt
    builder + agent expect. Mirrors ``audit_mcp_bridge._compact_spec``
    and ``ida_bridge._compact_spec`` — duplicated rather than imported
    to keep ``tools/`` free of cross-bridge coupling (each bridge
    stays independently swappable).
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


# Pipeline-only tools — the 5-stage target ingestion (APK_DECODE,
# JADX_DECOMPILE, INDEX_DECOMPILED, STATIC_SUMMARY, MOBSF_SCAN) runs
# these ONCE at target create time via TargetAnalysisService. By the
# time an investigation turn fires, the results live in
# vr_targets._mcp_handles_json + the audit_mcp index id, queryable via
# cheap read tools. Letting the agent re-invoke them is:
#   - wasteful (re-decoding the same APK every time)
#   - error-prone (apktool refuses to overwrite without -f; mobsf has
#     to re-upload + re-scan; jadx burns minutes per call)
#   - off-policy (mobsf output must never reach prompts per operator)
#
# Hidden from the agent-visible catalog. TargetAnalysisService still
# calls them directly via bridge.forward(action=...) — the denylist is
# only applied in list_tool_specs() (what the prompt builder pulls).
_PIPELINE_ONLY_TOOLS: frozenset[str] = frozenset((
    "apktool_decode",
    "jadx_decompile",
    "mobsf_scan",
))


class AndroidMcpBridgeTool(Tool):
    """HTTP bridge for android-mcp.

    Usage::

        bridge = AndroidMcpBridgeTool()
        resp = await bridge.forward(
            action="apktool_decode",
            apk_path="/path/to/app.apk",
        )
        # resp == {"output_dir": "...", "apk_sha256": "...", ...}

    The ``action`` argument is the android-mcp tool name. Remaining
    keyword arguments forward as JSON body fields. Returns the parsed
    JSON response on success; returns a ``{"status": "error", "error":
    "..."}`` dict on connection / timeout / non-JSON / non-2xx response
    so callers (notably ``TargetAnalysisService._analyze_android_apk``)
    can branch on a uniform shape without per-error-type try/except.

    Successful android-mcp responses do not always carry an explicit
    ``status`` field — most tool handlers return their result dict
    directly (e.g. ``{"output_dir": "...", "apk_sha256": "..."}``).
    The bridge surfaces these payloads as-is and only injects a
    synthetic ``status="error"`` when the HTTP layer itself fails.
    """

    name = "vr.android_mcp_bridge"
    description = (
        "android-mcp Android APK audit bridge. Supports apktool_decode, "
        "jadx_decompile, androguard_summary, mobsf_scan, drozer_scan_apk, "
        "qark_scan, androbugs_scan, lief_so analyze, yara_scan_dir, "
        "apksigner verify, objection patchapk / explore, frida helpers, "
        "adb facade, plus composite verify_capabilities / "
        "classify_behavior / compute_risk_score / find_secrets. "
        "Input: action (tool name) + tool-specific parameters. "
        "Output: tool result dict, or {status:'error', error:...} on "
        "transport failure."
    )
    inputs = {
        "action": {"type": "string", "description": "android-mcp tool name to invoke"},
    }
    output_type = "object"
    skip_forward_signature_validation = True

    # Default network timeout (seconds). MobSF static scans dominate
    # the upper end at ~30 min — anything longer is the stage-tracker's
    # job to reap. Per-stage StageTracker timeouts (apktool 600 s, jadx
    # 900 s, static-summary 300 s, mobsf 1800 s) are tighter; this is
    # only the absolute network ceiling for one HTTP call.
    _DEFAULT_TIMEOUT_S: float = 1800.0

    # Cached tool catalog. None until first ``list_tool_specs()`` call;
    # then a list of ``_compact_spec`` dicts. Class-level so multiple
    # bridge instances (tests, DI) share the same warm cache the way
    # ``AuditMcpBridgeTool`` and ``IDABridgeTool`` do.
    _SPEC_CACHE: list[dict[str, Any]] | None = None

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float | None = None,
    ) -> None:
        # ``base_url`` if explicitly supplied wins forever (tests, DI).
        # Otherwise resolve per-call via env → ConfigRegistry → default
        # so PATCH /vr/mcp/servers/android_mcp takes effect without a
        # restart — same pattern AuditMcpBridgeTool uses.
        self._fixed_base_url = base_url.rstrip("/") if base_url else None
        self._timeout = timeout or float(
            os.environ.get("ANDROID_MCP_TIMEOUT", str(self._DEFAULT_TIMEOUT_S)),
        )

    async def _resolve_base_url(self) -> str:
        """Resolve android-mcp base URL with env > config > default order."""
        if self._fixed_base_url is not None:
            return self._fixed_base_url
        env_value = os.environ.get("ANDROID_MCP_URL")
        if env_value:
            return env_value.rstrip("/")
        try:
            cfg_value = await ConfigRegistry().get("vr", "android_mcp_url")
            if isinstance(cfg_value, str) and cfg_value.strip():
                return cfg_value.rstrip("/")
        except (ValueError, RuntimeError, ImportError):
            pass
        return "http://127.0.0.1:18823"

    async def forward(self, action: str | None = None, **kwargs: Any) -> dict:
        """Dispatch to the android-mcp HTTP API.

        Args:
            action: android-mcp tool name (e.g. ``apktool_decode``,
                ``jadx_decompile``, ``androguard_summary``,
                ``mobsf_scan``).
            **kwargs: Parameters forwarded as JSON body fields.

        Returns:
            Parsed JSON response from android-mcp on success.
            ``{"status": "error", "error": "..."}`` on connection,
            timeout, non-JSON, or non-2xx HTTP responses.
        """
        if not action:
            return await self._list_tools()

        base = await self._resolve_base_url()
        url = f"{base}/tools/{action}"

        # Lazy import — top-level would create a circular dep through
        # ``aila.modules.vr.services.__init__`` (which re-exports
        # ``TargetAnalysisService`` that imports this bridge).
        from aila.modules.vr.services.mcp_call_logger import record_call  # noqa: PLC0415

        async with record_call(
            server_id="android_mcp", base_url=base, action=action,
        ) as ctx:
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(url, json=kwargs)
            except httpx.ConnectError as exc:
                ctx["status"] = "error"
                ctx["error_excerpt"] = str(exc)[:400]
                return {
                    "status": "error",
                    "error": (
                        f"Cannot reach android-mcp at {base}. "
                        "Ensure the HTTP server is running (python -m "
                        "android_mcp --mode http --port 18823)."
                    ),
                }
            except httpx.TimeoutException as exc:
                ctx["status"] = "error"
                ctx["error_excerpt"] = str(exc)[:400]
                return {
                    "status": "error",
                    "error": (
                        f"Timeout ({self._timeout:.0f}s) calling "
                        f"android-mcp action {action!r}."
                    ),
                }

            ctx["http_status"] = resp.status_code
            try:
                payload = resp.json()
            except ValueError as exc:
                ctx["status"] = "error"
                ctx["error_excerpt"] = str(exc)[:400]
                return {
                    "status": "error",
                    "error": (
                        f"Non-JSON response from android-mcp action "
                        f"{action!r}: {resp.text[:200]}"
                    ),
                }

            # Surface upstream error envelopes verbatim. android-mcp
            # raises Python exceptions on tool failure; FastMCP's HTTP
            # layer wraps them as 500 with a JSON body like
            # ``{"detail": "FileNotFoundError: ..."}``. Map to the
            # uniform ``{status, error}`` shape so callers don't need
            # to know which transport variant they hit.
            if resp.status_code >= 400:
                ctx["status"] = "error"
                err_msg: str
                if isinstance(payload, dict):
                    err_msg = (
                        payload.get("error")
                        or payload.get("detail")
                        or str(payload)
                    )
                else:
                    err_msg = str(payload)
                ctx["error_excerpt"] = str(err_msg)[:400]
                return {
                    "status": "error",
                    "error": (
                        f"android-mcp action {action!r} returned "
                        f"HTTP {resp.status_code}: {err_msg}"
                    ),
                }

            if isinstance(payload, dict) and payload.get("status") == "error":
                # Tool handler returned a structured error envelope
                # itself (e.g. mobsf_scan when MOBSF_API_KEY missing
                # before B-14's RuntimeError unification). Honor it.
                ctx["status"] = "error"
                err = payload.get("error")
                if isinstance(err, str):
                    ctx["error_excerpt"] = err[:400]
                return payload

            ctx["status"] = "ready"
            return payload if isinstance(payload, dict) else {
                "status": "ready", "result": payload,
            }

    async def _list_tools(self) -> dict:
        """Return android-mcp's tool catalog with parsed schemas."""
        specs = await self.list_tool_specs()
        return {
            "status": "ready",
            "tools": [s["name"] for s in specs],
            "count": len(specs),
            "specs": specs,
        }

    async def list_tool_specs(self) -> list[dict[str, Any]]:
        """Fetch android-mcp's tool catalog with parsed schemas.

        Cached per process at the class level so concurrent investigations
        share one HTTP round-trip. On fetch failure we return an empty
        list and cache it — the agent then sees a name-only listing
        (from ``KNOWN_TOOLS``) without schemas instead of repeated
        connect-error stalls per turn.
        """
        if self.__class__._SPEC_CACHE is not None:
            return self.__class__._SPEC_CACHE
        base = await self._resolve_base_url()
        url = f"{base}/tools"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
            raw = resp.json()
        except (httpx.ConnectError, httpx.TimeoutException, ValueError) as exc:
            _log.warning(
                "android_mcp_bridge: catalog fetch failed (%s) — agent "
                "will see name-only listing without schemas", exc,
            )
            self.__class__._SPEC_CACHE = []
            return []
        if not isinstance(raw, list):
            _log.warning(
                "android_mcp_bridge: /tools returned non-list payload "
                "(%s) — treating as empty catalog", type(raw).__name__,
            )
            self.__class__._SPEC_CACHE = []
            return []
        # Drop pipeline-only tools BEFORE caching so every consumer of
        # the cache (prompt builder, agent dispatcher, status UI) sees
        # the agent-safe subset. The pipeline still calls these via
        # bridge.forward directly, which bypasses the catalog.
        self.__class__._SPEC_CACHE = [
            _compact_spec(t) for t in raw
            if isinstance(t, dict)
            and t.get("name") not in _PIPELINE_ONLY_TOOLS
        ]
        _log.info(
            "android_mcp_bridge: catalog loaded — %d tools (%d hidden as pipeline-only)",
            len(self.__class__._SPEC_CACHE),
            sum(1 for t in raw if isinstance(t, dict) and t.get("name") in _PIPELINE_ONLY_TOOLS),
        )
        return self.__class__._SPEC_CACHE

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
