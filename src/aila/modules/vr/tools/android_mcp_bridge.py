"""android-mcp bridge — AILA Tool wrapping the android-mcp HTTP API.

Sibling of :class:`AuditMcpBridgeTool` (for source-graph audits) and
:class:`IDABridgeTool` (for binary disassembly). The android-mcp server
exposes Android-specific tools (apktool, jadx, androguard, MobSF, drozer,
LIEF, YARA-over-decompiled, apksigner, objection, frida,
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

import asyncio
import logging
import os
from typing import Any

import httpx

from aila.platform.tools._common import Tool
from aila.storage.registry import ConfigRegistry

__all__ = ["AndroidMcpBridgeTool"]

_log = logging.getLogger(__name__)


# fix §216 — module-level shared AsyncClient with persistent connection
# pool. The previous shape constructed a fresh client per forward()
# call; a 70-call investigation built + tore down 70 pools, each
# paying TCP-handshake + TLS-not-applicable + DNS-cache miss costs
# on every call. The shared client keeps connections alive between
# calls and is safe to share across all bridge instances on the same
# event loop.
_SHARED_CLIENT: httpx.AsyncClient | None = None
_SHARED_CLIENT_LOCK = asyncio.Lock()
_SHARED_CLIENT_MAX_CONNECTIONS = 100
_SHARED_CLIENT_KEEPALIVE = 20


async def _get_shared_client() -> httpx.AsyncClient:
    """Return the module-level shared AsyncClient, initializing on first call.

    Per-request ``timeout=`` overrides the client default, so callers
    keep their existing timeout semantics intact.
    """
    global _SHARED_CLIENT  # noqa: PLW0603
    if _SHARED_CLIENT is not None:
        return _SHARED_CLIENT
    async with _SHARED_CLIENT_LOCK:
        if _SHARED_CLIENT is None:
            _SHARED_CLIENT = httpx.AsyncClient(
                limits=httpx.Limits(
                    max_connections=_SHARED_CLIENT_MAX_CONNECTIONS,
                    max_keepalive_connections=_SHARED_CLIENT_KEEPALIVE,
                ),
            )
    return _SHARED_CLIENT


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
    "react_native_extract",
    "mobsf_scan",
))

# Each tool here REQUIRES a host CLI on PATH. When the CLI is missing
# the tool call fails inside android-mcp with `RuntimeError: <cli> not
# on PATH`. Agents see a transient-looking error and retry — 94 wasted
# attempts in 48h on the live VF Yanimda audit, mostly verify_apk_signing
# (apksigner) and drozer_scan_apk (drozer). Bridge-side: probe each
# CLI at catalog-load time + DROP the tool from the catalog when its
# binary isn't resolvable. The agent never sees the tool name → never
# tries to call it.
#
# The check uses shutil.which on the operator's PATH (in-process; the
# bridge inherits the worker's environment). If the operator installs
# the CLI later they restart workers — same lifecycle as other
# catalog-cache invalidations.
_ENV_GATED_TOOLS: dict[str, str] = {
    "verify_apk_signing": "apksigner",
    "drozer_scan_apk": "drozer",
    "frida_attach_and_trace_calls": "frida",
    "frida_dump_process_modules": "frida",
    "frida_list_running_devices": "frida",
    "objection_patch_apk": "objection",
    "objection_explore": "objection",
}


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
        "lief_so analyze, yara_scan_dir, "
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

        # Block pipeline-only tools from agent-initiated calls. These
        # ran exactly once during ingestion (TargetAnalysisService);
        # results are persisted on vr_targets._mcp_handles_json +
        # audit_mcp index id. Letting the agent retry them wastes
        # minutes per call (mobsf re-uploads + re-scans, jadx
        # re-decompiles 14k classes), risks corrupting the canonical
        # output, and per operator policy mobsf output MUST NOT
        # reach prompts.
        #
        # Observed live on bb5decf2: yuki + 5 siblings looped 50+
        # turns each calling apktool_decode with invented `focus=`
        # kwarg, hitting TypeError every time, ignoring the
        # repeat-failure circuit breaker text. Bridge-level enforce-
        # ment surfaces a clean error and points them at the data
        # that already exists.
        #
        # TargetAnalysisService bypasses this guard via the
        # internal _agent_bypass=True kwarg (popped before forward).
        _agent_bypass = kwargs.pop("_agent_bypass", False)
        # fix: pipeline-only blocks USED to return status='error' which
        # the agent treats as a transient failure and retries. 338
        # wasted attempts in 48h on the live VF Yanimda audit. Now we
        # hand back status='ready' with a clear `_bridge_note` so the
        # agent reads "already done, look elsewhere" as a TERMINAL
        # outcome instead of a retry-able error. Empty payload fields
        # signal there is no fresh data; the note tells the agent
        # where the cached output lives.
        if action in _PIPELINE_ONLY_TOOLS and not _agent_bypass:
            return {
                "status": "ready",
                "matches": [],
                "results": [],
                "_bridge_note": (
                    f"{action!r} is pipeline-only — the APK ingestion stage "
                    f"ran it once during target analysis. The output is on "
                    f"the target row's mcp_handles_json (apk_overview.* "
                    f"fields point at decompiled_dir / decoded_dir / "
                    f"audit_mcp_index_id). Do NOT re-run the pipeline; "
                    f"use audit_mcp.semantic_search / read_function / "
                    f"search_constants against the index to inspect "
                    f"decompiled Java + smali. This call has been "
                    f"acknowledged as policy-blocked; retrying it produces "
                    f"this same response and burns budget — pivot to an "
                    f"audit_mcp tool."
                ),
                "_bridge_policy": "pipeline_only_blocked",
            }

        # fix: schema-validate kwargs against the live tool catalog
        # BEFORE the HTTP roundtrip. 56 wasted attempts in 48h with
        # 'TypeError: register.<locals>.<tool>() got an unexpected
        # keyword argument' — each attempt pays the full 30-min
        # bridge timeout when classify_behavior is the target, OR
        # at minimum one HTTP roundtrip + an LLM turn to read the
        # error. The validator runs in <1 ms locally.
        validation_error = await self._validate_kwargs(action, kwargs)
        if validation_error is not None:
            return validation_error

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
                # fix §216 — reuse the module-level pooled client
                # instead of constructing one per call. Per-call
                # timeout override preserves the prior semantics.
                client = await _get_shared_client()
                resp = await client.post(url, json=kwargs, timeout=self._timeout)
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

            # fix §215 — whitelist known statuses explicitly. Unknown
            # values used to fall through to "ready" silently, masking
            # partial-failure envelopes (e.g. {"status": "partial_failure",
            # "errors": [...]}). Most android-mcp tool handlers return
            # their result dict directly without a status field; that is
            # still treated as ready since HTTP 2xx + no status is the
            # documented success shape.
            payload_status = payload.get("status") if isinstance(payload, dict) else None
            if payload_status in ("ready", "completed", "ok"):
                ctx["status"] = "ready"
            elif payload_status in ("pending", "queued", "running"):
                ctx["status"] = "pending"
            elif payload_status == "error":
                # Tool handler returned a structured error envelope itself
                # (e.g. mobsf_scan when MOBSF_API_KEY missing before B-14's
                # RuntimeError unification). Honor it.
                ctx["status"] = "error"
                err = payload.get("error") if isinstance(payload, dict) else None
                if isinstance(err, str):
                    ctx["error_excerpt"] = err[:400]
                return payload
            elif payload_status is None:
                # android-mcp tools usually return their result dict
                # directly without an explicit status field; HTTP 2xx
                # + no status is the documented success shape.
                ctx["status"] = "ready"
            else:
                _log.warning(
                    "android_mcp_bridge %s: unknown payload status %r "
                    "(HTTP %d) — coercing to error",
                    action, payload_status, resp.status_code,
                )
                ctx["status"] = "error"
                return {
                    "status": "error",
                    "error": (
                        f"android-mcp action {action!r} returned unknown "
                        f"status {payload_status!r}"
                    ),
                }

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
        # android-mcp returns `{"tools": [...]}` (FastAPI envelope).
        # Earlier versions of the codec returned a bare list at the
        # top level; accept either shape. When neither matches, drop
        # to the empty-catalog warning so the validator can't compare
        # against a None catalog.
        #
        # Operator-observed before the fix: bridge silently downgraded
        # to empty catalog -> validator passed every agent kwarg
        # through unchecked -> android-mcp raised TypeError on every
        # call (`androguard_summary() got an unexpected keyword
        # argument 'index_id'`, `find_secrets()` rejecting `apk_path`,
        # etc.) -> tool_executor HARD-BLOCK after 3 failures per tool
        # per branch. Diagnosed on inv 78d4a594 turn 23+ at 01:36:44.
        if isinstance(raw, dict):
            inner = raw.get("tools")
            if isinstance(inner, list):
                raw = inner
            else:
                _log.warning(
                    "android_mcp_bridge: /tools dict envelope missing "
                    "'tools' key (got %s) — treating as empty catalog",
                    sorted(raw.keys())[:8],
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
        # android-mcp's /tools returns only {name, description,
        # schema_url} per tool. The actual JSON Schema for each tool
        # lives at the separate /tools/{name}/schema endpoint. Without
        # following schema_url, _compact_spec sees no `parameters` or
        # `inputSchema` field, falls through to schema={}, and
        # produces a spec with required=[] / properties={} that the
        # validator cannot reject anything against.
        #
        # Diagnosed 2026-06-14 on inv 78d4a594: agent was firing
        # `androguard_summary()` without `apk_path` (75x), calling
        # `find_secrets(apk_path=...)` when the tool actually wants
        # `decompiled_dir` (9x), missing `device_serial`+`service` on
        # adb_dumpsys (75x), etc. All would have been caught by the
        # validator if the schemas had been loaded.
        #
        # Fetch every schema in parallel via asyncio.gather to keep
        # cold-start under 1s. On per-tool fetch failure, fall back to
        # an empty schema for that tool (keep it in catalog, just lose
        # validation for it). Cached for the worker's lifetime.
        async def _fetch_schema(client: httpx.AsyncClient,
                                name: str) -> dict[str, Any]:
            try:
                schema_resp = await client.get(f"{base}/tools/{name}/schema")
                schema_data = schema_resp.json()
                return schema_data if isinstance(schema_data, dict) else {}
            except (httpx.ConnectError, httpx.TimeoutException,
                    httpx.HTTPError, ValueError) as exc:
                _log.warning(
                    "android_mcp_bridge: schema fetch failed for %s: %s "
                    "(tool kept in catalog without validation)", name, exc,
                )
                return {}

        # Drop pipeline-only tools BEFORE fetching schemas so we don't
        # waste round-trips on tools the agent will never see.
        import shutil  # noqa: PLC0415
        missing_cli = {
            tool_name
            for tool_name, cli in _ENV_GATED_TOOLS.items()
            if shutil.which(cli) is None
        }
        visible_raw = [
            t for t in raw
            if isinstance(t, dict)
            and t.get("name") not in _PIPELINE_ONLY_TOOLS
            and t.get("name") not in missing_cli
        ]
        async with httpx.AsyncClient(timeout=10.0) as client:
            schemas = await asyncio.gather(*[
                _fetch_schema(client, str(t.get("name")))
                for t in visible_raw
            ])
        # Inject the fetched schema into each tool dict before
        # _compact_spec consumes it.
        for t, schema in zip(visible_raw, schemas, strict=True):
            t["parameters"] = schema
        self.__class__._SPEC_CACHE = [_compact_spec(t) for t in visible_raw]
        # Stats for the log line
        n_with_schema = sum(
            1 for t in visible_raw if t.get("parameters", {}).get("properties")
        )
        _log.info(
            "android_mcp_bridge: catalog loaded — %d tools "
            "(%d with schemas, %d hidden as pipeline-only, %d dropped "
            "for missing CLI: %s)",
            len(self.__class__._SPEC_CACHE),
            n_with_schema,
            sum(1 for t in raw if isinstance(t, dict)
                and t.get("name") in _PIPELINE_ONLY_TOOLS),
            len(missing_cli),
            sorted(missing_cli) if missing_cli else "[]",
        )
        return self.__class__._SPEC_CACHE

    async def _validate_kwargs(
        self,
        action: str,
        kwargs: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Validate ``kwargs`` against the live JSON Schema for ``action``.

        Mirror of :meth:`AuditMcpBridgeTool._validate_kwargs`. Returns
        None when the call is valid (or when validation must be skipped
        — empty catalog, unknown action). Returns a structured error
        dict suitable for direct return from :meth:`forward` when the
        call would fail at android-mcp anyway. The error message names
        the offending kwarg + the closest valid kwarg via
        ``difflib.get_close_matches`` so the agent's next turn can
        self-correct without burning a retry.

        Skipped for actions whose schema is missing (pseudo-actions or
        catalog-not-yet-loaded scenarios) so the call still forwards to
        android-mcp and the server's own error message surfaces.
        """
        import difflib  # noqa: PLC0415

        specs = await self.list_tool_specs()
        if not specs:
            return None
        match = next((s for s in specs if s.get("name") == action), None)
        if match is None:
            _log.info(
                "android_mcp_bridge: action %r not in /tools catalog "
                "(%d known) — forwarding anyway",
                action, len(specs),
            )
            return None

        known_param_names = {p["name"] for p in (match.get("params") or [])}
        required = set(match.get("required") or [])

        unknown = [k for k in kwargs if k not in known_param_names]
        if unknown:
            suggestions = {}
            for bad in unknown:
                close = difflib.get_close_matches(
                    bad, sorted(known_param_names), n=1, cutoff=0.5,
                )
                if close:
                    suggestions[bad] = close[0]
            valid_list = sorted(known_param_names)
            hint_parts = [
                f"'{bad}' (did you mean '{suggestions[bad]}'?)"
                if bad in suggestions else f"'{bad}'"
                for bad in unknown
            ]
            error_msg = (
                f"android_mcp.{action} rejected: unknown kwarg(s) "
                f"{', '.join(hint_parts)}. "
                f"Valid params: {valid_list}. "
                f"Required: {sorted(required)}."
            )
            _log.warning(
                "android_mcp_bridge: blocked %s call with unknown kwargs %s "
                "(suggestions: %s)", action, unknown, suggestions,
            )
            return {"status": "error", "error": error_msg}

        missing = sorted(required - set(kwargs))
        if missing:
            valid_list = sorted(known_param_names)
            error_msg = (
                f"android_mcp.{action} rejected: missing required kwarg(s) "
                f"{missing}. Valid params: {valid_list}."
            )
            _log.warning(
                "android_mcp_bridge: blocked %s call missing required %s",
                action, missing,
            )
            return {"status": "error", "error": error_msg}

        return None

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
