"""RFC-11 Tier C -- android-mcp middleware plugin.

Port of :class:`aila.platform.mcp.bridges.android_mcp.AndroidMcpBridgeTool`
onto the generic :class:`aila.platform.mcp.client.McpClient` transport.
Server-specific behaviour preserved verbatim:

* pipeline-only tool blocking (``apktool_decode`` / ``jadx_decompile`` /
  ``react_native_extract`` return a synthetic ``status: ready`` +
  ``_bridge_policy: pipeline_only_blocked`` envelope so the agent reads
  the block as terminal, not retryable, unless the pipeline call sites
  pass ``_agent_bypass=True``),
* kwarg validation against the live JSON Schema with difflib
  ``get_close_matches`` suggestions,
* APK path typo recovery over ``~/.android-mcp/uploads/shared/*.apk``
  via SHA prefix + substring matching (see :func:`_resolve_apk_path`),
* per-tool schema fan-out at catalog-load time (android-mcp's
  ``/tools`` endpoint returns only ``{name, description, schema_url}``
  per tool; the schema itself lives at ``/tools/{name}/schema``), plus
  env-gated CLI filtering (``shutil.which`` gate for ``apksigner`` /
  ``drozer`` / ``frida`` / ``objection``).

The connection pool policy lives on the client -- ``persistent_pool``
in :data:`~aila.platform.mcp.server_specs.SERVER_SPECS` is ``True``
for android-mcp so :meth:`McpClient._http_post` reuses one httpx
``AsyncClient`` across calls (replacing the pre-Tier-C module-level
``_SHARED_CLIENT``). This plugin does NOT own a module-level pool.
"""
from __future__ import annotations

import asyncio
import difflib
import logging
import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from aila.platform.mcp.client import compact_tool_spec

if TYPE_CHECKING:
    from aila.platform.mcp.client import McpClient
    from aila.platform.mcp.server_specs import ServerSpec

__all__ = ["AndroidMcpMiddleware"]

_log = logging.getLogger(__name__)


# Tools that the ingestion pipeline (TargetAnalysisService) runs ONCE
# at target create time. Blocking agent re-invocation avoids re-decoding
# the APK on every retry; the cached outputs (decompiled_dir,
# audit_mcp_index_id) are already on the target row.
_PIPELINE_ONLY_TOOLS: frozenset[str] = frozenset((
    "apktool_decode",
    "jadx_decompile",
    "react_native_extract",
))


# Tools requiring a host CLI on PATH. Dropped from the agent-visible
# catalog when the binary is unresolvable so the agent never tries to
# call a tool that would fail inside android-mcp with a transient-
# looking ``RuntimeError: <cli> not on PATH``.
_ENV_GATED_TOOLS: dict[str, str] = {
    "verify_apk_signing": "apksigner",
    "drozer_scan_apk": "drozer",
    "frida_attach_and_trace_calls": "frida",
    "frida_dump_process_modules": "frida",
    "frida_list_running_devices": "frida",
    "objection_patch_apk": "objection",
    "objection_explore": "objection",
}


# Kwarg names that carry an on-disk APK path. Each is a candidate for
# the typo-recovery pass; see :func:`_resolve_apk_path` for the rules.
_APK_PATH_KWARGS: frozenset[str] = frozenset(("apk_path", "apk", "path"))


# Payload statuses the bridge accepts as documented; anything else is
# coerced to a structured error rather than silently masked. Mirrors
# the pre-Tier-C bridge's whitelist (fix §215).
_KNOWN_STATUSES: frozenset[str] = frozenset((
    "ready", "completed", "ok", "pending", "queued", "running", "error",
))


def _shared_apks_dir() -> Path:
    """Return the directory that holds operator-uploaded APKs.

    Default: ``~/.android-mcp/uploads/shared/``. Env override:
    ``ANDROID_MCP_UPLOADS_DIR`` (full directory path, not just a parent).
    """
    env = os.environ.get("ANDROID_MCP_UPLOADS_DIR")
    if env:
        return Path(env)
    return Path.home() / ".android-mcp" / "uploads" / "shared"


def _resolve_apk_path(raw_path: str) -> tuple[str, str | None]:
    """Resolve an agent-supplied apk_path to the canonical on-disk path.

    Returns a ``(canonical_path, note)`` tuple. ``note`` is non-None
    when the resolver substituted something; it carries the human-
    readable correction for logging. Original behaviour when the
    path resolves cleanly or no candidate matches: ``(raw_path, None)``.

    Three passes:

    1. ``.strip()`` + strip surrounding quotes. Catches whitespace
       typos that don't change the SHA at all.
    2. If still missing, extract the basename without ``.apk`` and
       walk progressively shorter prefixes (32, 24, 16, 12, 8 hex
       chars) against the shared uploads directory. First unique
       match wins. 8 chars = ~32 bits; collision unlikely with
       < ~65k APKs in shared.
    3. Substring match against the longer of (candidate SHA, agent
       SHA) with an 8-hex-char minimum overlap. Catches the inverse
       typo where the agent kept only the middle/tail of the SHA.
    4. If still ambiguous OR zero matches, return the normalised
       path unchanged so the upstream FileNotFoundError still fires
       (so the breaker can engage and the agent can pivot).
    """
    normalised = raw_path.strip().strip('"').strip("'")
    if Path(normalised).is_file():
        if normalised == raw_path:
            return normalised, None
        return normalised, "trimmed whitespace from apk_path"

    shared = _shared_apks_dir()
    if not shared.is_dir():
        return raw_path, None

    base = Path(normalised).name
    if not base.lower().endswith(".apk"):
        return raw_path, None
    sha = base[:-4]  # strip .apk
    # Only the hex portion of the SHA is reliable. Stop at the first
    # non-hex character so paths with prefixes (e.g. "test-<sha>.apk")
    # still get a usable lookup key.
    hex_chars = []
    for c in sha:
        if c in "0123456789abcdefABCDEF":
            hex_chars.append(c.lower())
        else:
            break
    if len(hex_chars) < 8:
        return raw_path, None
    sha_hex = "".join(hex_chars)

    candidates_all = sorted(shared.glob("*.apk"))
    candidate_shas = {
        p: p.name[:-4].lower() for p in candidates_all if p.name.lower().endswith(".apk")
    }

    # Pass 1 -- prefix match. Progressively shorter prefixes of the
    # agent's SHA; first unique hit wins. Catches typos where the
    # agent dropped trailing chars or stuck a stray space mid-SHA.
    for n in (min(32, len(sha_hex)), 24, 16, 12, 8):
        if n > len(sha_hex):
            continue
        prefix = sha_hex[:n]
        matches = [p for p in candidates_all if candidate_shas[p].startswith(prefix)]
        if len(matches) == 1:
            canonical = str(matches[0])
            return canonical, (
                f"apk_path typo recovered via {n}-char SHA prefix: "
                f"agent passed {raw_path!r}, resolved to {canonical!r}"
            )
        if len(matches) == 0:
            continue
        # >1 matches at this prefix length means real ambiguity at
        # the head. Don't keep going wider -- the next pass uses a
        # different match strategy entirely.
        break

    # Pass 2 -- substring match against the longer of (candidate SHA,
    # agent SHA). Catches the inverse typo: the agent dropped the
    # LEADING characters and only kept the middle/tail. Require a
    # minimum overlap of 8 hex chars so we don't pick up coincidental
    # short hex strings.
    if len(sha_hex) >= 8:
        sub_matches: list[tuple[int, Path]] = []
        for cand, cand_sha in candidate_shas.items():
            if sha_hex in cand_sha:
                sub_matches.append((len(sha_hex), cand))
            elif cand_sha in sha_hex:
                sub_matches.append((len(cand_sha), cand))
        if len(sub_matches) == 1:
            _, cand = sub_matches[0]
            canonical = str(cand)
            return canonical, (
                f"apk_path typo recovered via SHA substring: "
                f"agent passed {raw_path!r}, resolved to {canonical!r}"
            )
        if len(sub_matches) > 1:
            # Multiple APKs contain (or are contained in) the agent's
            # SHA. Pick the LONGEST overlap as the most specific
            # match. Tie at longest -- give up and let the LLM see
            # the error.
            sub_matches.sort(key=lambda pair: -pair[0])
            if len(sub_matches) >= 2 and sub_matches[0][0] > sub_matches[1][0]:
                _, cand = sub_matches[0]
                canonical = str(cand)
                return canonical, (
                    f"apk_path typo recovered via longest SHA substring: "
                    f"agent passed {raw_path!r}, resolved to {canonical!r}"
                )

    return raw_path, None


class AndroidMcpMiddleware:
    """RFC-11 Tier C -- android-mcp behaviour plugin.

    Implements :class:`aila.platform.mcp.middleware.McpMiddleware`.
    Constructed by :func:`aila.platform.mcp.factory.make_bridge` from
    :data:`~aila.platform.mcp.server_specs.SERVER_SPECS['android_mcp']`;
    behaviour is a verbatim port of the pre-Tier-C
    :class:`~aila.platform.mcp.bridges.android_mcp.AndroidMcpBridgeTool`.

    The connection pool is owned by :class:`McpClient` (the spec's
    ``persistent_pool=True`` flag makes the client reuse one httpx
    ``AsyncClient`` across calls); this plugin has NO module-level
    httpx state.
    """

    # Class-level tool catalog cache; no TTL -- warmed once per worker
    # process, invalidated on worker restart the same way the pre-Tier-C
    # bridge's ``_SPEC_CACHE`` behaved.
    _SPEC_CACHE: list[dict[str, Any]] | None = None

    def __init__(self, *, spec: ServerSpec, module_id: str) -> None:
        self.server_id = spec.server_id
        self.tool_name = spec.tool_name
        self.env_var = spec.env_var
        self.config_key = spec.config_key
        self.default_url = spec.default_url
        self.persistent_pool = spec.persistent_pool
        # Env override lets the operator bump the network ceiling
        # without a code change; per-stage StageTracker timeouts (in
        # services/stage_tracker.py) still bound each individual tool.
        self.default_timeout = float(
            os.environ.get("ANDROID_MCP_TIMEOUT", str(spec.default_timeout)),
        )
        self.module_id = module_id

    async def forward(
        self,
        client: McpClient,
        action: str | None,
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Dispatch one android-mcp tool call.

        Verbatim port of ``AndroidMcpBridgeTool.forward``: pipeline-only
        block, kwarg validation, APK path recovery, then transport via
        :meth:`McpClient.post` inside one :meth:`McpClient.recorder_context`
        envelope. Post-call the middleware re-wraps non-2xx and unknown-
        status envelopes into the uniform ``{status: error, error: ...}``
        shape the pre-Tier-C bridge produced.
        """
        if not action:
            return await self._list_tools(client)

        # Block pipeline-only tools from agent-initiated calls. The
        # pipeline call sites (TargetAnalysisService) bypass with
        # ``_agent_bypass=True`` popped before we look at ``action``.
        # The block returns ``status: ready`` (not ``error``) so the
        # agent's retry breaker treats it as terminal; the note points
        # at the cached decompilation output.
        _agent_bypass = kwargs.pop("_agent_bypass", False)
        if action in _PIPELINE_ONLY_TOOLS and not _agent_bypass:
            return {
                "status": "ready",
                "matches": [],
                "results": [],
                "_bridge_note": (
                    f"{action!r} is pipeline-only -- the APK ingestion stage "
                    f"ran it once during target analysis. The output is on "
                    f"the target row's mcp_handles_json (apk_overview.* "
                    f"fields point at decompiled_dir / decoded_dir / "
                    f"audit_mcp_index_id). Do NOT re-run the pipeline; "
                    f"use audit_mcp.semantic_search / read_function / "
                    f"search_constants against the index to inspect "
                    f"decompiled Java + smali. This call has been "
                    f"acknowledged as policy-blocked; retrying it produces "
                    f"this same response and burns budget -- pivot to an "
                    f"audit_mcp tool."
                ),
                "_bridge_policy": "pipeline_only_blocked",
            }

        # Schema-validate kwargs against the live catalog BEFORE the
        # HTTP roundtrip. Runs in <1 ms locally; saves the full 30-min
        # bridge timeout when a slow tool would have rejected the call
        # server-side anyway.
        validation_error = await self._validate_kwargs(client, action, kwargs)
        if validation_error is not None:
            return validation_error

        # Auto-resolve any apk_path-like kwarg from typo'd input to
        # the canonical on-disk path BEFORE the HTTP roundtrip. See
        # the ``_APK_PATH_KWARGS`` comment block for the rationale --
        # agents typo-drift long SHA-derived paths every retry, each
        # typo generating a FileNotFoundError that the breaker only
        # catches after burning several turns.
        for _k in _APK_PATH_KWARGS:
            _raw = kwargs.get(_k)
            if not isinstance(_raw, str) or not _raw:
                continue
            _canonical, _note = _resolve_apk_path(_raw)
            if _note is not None:
                kwargs[_k] = _canonical
                _log.warning("android_mcp_middleware: %s", _note)

        # Transport hop -- one recorded audit-log row per call.
        async with client.recorder_context(action) as ctx:
            body = await client.post(
                action, kwargs, timeout=self.default_timeout, ctx=ctx,
            )
            http_status = ctx.get("http_status")
            body_status = body.get("status") if isinstance(body, dict) else None

            # Non-2xx wrap. The client's post left ``ctx["status"] =
            # "error"`` but returned the raw body; the pre-Tier-C
            # bridge re-shaped this as ``{status: error, error: "...
            # returned HTTP N: <msg>"}``. Skip the wrap when the body
            # already carries ``status: error`` -- transport failures
            # (non-JSON, connect, timeout) come pre-formatted from
            # ``client.post`` and re-wrapping would double-nest them.
            if (
                http_status is not None
                and http_status >= 400
                and body_status != "error"
            ):
                if isinstance(body, dict):
                    err_msg = (
                        body.get("error")
                        or body.get("detail")
                        or str(body)
                    )
                else:
                    err_msg = str(body)
                ctx["error_excerpt"] = str(err_msg)[:400]
                return {
                    "status": "error",
                    "error": (
                        f"android-mcp action {action!r} returned "
                        f"HTTP {http_status}: {err_msg}"
                    ),
                }

            # Unknown status coercion (fix §215). Client.post already
            # logged + set ctx.status=error; middleware surfaces the
            # structured error the pre-Tier-C bridge produced so the
            # agent sees a clean rejection rather than a partial-
            # failure envelope masquerading as ready.
            if (
                isinstance(body, dict)
                and body_status is not None
                and body_status not in _KNOWN_STATUSES
            ):
                return {
                    "status": "error",
                    "error": (
                        f"android-mcp action {action!r} returned unknown "
                        f"status {body_status!r}"
                    ),
                }

            return body

    async def _list_tools(self, client: McpClient) -> dict[str, Any]:
        """Return android-mcp's tool catalog with parsed schemas."""
        specs = await self.list_tool_specs(client)
        return {
            "status": "ready",
            "tools": [s["name"] for s in specs],
            "count": len(specs),
            "specs": specs,
        }

    async def list_tool_specs(self, client: McpClient) -> list[dict[str, Any]]:
        """Fetch android-mcp's tool catalog with parsed schemas.

        android-mcp's ``/tools`` endpoint returns only
        ``{name, description, schema_url}`` per tool; the JSON Schema
        for each tool lives at the separate ``/tools/{name}/schema``
        endpoint. This plugin fetches the raw ``/tools`` list itself
        (NOT via :meth:`McpClient.list_tool_specs`, which pre-compacts
        via :func:`~aila.platform.mcp.client.compact_tool_spec` and
        would drop the schema-fan-out hook) so the per-tool schema
        fetches can inject the returned schema as ``parameters`` before
        compaction.

        Cached on the class so concurrent bridge instances share one
        HTTP round-trip. Fetch failure caches an empty list so the
        validator never compares against a ``None`` catalog.
        """
        cls = self.__class__
        if cls._SPEC_CACHE is not None:
            return cls._SPEC_CACHE
        base = await client.base_url()
        url = f"{base}/tools"
        try:
            async with httpx.AsyncClient(timeout=10.0) as http_client:
                resp = await http_client.get(url)
            raw = resp.json()
        except (httpx.ConnectError, httpx.TimeoutException, ValueError) as exc:
            _log.warning(
                "android_mcp_middleware: catalog fetch failed (%s) -- agent "
                "will see name-only listing without schemas", exc,
            )
            cls._SPEC_CACHE = []
            return []

        # Accept either shape android-mcp has shipped: bare list at
        # the top level, or ``{"tools": [...]}`` envelope. A dict
        # without a ``tools`` key is treated as empty so the validator
        # never compares against a ``None`` catalog (see the
        # pre-Tier-C §216 diagnosis).
        if isinstance(raw, dict):
            inner = raw.get("tools")
            if isinstance(inner, list):
                raw = inner
            else:
                _log.warning(
                    "android_mcp_middleware: /tools dict envelope missing "
                    "'tools' key (got %s) -- treating as empty catalog",
                    sorted(raw.keys())[:8],
                )
                cls._SPEC_CACHE = []
                return []
        if not isinstance(raw, list):
            _log.warning(
                "android_mcp_middleware: /tools returned non-list payload "
                "(%s) -- treating as empty catalog", type(raw).__name__,
            )
            cls._SPEC_CACHE = []
            return []

        # Env-gated CLI probe: drop tools whose backing binary is not
        # on PATH. shutil.which reflects the worker's current PATH; a
        # later CLI install requires a worker restart to pick up (same
        # lifecycle as other catalog-cache invalidations).
        missing_cli = {
            tool_name
            for tool_name, cli in _ENV_GATED_TOOLS.items()
            if shutil.which(cli) is None
        }

        # Drop pipeline-only + missing-CLI tools BEFORE the per-tool
        # schema fetch so we do not spend round-trips on tools the
        # agent will never see.
        visible_raw = [
            t for t in raw
            if isinstance(t, dict)
            and t.get("name") not in _PIPELINE_ONLY_TOOLS
            and t.get("name") not in missing_cli
        ]

        async def _fetch_schema(
            http_client: httpx.AsyncClient, name: str,
        ) -> dict[str, Any]:
            try:
                schema_resp = await http_client.get(
                    f"{base}/tools/{name}/schema",
                )
                schema_data = schema_resp.json()
                return schema_data if isinstance(schema_data, dict) else {}
            except (httpx.ConnectError, httpx.TimeoutException,
                    httpx.HTTPError, ValueError) as exc:
                _log.warning(
                    "android_mcp_middleware: schema fetch failed for %s: %s "
                    "(tool kept in catalog without validation)", name, exc,
                )
                return {}

        async with httpx.AsyncClient(timeout=10.0) as http_client:
            schemas = await asyncio.gather(*[
                _fetch_schema(http_client, str(t.get("name")))
                for t in visible_raw
            ])
        # Inject the fetched schema into each tool dict before
        # _compact_spec consumes it.
        for t, schema in zip(visible_raw, schemas, strict=True):
            t["parameters"] = schema

        cls._SPEC_CACHE = [compact_tool_spec(t) for t in visible_raw]
        # Diagnostic log matching the pre-Tier-C bridge's line so the
        # operator's grep patterns still hit.
        n_with_schema = sum(
            1 for t in visible_raw if t.get("parameters", {}).get("properties")
        )
        _log.info(
            "android_mcp_middleware: catalog loaded -- %d tools "
            "(%d with schemas, %d hidden as pipeline-only, %d dropped "
            "for missing CLI: %s)",
            len(cls._SPEC_CACHE),
            n_with_schema,
            sum(
                1 for t in raw
                if isinstance(t, dict) and t.get("name") in _PIPELINE_ONLY_TOOLS
            ),
            len(missing_cli),
            sorted(missing_cli) if missing_cli else "[]",
        )
        return cls._SPEC_CACHE

    async def _validate_kwargs(
        self,
        client: McpClient,
        action: str,
        kwargs: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Validate ``kwargs`` against the live JSON Schema for ``action``.

        Verbatim port of ``AndroidMcpBridgeTool._validate_kwargs``.
        Returns ``None`` when the call is valid (or when validation
        must be skipped -- empty catalog, unknown action). Returns a
        structured ``{status: error, error: ...}`` dict when the call
        would fail at android-mcp anyway. Unknown kwargs surface the
        closest valid name via :func:`difflib.get_close_matches` so
        the agent's next turn can self-correct without burning a retry.
        """
        specs = await self.list_tool_specs(client)
        if not specs:
            return None
        match = next((s for s in specs if s.get("name") == action), None)
        if match is None:
            _log.info(
                "android_mcp_middleware: action %r not in /tools catalog "
                "(%d known) -- forwarding anyway",
                action, len(specs),
            )
            return None

        known_param_names = {p["name"] for p in (match.get("params") or [])}
        required = set(match.get("required") or [])

        unknown = [k for k in kwargs if k not in known_param_names]
        if unknown:
            suggestions: dict[str, str] = {}
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
                "android_mcp_middleware: blocked %s call with unknown kwargs %s "
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
                "android_mcp_middleware: blocked %s call missing required %s",
                action, missing,
            )
            return {"status": "error", "error": error_msg}

        return None
