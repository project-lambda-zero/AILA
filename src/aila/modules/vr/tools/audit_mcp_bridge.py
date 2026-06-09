"""audit-mcp bridge — AILA Tool wrapping the audit-mcp HTTP API.

Mirrors ``IDABridgeTool``. The audit-mcp server (source code audit MCP,
51 tools, GPU-accelerated graph engine) runs at the URL configured by
``AUDIT_MCP_URL`` env var or ``vr.audit_mcp_url`` config key. Default
``http://127.0.0.1:18822`` (audit-mcp's default HTTP bind).

This bridge is the only place where the VR module touches the
audit-mcp HTTP surface. Use it for source-code targets the same way
``IDABridgeTool`` is used for binary targets.

Timeout: ``AUDIT_MCP_TIMEOUT`` env var, default 900 s (15 min — covers
monorepo-scale ``fuzzing_targets`` on a fresh index that needs GPU CSR
build + ranking, e.g. firefox cold 294 s on RTX 3080). Heavy graph
queries (``dead_code``, ``scan_and_correlate``) that the server runs
truly-async return ``status='pending'`` + a ``task_id``; callers poll
with ``action='poll_task'`` until ``status='ready'`` — see
``FunctionRankingDispatcher._rank_source`` for the poll pattern.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from aila.platform.tools._common import Tool

__all__ = ["AuditMcpBridgeTool"]


# Tools that walk the call graph. Used by forward() to apply the
# zero-result auto-suggestion: if any of these returns 0 results, the
# bridge appends a `_bridge_note` field with diagnostic guidance and
# nearest-name suggestions so the agent doesn't walk away thinking
# "no edges = no bug here" when the real cause is an indexer miss.
_XREF_ACTIONS = frozenset({
    "callers_of", "callees_of", "ancestors_of", "reachable_from",
})


def _compact_spec(raw: dict[str, Any]) -> dict[str, Any]:
    """Project an MCP tool catalog entry into the form the prompt
    builder + agent need.

    Input shape (from /tools): ``{name, description, parameters:
    {properties, required}}``. Output: ``{name, description,
    params: [{name, type, required, default, description}],
    required: [...]}``.
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
            os.environ.get("AUDIT_MCP_TIMEOUT", "300"),
        )

    # ── Per-index pre-warm registry ──────────────────────────────────
    #
    # When audit_mcp runs with AUDIT_MCP_WORKERS>1, each worker holds
    # its own TypeResolver + semble + engine caches. A single request
    # warms only ONE worker; the other N-1 stay cold and pay ~30s on
    # their first hit. Result: investigation experiences ~30s lag
    # spread across the first wave of agent tool calls.
    #
    # On the first call to a new index_id we fire 16 parallel cheap
    # requests (summary + semble noop). Round-robin distribution
    # gives each of the 4 workers ~4 calls — statistically certain to
    # warm them all. Subsequent calls go through unchanged.
    #
    # Class-level set + per-index asyncio.Lock so 3 branches firing
    # the first call in parallel don't trigger 3 separate fan-outs.
    _warmed_indexes: set[str] = set()
    _warm_locks: dict[str, Any] = {}  # lazy asyncio.Lock per index_id
    _PREWARM_FANOUT: int = 16
    _PREWARM_TIMEOUT_S: float = 90.0

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
    # See ``_kwarg_alias.py`` for the algorithm. We define the families
    # here (they're catalog-specific) and delegate alias resolution to
    # the shared module so ``ida_bridge.py`` uses the exact same code.
    #
    # Families are intentionally tight — `path` and `file_path` are NOT
    # the same intent (repo root vs. one file), so they stay separate.
    # `query` (natural-language) and `pattern` (regex) are also distinct.
    # `depth` is kept separate from the how_many family because tools
    # like ``ancestors_of`` and ``paths_between`` take BOTH at once.
    _KW_FAMILIES: dict[str, set[str]] = {
        "how_many": {
            "limit", "top_k", "top_n", "n", "count", "max_results",
            "k", "max_count", "num", "max_n", "max_items",
        },
        "depth": {
            "depth", "max_depth", "max_hops", "traversal_depth",
        },
        "threshold": {
            "threshold", "min_complexity", "cutoff", "min_cyc",
            "complexity_threshold", "min_score", "score_threshold",
            "min_value",
        },
        "name": {
            "name", "function_name", "class_name", "sink_name",
            "symbol_name", "fn_name", "fn", "function", "symbol",
            "exception_name",
        },
    }

    # Manual overrides for renames the family algorithm cannot infer.
    # Keep small; prefer adding to ``_KW_FAMILIES``.
    _MANUAL_OVERRIDES: dict[str, dict[str, str]] = {}

    # Auto-built ``{action: {alias: canonical}}`` populated by
    # ``list_tool_specs()`` after the first /tools fetch.
    _AUTO_ALIAS_MAP: dict[str, dict[str, str]] = {}

    @classmethod
    def _normalize_kwargs(
        cls, action: str, kwargs: dict[str, Any],
    ) -> tuple[dict[str, Any], list[str]]:
        """Delegate to the shared resolver against the live alias map."""
        from aila.modules.vr.tools._kwarg_alias import normalize_kwargs  # noqa: PLC0415

        return normalize_kwargs(action, kwargs, cls._AUTO_ALIAS_MAP)

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
        # Bridge-side virtual tools — handled locally without HTTP.
        # `read_lines` resolves index_id -> root_path via list_indexes
        # and slices the file from disk. Bypasses semble chunking and
        # all the broken indexers (read_function returning file headers,
        # search_constants returning 0, etc.).
        if action == "read_lines":
            return await self._read_lines_local(kwargs)
        normalized_kwargs, kw_notes = self._normalize_kwargs(action, kwargs)
        for note in kw_notes:
            logging.getLogger(__name__).info("audit_mcp_bridge %s", note)

        # Local kwarg validation against the live JSON Schema. Catches
        # LLM-hallucinated args (e.g. fuzzing_targets(threshold=0.5) — no
        # such param) and returns a structured "did you mean" error
        # before the HTTP round-trip. Without this, audit-mcp's bare
        # TypeError reply is too generic for the agent to recover from
        # and we see retry storms of the same invalid call (8x in one
        # investigation, all 'unexpected keyword argument threshold').
        # Skipped for poll_task / unknown actions where the cache is
        # empty or the action isn't in the schema catalog (those
        # forward straight through and audit-mcp adjudicates).
        validation_error = await self._validate_kwargs(action, normalized_kwargs)
        if validation_error is not None:
            return validation_error

        # Pre-warm fan-out: when this is the FIRST call seen for the
        # index_id in this process, fire 16 parallel cheap requests to
        # ensure every audit_mcp worker (AUDIT_MCP_WORKERS=4 by default)
        # has the engine + TypeResolver + semble index loaded in RAM
        # before the real call dispatches. Without this, the agent's
        # first 4 tool calls each pay a separate ~30s cold-build cost
        # on different workers (round-robin distribution).
        index_id = normalized_kwargs.get("index_id")
        if isinstance(index_id, str) and index_id:
            await self._ensure_prewarmed(index_id)

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
                    # Auto-fallback: when read_function reports "not
                    # indexed", fan a search_functions(pattern=name)
                    # call and append the top matches to the error
                    # string. Turns a dead-end error into actionable
                    # next step. Agents repeatedly tried ensureStrBuf
                    # (hallucinated name) on Firefox; the real index
                    # had appendStrBuf, emitStrBuf, etc. Without
                    # suggestions, the agent looped on the same bad
                    # name across 4+ turns.
                    if (
                        action == "read_function"
                        and "not indexed" in err.lower()
                        and isinstance(normalized_kwargs.get("name"), str)
                    ):
                        suggestions = await self._suggest_function_names(
                            base=base,
                            index_id=normalized_kwargs.get("index_id") or "",
                            name=str(normalized_kwargs["name"]),
                        )
                        if suggestions:
                            payload["error"] = (
                                f"{err}\n\nNEAREST INDEXED FUNCTION NAMES "
                                f"(use one of these with read_function, OR "
                                f"if none matches, the symbol genuinely "
                                f"does NOT exist in this codebase — STOP "
                                f"trying this name and pivot to "
                                f"semantic_search):\n"
                                + "\n".join(f"  - {s}" for s in suggestions)
                            )

            # Zero-result enrichment for xref tools. callers_of /
            # callees_of / ancestors_of / reachable_from can return
            # 0 hits for two very different reasons: (a) the queried
            # symbol genuinely doesn't exist in the indexed tree (agent
            # hallucinated a name, the symbol is in an unindexed sibling
            # repo); or (b) the symbol exists but trailmark's call-graph
            # indexer missed its forward edges — observed live with
            # ngx_http_init_phase_handlers having only 1 of ~10 real
            # outgoing calls indexed. Without a hint, the agent treats
            # both cases as "no edges = my hypothesis is wrong" and
            # walks away from a real lead. Embed both possibilities +
            # nearest-name suggestions so the agent's next turn knows
            # whether to fix the name or fall back to read_function.
            if (
                ctx.get("status") == "ready"
                and isinstance(payload, dict)
                and action in _XREF_ACTIONS
                and isinstance(normalized_kwargs.get("name"), str)
            ):
                result_keys = ("callers", "callees", "results", "nodes")
                result_list: list[Any] = []
                for k in result_keys:
                    v = payload.get(k)
                    if isinstance(v, list):
                        result_list = v
                        break
                if len(result_list) == 0:
                    suggestions = await self._suggest_function_names(
                        base=base,
                        index_id=normalized_kwargs.get("index_id") or "",
                        name=str(normalized_kwargs["name"]),
                    )
                    note_lines = [
                        f"audit_mcp.{action}({normalized_kwargs['name']!r}) "
                        f"returned 0 results. Two possibilities:",
                        "  (a) the symbol does not exist in this index "
                        "(hallucinated name, or in a sibling repo not "
                        "indexed alongside the primary target);",
                        "  (b) the call-graph indexer missed this "
                        "function's edges in this direction. Fall back "
                        "to read_function() to see the body and grep "
                        "for calls directly, OR run semantic_search() "
                        "to find the body via embedding.",
                    ]
                    if suggestions:
                        note_lines.append(
                            "NEAREST INDEXED FUNCTION NAMES:")
                        note_lines.extend(f"  - {s}" for s in suggestions)
                    payload["_bridge_note"] = "\n".join(note_lines)
            return payload

    async def _suggest_function_names(
        self, base: str, index_id: str, name: str,
    ) -> list[str]:
        """Return up to 5 indexed function names nearest to ``name``.

        Fires search_functions with a permissive prefix pattern (just
        the first 4-6 chars of the queried name) so the agent sees
        candidates even when its hallucinated name shares only a stem
        with anything real. Best-effort: empty list on any error
        means the caller emits the original error unchanged.
        """
        if not index_id or not name:
            return []
        # Take the longest unambiguous prefix — drop trailing CamelCase
        # tail. ``ensureStrBuf`` becomes ``ensureStrB`` then ``ensureS``
        # and finally ``ensure`` so search_functions finds appendStrBuf,
        # emitStrBuf, etc. via the StrBuf stem.
        candidates: list[str] = []
        seen: set[str] = set()
        probes = [name, name[:6], name[:4]]
        # Add CamelCase-stem variants: 'ensureStrBuf' -> 'StrBuf'
        import re  # noqa: PLC0415
        camel_parts = re.findall(r"[A-Z][a-z]+", name)
        probes.extend(camel_parts[-2:])
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                for pattern in probes:
                    if not pattern or len(pattern) < 3:
                        continue
                    try:
                        resp = await client.post(
                            f"{base}/tools/search_functions",
                            json={"index_id": index_id, "pattern": pattern, "limit": 8},
                        )
                        body = resp.json()
                    except (httpx.ConnectError, httpx.TimeoutException, ValueError):
                        continue
                    matches = body.get("matches") or body.get("results") or []
                    for m in matches:
                        if not isinstance(m, dict):
                            continue
                        n = m.get("name") or m.get("qualified_name")
                        if not n or n in seen:
                            continue
                        seen.add(n)
                        candidates.append(n)
                        if len(candidates) >= 5:
                            return candidates
                    if len(candidates) >= 5:
                        return candidates
        except (httpx.ConnectError, RuntimeError):
            return candidates
        return candidates

    # ── Schema-driven tool catalog ────────────────────────────────────
    #
    # The MCP server exposes the full JSON Schema for every tool via
    # GET /tools. Fetch once per process, hand the parsed form to
    # the prompt builder. The agent sees exact parameter names +
    # required flag + default per tool, so it never has to guess —
    # which is what was causing read_function(file_hint=...) etc.
    _SPEC_CACHE: list[dict[str, Any]] | None = None
    # Cache TTL: audit-mcp restarts can ship new tools / renamed kwargs.
    # Without a TTL, the bridge's first-startup schema stays stuck until
    # AILA backend itself restarts. 300s matches the operator-observable
    # latency of "I just restarted audit-mcp, when do schemas refresh?"
    # and is short enough that the auto-refresh fires before a typical
    # multi-investigation batch finishes.
    _SPEC_CACHE_TTL_S: float = 300.0
    _SPEC_CACHE_FETCHED_AT: float | None = None

    async def _list_tools(self) -> dict:
        """Return available audit-mcp tool names + schemas."""
        specs = await self.list_tool_specs()
        return {
            "status": "ready",
            "tools": [s["name"] for s in specs],
            "count": len(specs),
            "specs": specs,
        }

    async def list_tool_specs(self) -> list[dict[str, Any]]:
        """Fetch the MCP catalog with parsed schemas. Cached per process.

        Each entry: ``{name, description, params: [{name, type,
        required, default}], required: [...]}``. Race-safe: two
        concurrent fetches may both hit the server on cold start;
        each sets the same value so the cache converges.
        """
        import time as _time  # noqa: PLC0415
        now = _time.monotonic()
        cached_at = self.__class__._SPEC_CACHE_FETCHED_AT
        if (
            self.__class__._SPEC_CACHE is not None
            and cached_at is not None
            and (now - cached_at) < self.__class__._SPEC_CACHE_TTL_S
        ):
            return self.__class__._SPEC_CACHE
        if self.__class__._SPEC_CACHE is not None and cached_at is not None:
            logging.getLogger(__name__).info(
                "audit_mcp_bridge: schema cache stale (%.0fs old, TTL %.0fs) — refetching",
                now - cached_at, self.__class__._SPEC_CACHE_TTL_S,
            )
        base = await self._resolve_base_url()
        url = f"{base}/tools"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
            raw = resp.json()
        except (httpx.ConnectError, httpx.TimeoutException, ValueError) as exc:
            logging.getLogger(__name__).warning(
                "audit_mcp catalog fetch failed (%s) — agent will see "
                "name-only listing without schemas", exc,
            )
            # On fetch failure: keep any prior cache (better stale than
            # empty) and back off TTL so we retry sooner. Only flatten
            # to [] when we never had a cache to begin with.
            if self.__class__._SPEC_CACHE is None:
                self.__class__._SPEC_CACHE = []
                self.__class__._SPEC_CACHE_FETCHED_AT = now
            else:
                # Back off TTL by 30s so the next call retries; without
                # this the stale cache would be honored for the full TTL.
                self.__class__._SPEC_CACHE_FETCHED_AT = now - (
                    self.__class__._SPEC_CACHE_TTL_S - 30.0
                )
            return self.__class__._SPEC_CACHE
        self.__class__._SPEC_CACHE = [_compact_spec(t) for t in raw]
        self.__class__._SPEC_CACHE_FETCHED_AT = now
        # Inject the bridge-side virtual `read_lines` tool. audit_mcp
        # doesn't ship this; we resolve index_id -> root_path locally
        # and read the file slice from disk. The agent sees it in the
        # tool catalog and can call it like any other audit_mcp tool.
        self.__class__._SPEC_CACHE.append({
            "name": "read_lines",
            "description": (
                "Read a verbatim slice of source from a file in the "
                "indexed repo. Bypasses every audit_mcp indexer — gives "
                "you EXACTLY the lines you ask for. Use this when you "
                "know the file path and the line range you need to "
                "verify (e.g. after a semantic_search hit gave you the "
                "neighborhood). Lines are 1-indexed inclusive. Hard "
                "ceiling 1500 lines per call; default max 500."
            ),
            "params": [
                {"name": "index_id", "type": "string", "required": True},
                {"name": "file_path", "type": "string", "required": True,
                 "description": "path relative to repo root (e.g. src/http/v3/ngx_http_v3_filter_module.c)"},
                {"name": "start", "type": "integer", "required": True,
                 "description": "1-indexed start line (inclusive)"},
                {"name": "end", "type": "integer", "required": True,
                 "description": "1-indexed end line (inclusive)"},
                {"name": "max_lines", "type": "integer", "required": False,
                 "description": "cap on returned lines (default 500, max 1500)"},
            ],
            "required": ["index_id", "file_path", "start", "end"],
        })
        # Derive the per-action alias map from the live schema. Every
        # subsequent _normalize_kwargs call resolves through this map.
        from aila.modules.vr.tools._kwarg_alias import build_alias_map  # noqa: PLC0415

        self.__class__._AUTO_ALIAS_MAP = build_alias_map(
            self.__class__._SPEC_CACHE,
            self._KW_FAMILIES,
            self._MANUAL_OVERRIDES,
        )
        logging.getLogger(__name__).info(
            "audit_mcp_bridge: catalog loaded — %d tools, %d with alias maps",
            len(self.__class__._SPEC_CACHE),
            len(self.__class__._AUTO_ALIAS_MAP),
        )
        return self.__class__._SPEC_CACHE

    async def _ensure_prewarmed(self, index_id: str) -> None:
        """Fan out lightweight calls so every audit_mcp worker pre-loads
        the engine + semble caches for ``index_id``, exactly once per
        process per index. Subsequent calls are no-ops.

        Skipped entirely when ``AUDIT_MCP_WORKERS<=1`` (the Windows
        reality). With a single worker, 16 parallel calls don't warm
        anything — they all serialize on the same async loop and just
        multiply the workload the worker has to chew through before
        the agent's REAL tool call gets a slot. That happened on
        investigation 417b469f: 3 branches simultaneously fired
        attack_surface/summary on firefox; bridge fired 16 pre-warm
        calls onto a single GIL-bound worker; the worker spent 6+
        minutes thrashing without ever responding to any tool call.

        Each call hits ``/tools/summary`` (loads engine + preanalysis)
        and ``/tools/semble_stats`` (triggers lazy semble build).
        Round-robin from uvicorn distributes the calls across the
        worker pool when N>1.

        Errors are swallowed by design: warming is best-effort. If
        audit-mcp is down or the index is broken, the real call that
        follows will surface a proper error.
        """
        import asyncio  # noqa: PLC0415

        if index_id in self.__class__._warmed_indexes:
            return
        # Skip pre-warm on single-worker deployments — see docstring.
        workers = int(os.environ.get("AUDIT_MCP_WORKERS", "1") or "1")
        if workers <= 1:
            self.__class__._warmed_indexes.add(index_id)
            logging.getLogger(__name__).info(
                "audit_mcp_bridge: pre-warm skipped for %s "
                "(AUDIT_MCP_WORKERS=%d, no fan-out needed)",
                index_id, workers,
            )
            return

        lock = self.__class__._warm_locks.get(index_id)
        if lock is None:
            lock = asyncio.Lock()
            self.__class__._warm_locks[index_id] = lock

        async with lock:
            if index_id in self.__class__._warmed_indexes:
                return  # another caller raced through while we waited

            base = await self._resolve_base_url()
            log = logging.getLogger(__name__)
            # Fan-out sized to 4x worker count so round-robin distribution
            # statistically hits every worker at least once (not a fixed 16).
            fanout = max(workers * 4, 4)
            log.info(
                "audit_mcp_bridge: pre-warming index %s across %d workers "
                "(fan-out=%d, timeout=%.0fs)",
                index_id, workers, fanout, self.__class__._PREWARM_TIMEOUT_S,
            )

            async def _one(client: httpx.AsyncClient, tool: str) -> None:
                try:
                    await client.post(
                        f"{base}/tools/{tool}",
                        json={"index_id": index_id},
                    )
                except (httpx.ConnectError, httpx.TimeoutException,
                        httpx.ReadError):
                    pass  # best-effort

            timeout = httpx.Timeout(
                self.__class__._PREWARM_TIMEOUT_S,
                connect=10.0,
            )
            t0 = asyncio.get_event_loop().time()
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    tasks = []
                    for i in range(fanout):
                        tool = "summary" if i < fanout // 2 else "semble_stats"
                        tasks.append(_one(client, tool))
                    await asyncio.gather(*tasks, return_exceptions=True)
            except (httpx.ConnectError, RuntimeError) as exc:
                log.warning(
                    "audit_mcp_bridge: pre-warm for %s failed: %s "
                    "(proceeding; real call will surface errors)",
                    index_id, exc,
                )
            elapsed = asyncio.get_event_loop().time() - t0
            log.info(
                "audit_mcp_bridge: pre-warm of %s complete in %.1fs",
                index_id, elapsed,
            )
            self.__class__._warmed_indexes.add(index_id)

    async def _validate_kwargs(
        self,
        action: str,
        kwargs: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Validate ``kwargs`` against the live JSON Schema for ``action``.

        Returns None when the call is valid (or when validation must be
        skipped — empty catalog, unknown action). Returns a structured
        error dict suitable for direct return from ``forward()`` when
        the call would fail at audit-mcp anyway. The error message
        names the offending kwarg + the closest valid kwarg name via
        ``difflib.get_close_matches`` so the agent's next turn can
        self-correct without burning a retry.

        Skipped for actions whose schema is missing or empty — those
        are either bridge-internal pseudo-actions (``poll_task`` when
        the catalog hasn't loaded it) or genuinely unknown tools that
        the upstream server is best placed to reject.
        """
        import difflib  # noqa: PLC0415

        specs = await self.list_tool_specs()
        if not specs:
            return None
        match = next((s for s in specs if s.get("name") == action), None)
        if match is None:
            # Action not in catalog → upstream decides (typo, new tool,
            # poll_task internal action, etc.). Log a single info line
            # so unknown-action call patterns surface in worker logs
            # without blocking the call.
            logging.getLogger(__name__).info(
                "audit_mcp_bridge: action %r not in /tools catalog (%d known) — forwarding anyway",
                action, len(specs),
            )
            return None

        known_param_names = {p["name"] for p in (match.get("params") or [])}
        required = set(match.get("required") or [])

        # Unknown kwargs first — they're the loud LLM-hallucination case.
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
                f"audit_mcp.{action} rejected: unknown kwarg(s) "
                f"{', '.join(hint_parts)}. "
                f"Valid params: {valid_list}. "
                f"Required: {sorted(required)}."
            )
            logging.getLogger(__name__).warning(
                "audit_mcp_bridge: blocked %s call with unknown kwargs %s "
                "(suggestions: %s)", action, unknown, suggestions,
            )
            return {"status": "error", "error": error_msg}

        # Missing required kwargs — fail loud rather than letting
        # audit-mcp return a less actionable error.
        missing = sorted(required - set(kwargs))
        if missing:
            valid_list = sorted(known_param_names)
            error_msg = (
                f"audit_mcp.{action} rejected: missing required kwarg(s) "
                f"{missing}. Valid params: {valid_list}."
            )
            logging.getLogger(__name__).warning(
                "audit_mcp_bridge: blocked %s call missing required %s",
                action, missing,
            )
            return {"status": "error", "error": error_msg}

        return None

    # Index root cache. Maps index_id -> absolute root_path on disk.
    # Populated lazily from list_indexes; refreshed on a miss.
    _INDEX_ROOTS: dict[str, str] = {}

    async def _refresh_index_roots(self) -> None:
        """Fetch list_indexes and cache index_id -> root_path mapping."""
        base = await self._resolve_base_url()
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(f"{base}/tools/list_indexes", json={})
            data = resp.json()
        except (httpx.ConnectError, httpx.TimeoutException, ValueError) as exc:
            logging.getLogger(__name__).warning(
                "audit_mcp_bridge: list_indexes refresh failed: %s", exc,
            )
            return
        roots: dict[str, str] = {}
        for idx in (data.get("indexes") or []):
            if not isinstance(idx, dict):
                continue
            iid = idx.get("index_id")
            rp = idx.get("root_path")
            if isinstance(iid, str) and isinstance(rp, str) and iid and rp:
                roots[iid] = rp
        self.__class__._INDEX_ROOTS = roots

    async def _read_lines_local(self, kwargs: dict[str, Any]) -> dict:
        """Read lines [start, end] (1-indexed, inclusive) from a file
        in the indexed repo. Resolves index_id via list_indexes and
        reads the file directly from disk. Bypasses every audit_mcp
        indexer.

        Required kwargs: index_id, file_path, start, end.
        Optional: max_lines (cap, default 500, hard ceiling 1500).
        """
        from pathlib import Path  # noqa: PLC0415

        index_id = str(kwargs.get("index_id") or "").strip()
        file_path = str(kwargs.get("file_path") or "").strip()
        try:
            start = int(kwargs.get("start") or 0)
            end = int(kwargs.get("end") or 0)
        except (TypeError, ValueError):
            return {
                "status": "error",
                "error": "read_lines: start and end must be integers",
            }
        try:
            max_lines = int(kwargs.get("max_lines") or 500)
        except (TypeError, ValueError):
            max_lines = 500
        max_lines = min(max(1, max_lines), 1500)

        if not index_id or not file_path:
            return {
                "status": "error",
                "error": "read_lines: index_id and file_path are required",
            }
        if start < 1 or end < start:
            return {
                "status": "error",
                "error": f"read_lines: invalid range start={start} end={end} "
                          "(must be 1-indexed, end >= start)",
            }
        requested = end - start + 1
        if requested > max_lines:
            end = start + max_lines - 1

        if index_id not in self.__class__._INDEX_ROOTS:
            await self._refresh_index_roots()
        root = self.__class__._INDEX_ROOTS.get(index_id)
        if not root:
            return {
                "status": "error",
                "error": (
                    f"read_lines: unknown index_id={index_id!r}. "
                    f"Known indexes: {sorted(self.__class__._INDEX_ROOTS)}"
                ),
            }

        # Normalize file_path and ensure resolved path stays under root
        # (prevent ../../ escapes).
        rel = file_path.lstrip("/\\").replace("\\", "/")
        abs_path = (Path(root) / rel).resolve()
        root_resolved = Path(root).resolve()
        try:
            abs_path.relative_to(root_resolved)
        except ValueError:
            return {
                "status": "error",
                "error": f"read_lines: file_path escapes index root: {file_path}",
            }
        if not abs_path.is_file():
            # jadx APK decompilation emits .java only. Agent occasionally
            # guesses .kt because the original codebase is Kotlin (the
            # class names hint at it). Try the obvious extension swap
            # before failing — saves the agent a follow-up turn.
            swap_path: Path | None = None
            if abs_path.suffix == ".kt":
                swap_path = abs_path.with_suffix(".java")
            elif abs_path.suffix == ".java":
                swap_path = abs_path.with_suffix(".kt")
            if swap_path is not None and swap_path.is_file():
                # Resolved to a real file under root — proceed with the
                # swapped path but echo the original file_path in the
                # response so the caller knows what was tried.
                logging.getLogger(__name__).info(
                    "read_lines EXT_FALLBACK %s → %s",
                    abs_path.name, swap_path.name,
                )
                abs_path = swap_path
                file_path = file_path.rsplit(".", 1)[0] + abs_path.suffix
            else:
                return {
                    "status": "error",
                    "error": (
                        f"read_lines: file not found: {file_path} "
                        f"(resolved to {abs_path}). Use semantic_search to "
                        f"locate the correct path. Note: jadx decompiles "
                        f"APKs to .java only — .kt files do not exist in "
                        f"the decompiled tree."
                    ),
                }

        try:
            with abs_path.open("r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
        except OSError as exc:
            return {"status": "error", "error": f"read_lines: read failed: {exc}"}

        total = len(all_lines)
        if start > total:
            return {
                "status": "error",
                "error": f"read_lines: start={start} exceeds file length {total}",
            }
        actual_end = min(end, total)
        slice_lines = all_lines[start - 1:actual_end]
        content = "".join(slice_lines)
        return {
            "status": "ready",
            "file_path": file_path,
            "start_line": start,
            "end_line": actual_end,
            "total_lines_in_file": total,
            "content": content,
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
