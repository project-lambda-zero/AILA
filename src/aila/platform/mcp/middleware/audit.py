"""RFC-11 Tier C -- audit-mcp middleware plugin.

Verbatim port of :class:`aila.platform.mcp.bridges.audit_mcp.AuditMcpBridgeTool`
behind the :class:`McpMiddleware` protocol. The generic
:class:`aila.platform.mcp.bridge_tool.McpBridgeTool` owns the transport
via :class:`aila.platform.mcp.client.McpClient`; every server-specific
decision (kwarg alias map, prewarm fan-out, virtual ``read_lines`` tool,
heavy-tool semaphore, generic-Java-name refusal, read_function
NOT-INDEXED 4-step fallback chain, xref zero-result enrichment, status
injection) lives here so the transport can collapse.

Behaviour-preservation contract: the only thing that changed relative
to the pre-Tier-C bridge is the transport hop -- every raw ``httpx``
call is replaced by :meth:`McpClient.post` (with ``ctx`` for the one
recorded call and ``ctx=None`` for prewarm / fallback / poll fan-out).
Return-dict shapes, error strings, ``_bridge_note`` / ``_bridge_policy``
markers, class-level TTL cache, per-instance prewarm registry, alias
map, and semaphore caps are byte-for-byte the bridge's.
"""
from __future__ import annotations

import asyncio
import difflib
import logging
import os
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aila.platform.mcp.middleware._kwarg_alias import (
    build_alias_map,
    build_known_params,
    drop_unknown_pagination_kwargs,
    normalize_kwargs,
)

if TYPE_CHECKING:
    from aila.platform.mcp.client import McpClient
    from aila.platform.mcp.server_specs import ServerSpec

__all__ = ["AuditMcpMiddleware"]

_log = logging.getLogger(__name__)


# ── Module-level constants + helpers (verbatim from the bridge) ───────


# Tools that walk the call graph. Used by forward() to apply the
# zero-result auto-suggestion: if any of these returns 0 results, the
# middleware appends a `_bridge_note` field with diagnostic guidance
# and nearest-name suggestions so the agent doesn't walk away thinking
# "no edges = no bug here" when the real cause is an indexer miss.
_XREF_ACTIONS: frozenset[str] = frozenset({
    "callers_of", "callees_of", "ancestors_of", "reachable_from",
})

# xref tools whose audit-mcp signature accepts ``include_virtual``
# (direct callers/callees only; the transitive ancestors_of /
# reachable_from walk the resolved adjacency and do not take the flag).
# The middleware forces it on so a call-graph query surfaces callers
# that reach the target through an unresolved receiver expression
# (``this.field.method``) -- interface / DI dispatch that the parser
# could not bind to a concrete node.
_VIRTUAL_ACTIONS: frozenset[str] = frozenset({"callers_of", "callees_of"})


# JADX p-prefix rewriter -- see _resolve_jadx_prefixes docstring.
_JADX_PREFIX_RE = re.compile(r"^p[0-9A-F]+(.+)$")


def _resolve_jadx_prefixes(root: Path, file_path: str) -> Path | None:
    """Walk ``file_path`` through ``root`` adding JADX p-prefixes where
    needed. Returns the resolved absolute Path if every segment maps
    to a real on-disk entry, otherwise None.

    JADX rewrites package segments that collide with Java keywords,
    digits, or its own internal rules by prefixing them with
    ``p<smali_line_number_hex>``:

      ``ui`` -> ``p182ui`` (most common -- every Android app)
      ``do`` -> ``p23do`` (Java keyword)
      ``if`` -> ``p17if`` (Java keyword)
      ``2D`` -> ``p9C2D`` (leading digit)

    The renaming is per-class and the line-number portion is
    deterministic but un-derivable from outside JADX itself. So we
    walk the path: at each segment, if the literal name doesn't
    resolve, scan the parent's children for any directory matching
    ``p[0-9A-F]+<requested-name>``. If exactly one matches, use it
    and continue walking. If zero or multiple match, give up.
    """
    parts = [p for p in file_path.replace("\\", "/").split("/") if p]
    cursor = root
    for part in parts:
        candidate = cursor / part
        try:
            if candidate.exists():
                cursor = candidate
                continue
            if not cursor.is_dir():
                return None
            matches = [
                entry for entry in cursor.iterdir()
                if entry.name.endswith(part)
                and _JADX_PREFIX_RE.match(entry.name)
            ]
        except OSError as exc:
            _log.warning(
                "_resolve_jadx_prefixes: iterdir FAILED for %s: %s",
                cursor, exc,
            )
            return None
        if len(matches) != 1:
            return None
        cursor = matches[0]
    return cursor


# Bounded whole-tree basename fallback -- see _search_by_basename.
#
# Prunes trees that never carry indexed source: VCS metadata, package
# manager caches, Python bytecode caches, and JADX ``resources/``
# mirror (which is reached via the RESOURCES_FALLBACK path in
# _read_lines_local, not via the basename walker).
_WALK_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", "__pycache__", ".svn", ".hg", "resources",
})


def _search_by_basename(
    root: Path, leaf: str, *, cap: int = 12, max_scan: int = 60000,
) -> list[str]:
    """Bounded ``os.walk`` under ``root`` collecting repo-relative POSIX
    paths whose basename equals ``leaf``.

    Prunes :data:`_WALK_SKIP_DIRS` in place so heavy trees (npm
    dependencies, VCS metadata, JADX ``resources/`` mirror) don't
    balloon the scan. Stops at ``cap`` matches or after scanning
    ``max_scan`` files -- guaranteed bounded so a browser-sized index
    (~500k+ files) can never hang the fallback. Wraps the walk in
    ``except OSError`` and returns whatever was already collected on
    failure. Empty ``leaf`` short-circuits to ``[]``.
    """
    if not leaf:
        return []
    root_str = str(root)
    matches: list[str] = []
    scanned = 0
    try:
        for dirpath, dirnames, filenames in os.walk(root_str):
            dirnames[:] = [d for d in dirnames if d not in _WALK_SKIP_DIRS]
            for name in filenames:
                scanned += 1
                if name == leaf:
                    rel = os.path.relpath(
                        os.path.join(dirpath, name), root_str,
                    ).replace("\\", "/")
                    matches.append(rel)
                    if len(matches) >= cap:
                        return matches
                if scanned >= max_scan:
                    return matches
    except OSError as exc:
        _log.warning(
            "_search_by_basename: walk aborted at %s (leaf=%r): %s",
            root, leaf, exc,
        )
    return matches


def _looks_like_jadx(root: Path) -> bool:
    """Return True iff ``root`` looks like a JADX / Android decompile.

    JADX writes decompiled Java/Kotlin under ``sources/`` and Android
    resources under ``resources/``; the operator may index either the
    workdir root (both dirs one level down) or ``sources/`` itself
    (p-prefixed package dirs as direct children). Any of those three
    signals -- ``resources/``, ``sources/``, or a child dir matching
    :data:`_JADX_PREFIX_RE` -- flips this to True at ``root`` or one
    level down. On ``OSError`` (unreadable root) return False rather
    than propagating; the JADX package-rename sentence is a hint, not
    a correctness gate.
    """

    def _child_signals_jadx(entry: Path) -> bool:
        name = entry.name
        if name in ("resources", "sources"):
            return True
        return bool(_JADX_PREFIX_RE.match(name))

    try:
        for entry in root.iterdir():
            if not entry.is_dir():
                continue
            if _child_signals_jadx(entry):
                return True
            # One level down.
            try:
                for sub in entry.iterdir():
                    if not sub.is_dir():
                        continue
                    if _child_signals_jadx(sub):
                        return True
            except OSError as exc:
                _log.debug(
                    "_looks_like_jadx: iterdir failed for %s: %s",
                    entry, exc,
                )
                continue
    except OSError as exc:
        _log.debug(
            "_looks_like_jadx: iterdir failed for %s: %s", root, exc,
        )
        return False
    return False


def _suggest_nearest_paths(
    root: Path, file_path: str, max_suggestions: int = 6,
) -> list[str]:
    """Build a 'did you mean' list by walking back to the deepest
    existing ancestor and returning its children whose name shares
    the leaf basename (with JADX p-prefix stripped for fuzzy match).
    """
    parts = [p for p in file_path.replace("\\", "/").split("/") if p]
    leaf = parts[-1] if parts else ""
    leaf_stem = leaf.rsplit(".", 1)[0]
    # Walk back until we find an existing ancestor.
    cursor = root
    consumed: list[str] = []
    for part in parts[:-1]:
        candidate = cursor / part
        try:
            if candidate.is_dir():
                cursor = candidate
                consumed.append(part)
                continue
            # Try p-prefix fuzzy.
            if cursor.is_dir():
                matches = [
                    e for e in cursor.iterdir()
                    if e.name.endswith(part)
                    and _JADX_PREFIX_RE.match(e.name)
                ]
                if len(matches) == 1:
                    cursor = matches[0]
                    consumed.append(matches[0].name)
                    continue
        except OSError as exc:
            _log.debug(
                "_suggest_nearest_paths: walk failed at %s: %s", cursor, exc,
            )
        break
    # Scan cursor's children for fuzzy-match on the leaf.
    suggestions: list[str] = []
    try:
        if cursor.is_dir():
            for entry in cursor.iterdir():
                name = entry.name
                stem = name.rsplit(".", 1)[0]
                # Direct match, prefix-stripped match, or substring.
                m = _JADX_PREFIX_RE.match(stem)
                stripped = m.group(1) if m else stem
                if (
                    name == leaf
                    or stem == leaf_stem
                    or stripped == leaf_stem
                    or leaf_stem.lower() in name.lower()
                ):
                    rel = "/".join([*consumed, name])
                    suggestions.append(rel)
                    if len(suggestions) >= max_suggestions:
                        break
    except OSError as exc:
        _log.debug(
            "_suggest_nearest_paths: iterdir failed for %s: %s", cursor, exc,
        )
    return suggestions


# Method names that exist on dozens-to-hundreds of classes in any
# typical Android / Java codebase. read_function with one of these as
# the bare name has no way to disambiguate against the function index.
# The middleware refuses the call BEFORE the HTTP roundtrip + tells
# the agent to use search_functions(pattern=...) or extract_class
# instead. Observed live on the SampleApp audit: 100% of recent
# read_function-not-indexed errors were name='init', 857 wasted
# attempts in 48h across 80 distinct branches.
_GENERIC_JAVA_NAMES: frozenset[str] = frozenset({
    # Constructors + lifecycle
    "init", "<init>", "<clinit>",
    "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
    "onAttach", "onDetach", "onActivityCreated", "onActivityResult",
    "onConfigurationChanged", "onSaveInstanceState", "onRestoreInstanceState",
    "onNewIntent", "onBackPressed", "onCreateView", "onViewCreated",
    # Common entry points / overrides
    "main", "run", "start", "stop", "close", "dispose", "shutdown",
    "apply", "call", "execute", "perform", "invoke", "handle",
    # Object overrides
    "toString", "equals", "hashCode", "clone", "finalize",
    # Generic getters/setters
    "get", "set", "getValue", "setValue", "getId", "setId",
    # Coroutine / reactive
    "subscribe", "unsubscribe", "next", "onNext", "onComplete", "onError",
    "emit", "collect", "flow",
    # Common Android callback names
    "onClick", "onLongClick", "onCheckedChanged", "onItemClick",
    "onItemSelected", "onTextChanged", "afterTextChanged",
    "beforeTextChanged", "onFocusChange", "onTouch",
    # JSON / parcel / serialize
    "fromJson", "toJson", "readFromParcel", "writeToParcel",
    "describeContents", "serialize", "deserialize",
})


def _looks_like_class_basename(name: str, file_path: str) -> bool:
    """True iff ``name`` looks like the class declared in ``file_path``.

    Heuristic for the class-rewrite auto-fallback in read_function:
    Java + Kotlin convention is one top-level public class per file,
    named identically to the file basename. So when the agent asks
    for ``read_function(name="UcsLib", file_path=".../UcsLib.java")``,
    name == file basename without extension is a near-certain signal
    that the agent meant "give me the class" rather than "give me a
    method called UcsLib".

    Conservative: requires PascalCase first char so we don't rewrite
    legitimately-failed method lookups like
    ``read_function(name="checkNativeLibrary", file_path="...UcsLib.java")``
    where the method actually exists in the file but the indexer
    didn't catch it. False on lowercase names, names with parens,
    names with dots, names not matching the basename.
    """
    if not name or not file_path:
        return False
    if not name[0].isupper():
        return False
    if any(c in name for c in "().<> "):
        return False
    # Extract basename without extension. Handle both / and \.
    bare = file_path.replace("\\", "/").rsplit("/", 1)[-1]
    stem = bare.rsplit(".", 1)[0] if "." in bare else bare
    return name == stem


# ── Middleware plugin ────────────────────────────────────────────────


class AuditMcpMiddleware:
    """audit-mcp server behaviour layered over :class:`McpClient`.

    Implements :class:`aila.platform.mcp.middleware.McpMiddleware`. Every
    per-call decision -- kwarg normalisation, generic-name refusal,
    virtual ``read_lines`` dispatch, prewarm fan-out, heavy-tool
    semaphore, read_function fallback chain, xref zero-result
    enrichment, status injection -- is ported verbatim from
    ``AuditMcpBridgeTool``. Only the transport call site changed:
    ``await client.post(action, payload, ctx=ctx)`` for the primary
    recorded call, ``await client.post(action, payload)`` (no ctx) for
    every prewarm / fallback / helper hop so exactly one audit row is
    written per ``forward`` call.
    """

    # ── LLM kwarg synonym map ─────────────────────────────────────────
    #
    # See ``_kwarg_alias.py`` for the algorithm. Families are
    # intentionally tight: ``path`` and ``file_path`` are NOT the same
    # intent (repo root vs. one file), so they stay separate.
    # ``query`` (natural-language) and ``pattern`` (regex) are also
    # distinct. ``depth`` is kept separate from the how_many family
    # because tools like ``ancestors_of`` and ``paths_between`` take
    # BOTH at once.
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

    # fix #195 -- canonical params per action, used by
    # ``drop_unknown_pagination_kwargs`` to strip pagination-style kwargs
    # (limit / offset / page / cursor / count) that an agent attaches
    # to audit-mcp tools that do not declare them (attack_surface,
    # complexity_hotspots, ...). Without this drop, the kwargs reach
    # validation and burn a full agent turn as ``unknown parameter``.
    # ``ida.py`` already applied this drop; ``audit.py`` was missing
    # it, so agents tuned to IDA's forgiving behaviour incurred an
    # extra error cycle on every audit-mcp call. Populated by
    # ``list_tool_specs()`` from the live catalog alongside
    # ``_AUTO_ALIAS_MAP``.
    _KNOWN_PARAMS: dict[str, frozenset[str]] = {}

    # ── Schema-driven tool catalog ────────────────────────────────────
    #
    # The MCP server exposes the full JSON Schema for every tool via
    # GET /tools. Fetch once per process, hand the parsed form to the
    # prompt builder. Cache TTL: audit-mcp restarts can ship new tools
    # / renamed kwargs. Without a TTL, the first-startup schema stays
    # stuck until AILA restarts. 300s matches operator-observable
    # "I just restarted audit-mcp, when do schemas refresh?" latency.
    _SPEC_CACHE: list[dict[str, Any]] | None = None
    _SPEC_CACHE_TTL_S: float = 300.0
    _SPEC_CACHE_FETCHED_AT: float | None = None

    # Index root cache. Maps index_id -> absolute root_path on disk.
    # Populated lazily from list_indexes; refreshed on a miss.
    _INDEX_ROOTS: dict[str, str] = {}

    # Per-tool concurrency caps. The `fuzzing_targets` /
    # `complexity_hotspots` / `attack_surface` / `preanalysis` /
    # `dead_code` calls walk the entire index call-graph and allocate
    # ~67 MiB float32 slabs per batch. Concurrent fan-out piles slabs
    # onto a fragmented Python heap and audit-mcp OOMs. A bounded
    # semaphore per heavy tool caps in-flight so peak resident memory
    # stays at cap * slab_size instead of N * slab_size.
    #
    # ``semantic_search`` joins the heavy list because semble's dense
    # backend materialises a (embedding_dim x N_chunks) float64
    # similarity matrix per query. Cheap tools (read_function,
    # read_lines, search_functions, callers_of) stay unbounded.
    _HEAVY_TOOL_CAPS: dict[str, int] = {
        "fuzzing_targets":     2,
        "complexity_hotspots": 2,
        "attack_surface":      3,
        "preanalysis":         3,
        "dead_code":           2,
        "scan_and_correlate":  2,
        "blast_radius_batch":  2,
        "semantic_search":     3,
    }
    _TOOL_SEMAPHORES: dict[str, asyncio.BoundedSemaphore] = {}

    # Per-index pre-warm fan-out sizing (used by ``_ensure_prewarmed``).
    _PREWARM_FANOUT: int = 16
    _PREWARM_TIMEOUT_S: float = 90.0

    def __init__(self, *, spec: ServerSpec, module_id: str) -> None:
        self.server_id = spec.server_id
        self.tool_name = spec.tool_name
        self.env_var = spec.env_var
        self.config_key = spec.config_key
        self.default_url = spec.default_url
        self.persistent_pool = spec.persistent_pool
        self.default_timeout = float(
            os.environ.get("AUDIT_MCP_TIMEOUT", spec.default_timeout),
        )
        self.module_id = module_id
        # Per-instance prewarm registry -- class-level storage leaked
        # across instances (tests saw stale state) and grew monotonically
        # in long-running workers (one entry per index_id, never
        # reclaimed).
        self._warmed_indexes: set[str] = set()
        self._warm_locks: dict[str, asyncio.Lock] = {}

    # ── Kwarg normalisation ───────────────────────────────────────────

    @classmethod
    def _normalize_kwargs(
        cls, action: str, kwargs: dict[str, Any],
    ) -> tuple[dict[str, Any], list[str]]:
        """Alias-resolve, then strip pagination kwargs the tool doesn't declare.

        fix #195 -- mirrors ``ida.py``: alias renaming ->
        :func:`drop_unknown_pagination_kwargs`. When ``_KNOWN_PARAMS``
        is still empty (first call before ``list_tool_specs`` populated
        it), the drop step is a no-op and the caller sees only the
        alias-resolver output, preserving prior behaviour on cold
        start.
        """
        renamed, alias_notes = normalize_kwargs(
            action, kwargs, cls._AUTO_ALIAS_MAP,
        )
        if not cls._KNOWN_PARAMS:
            return renamed, alias_notes
        filtered, drop_notes = drop_unknown_pagination_kwargs(
            action, renamed, cls._KNOWN_PARAMS,
        )
        return filtered, alias_notes + drop_notes

    # ── Heavy-tool semaphore ──────────────────────────────────────────

    @classmethod
    def _tool_semaphore(cls, tool: str) -> asyncio.BoundedSemaphore | None:
        """Return the bounded semaphore for ``tool`` if it's heavy.

        Lazy-instantiated per tool name. Returns None for tools that
        aren't in the heavy list so the caller can skip the
        ``async with`` cleanly. Class-level so every middleware
        instance in the worker process shares the cap (one
        investigation can't bypass by constructing a fresh middleware).
        """
        cap = cls._HEAVY_TOOL_CAPS.get(tool)
        if cap is None:
            return None
        sem = cls._TOOL_SEMAPHORES.get(tool)
        if sem is None:
            sem = asyncio.BoundedSemaphore(cap)
            cls._TOOL_SEMAPHORES[tool] = sem
        return sem

    # ── Public middleware surface ─────────────────────────────────────

    async def forward(
        self,
        client: McpClient,
        action: str | None,
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Dispatch one agent tool call through the audit-mcp middleware."""
        if not action:
            return await self._list_tools(client)
        # Bridge-side virtual tools -- handled locally without HTTP.
        # ``read_lines`` resolves index_id -> root_path via list_indexes
        # and slices the file from disk. Bypasses semble chunking and
        # every broken indexer. NO recorder row: the read is local.
        if action == "read_lines":
            return await self._read_lines_local(client, kwargs)

        normalized_kwargs, kw_notes = self._normalize_kwargs(action, kwargs)
        for note in kw_notes:
            _log.info("audit_mcp_bridge %s", note)

        # Local kwarg validation against the live JSON Schema. Catches
        # LLM-hallucinated args and returns a structured "did you mean"
        # error before the HTTP round-trip. Skipped for poll_task /
        # unknown actions where the cache is empty or the action isn't
        # in the schema catalog.
        validation_error = await self._validate_kwargs(
            client, action, normalized_kwargs,
        )
        if validation_error is not None:
            return validation_error

        # Generic-name pre-refuse for read_function. Turns a retryable
        # error into a "use a different tool" terminal response so the
        # agent doesn't loop 800+ times on ``name='init'``.
        if action == "read_function":
            requested_name = normalized_kwargs.get("name") or ""
            if (
                isinstance(requested_name, str)
                and requested_name.strip() in _GENERIC_JAVA_NAMES
            ):
                clean = requested_name.strip()
                return {
                    "status": "error",
                    "error": (
                        f"audit_mcp.read_function rejected: {clean!r} is a "
                        f"generic Java method/constructor name that exists "
                        f"on hundreds of classes in any Android app -- the "
                        f"function index can't disambiguate. Possible "
                        f"next moves:\n"
                        f"  (1) audit_mcp.search_functions(pattern='\\\\b{clean}\\\\b') "
                        f"to enumerate every class that defines {clean};\n"
                        f"  (2) audit_mcp.extract_class(file_path=...) when "
                        f"you already know which class's {clean} you want;\n"
                        f"  (3) audit_mcp.read_lines(file_path=..., start=, end=) "
                        f"to read the body directly.\n"
                        f"Do NOT retry read_function with the bare name "
                        f"{clean!r} -- the result will be identical."
                    ),
                    "_bridge_policy": "generic_name_blocked",
                }

        # Force interface/DI-dispatch resolution on for direct call-graph
        # queries. audit-mcp defaults include_virtual=True server-side;
        # set it explicitly so behaviour is pinned regardless of server
        # default drift. The agent can still pass include_virtual=False
        # for strictly statically-resolved edges.
        if (
            action in _VIRTUAL_ACTIONS
            and "include_virtual" not in normalized_kwargs
        ):
            normalized_kwargs["include_virtual"] = True

        # Prewarm fan-out: first call per index_id per instance fires
        # cheap parallel requests so every audit_mcp worker pre-loads
        # the engine + semble caches. Subsequent calls are no-ops.
        index_id = normalized_kwargs.get("index_id")
        if isinstance(index_id, str) and index_id:
            await self._ensure_prewarmed(client, index_id)

        # One recorded call per forward. Heavy-tool semaphore held
        # across the POST + JSON parse -- released before the response
        # processing below runs unbounded.
        async with client.recorder_context(action) as ctx:
            sem = self.__class__._tool_semaphore(action)
            if sem is not None:
                await sem.acquire()
            try:
                payload = await client.post(
                    action, normalized_kwargs, ctx=ctx,
                )
            finally:
                if sem is not None:
                    sem.release()

            if ctx.get("status") == "error" and isinstance(payload, dict):
                err = payload.get("error")
                if isinstance(err, str):
                    # Auto-fallback: when read_function reports
                    # "not indexed", chain: (1) class-rewrite via
                    # _read_lines_local; (2) bare-name retry via
                    # client.post no-ctx; (3) file fallback via
                    # _read_lines_local; (4) semantic_search fallback
                    # via client.post no-ctx; (5) nearest-name
                    # suggestions appended to the error string.
                    if (
                        action == "read_function"
                        and "not indexed" in err.lower()
                        and isinstance(normalized_kwargs.get("name"), str)
                    ):
                        name = str(normalized_kwargs["name"])
                        file_hint = str(
                            normalized_kwargs.get("file_path") or "",
                        )
                        # (1) Class-rewrite. Java + Kotlin convention:
                        # one top-level public class per file, named
                        # like the basename. Agent asks for
                        # read_function(name="<Class>") -- rewrite to
                        # read_lines(file, 1, 300) and return the
                        # class source as if it were a function body.
                        if (
                            file_hint
                            and _looks_like_class_basename(name, file_hint)
                        ):
                            rewrite_kwargs = {
                                "index_id": (
                                    normalized_kwargs.get("index_id") or ""
                                ),
                                "file_path": file_hint,
                                "start": 1,
                                "end": 300,
                            }
                            rewrite_result = await self._read_lines_local(
                                client, rewrite_kwargs,
                            )
                            if rewrite_result.get("status") == "ready":
                                _log.info(
                                    "read_function CLASS_REWRITE %r -> "
                                    "read_lines(%s, 1-300)",
                                    name, file_hint,
                                )
                                total_lines = rewrite_result.get(
                                    "total_lines_in_file", 0,
                                )
                                ctx["status"] = "ready"
                                return {
                                    "status": "ready",
                                    "name": name,
                                    "file_path": file_hint,
                                    "start_line": 1,
                                    "end_line": rewrite_result.get(
                                        "end_line", 0,
                                    ),
                                    "total_lines_in_file": total_lines,
                                    "content": rewrite_result.get(
                                        "content", "",
                                    ),
                                    "_bridge_note": (
                                        f"{name!r} is a CLASS, not a "
                                        f"function -- audit-mcp's function "
                                        f"index does not track class "
                                        f"containers. Auto-rewrote to "
                                        f"read_lines(file_path={file_hint!r}, "
                                        f"start=1, end=300) and returned the "
                                        f"class source below. To inspect a "
                                        f"specific method INSIDE this class, "
                                        f"call read_function with the method "
                                        f"name (e.g. checkNativeLibrary, "
                                        f"decryptKek) OR read_lines with a "
                                        f"specific line range. If the file is "
                                        f"larger than 300 lines, call "
                                        f"read_lines again with start=301."
                                    ),
                                }
                        # (2) Bare-name auto-retry. Agents routinely
                        # over-qualify names as ``Class.method`` /
                        # ``Class::method`` / ``Class#method``.
                        # trailmark keys on the BARE method name;
                        # retry once with the tail after the last
                        # separator and return the body if it resolves.
                        bare = name
                        for _sep in (".", "::", "#"):
                            if _sep in bare:
                                bare = bare.split(_sep)[-1]
                        bare = bare.strip()
                        if (
                            bare
                            and bare != name
                            and bare not in _GENERIC_JAVA_NAMES
                        ):
                            retry_kwargs = dict(normalized_kwargs)
                            retry_kwargs["name"] = bare
                            _rpayload = await client.post(
                                action, retry_kwargs,
                            )
                            if (
                                isinstance(_rpayload, dict)
                                and _rpayload.get("status") == "ready"
                            ):
                                _log.info(
                                    "read_function BARE_RETRY %r -> %r "
                                    "resolved", name, bare,
                                )
                                _rpayload["_bridge_note"] = (
                                    f"{name!r} was not indexed; "
                                    f"auto-resolved to the bare method "
                                    f"name {bare!r}. Use {bare!r} (no "
                                    f"class prefix) with read_function "
                                    f"-- the function index keys on "
                                    f"bare names."
                                )
                                ctx["status"] = "ready"
                                return _rpayload
                        # (3) File fallback. With a file_path, read
                        # the region from disk (bypasses the indexer).
                        if file_hint:
                            fb = await self._read_lines_local(client, {
                                "index_id": (
                                    normalized_kwargs.get("index_id") or ""
                                ),
                                "file_path": file_hint,
                                "start": 1,
                                "end": 400,
                            })
                            if fb.get("status") == "ready":
                                _log.info(
                                    "read_function NOT_INDEXED_FALLBACK "
                                    "%r -> read_lines(%s, 1-400)",
                                    name, file_hint,
                                )
                                ctx["status"] = "ready"
                                return {
                                    "status": "ready",
                                    "name": name,
                                    "file_path": file_hint,
                                    "start_line": 1,
                                    "end_line": fb.get("end_line", 0),
                                    "total_lines_in_file": fb.get(
                                        "total_lines_in_file", 0,
                                    ),
                                    "content": fb.get("content", ""),
                                    "_bridge_note": (
                                        f"{name!r} is not in the function "
                                        f"index. Auto-read {file_hint!r} "
                                        f"lines 1-400 from disk. Search "
                                        f"this content for the body; call "
                                        f"read_lines for a wider window "
                                        f"if it runs past line 400."
                                    ),
                                }
                        # (4) Semantic-search fallback. Without a
                        # file_hint but with an index_id, ask
                        # semantic_search for the top match by name.
                        elif normalized_kwargs.get("index_id"):
                            ss_kwargs = {
                                "index_id": normalized_kwargs["index_id"],
                                "query": name,
                                "top_k": 3,
                            }
                            _spayload = await client.post(
                                "semantic_search", ss_kwargs,
                            )
                            _results = (
                                _spayload.get("results")
                                if isinstance(_spayload, dict) else None
                            )
                            if isinstance(_results, list) and _results:
                                _top = _results[0]
                                _log.info(
                                    "read_function NOT_INDEXED_FALLBACK "
                                    "%r -> semantic_search top result",
                                    name,
                                )
                                ctx["status"] = "ready"
                                return {
                                    "status": "ready",
                                    "name": name,
                                    "file_path": _top.get("file_path") or "?",
                                    "start_line": (
                                        _top.get("start_line") or 0
                                    ),
                                    "end_line": _top.get("end_line") or 0,
                                    "content": (
                                        _top.get("content")
                                        or _top.get("body")
                                        or ""
                                    ),
                                    "_bridge_note": (
                                        f"{name!r} is not in the function "
                                        f"index. Auto-fell back to "
                                        f"semantic_search; showing the top "
                                        f"match. Use read_lines for a wider "
                                        f"window."
                                    ),
                                }
                        # (5) Nearest-name suggestions.
                        suggestions = await self._suggest_function_names(
                            client,
                            index_id=(
                                normalized_kwargs.get("index_id") or ""
                            ),
                            name=name,
                        )
                        if suggestions:
                            payload["error"] = (
                                f"{err}\n\nNEAREST INDEXED FUNCTION NAMES "
                                f"(use one of these with read_function, OR "
                                f"if none matches, the symbol genuinely "
                                f"does NOT exist in this codebase -- STOP "
                                f"trying this name and pivot to "
                                f"semantic_search):\n"
                                + "\n".join(f"  - {s}" for s in suggestions)
                            )

            # Zero-result enrichment for xref tools. Without a hint the
            # agent treats "no callers" as "no bug here"; append both
            # possibilities (hallucinated name vs indexer miss) + the
            # nearest-name suggestions so the next turn knows whether
            # to fix the name or fall back to read_function.
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
                        client,
                        index_id=(
                            normalized_kwargs.get("index_id") or ""
                        ),
                        name=str(normalized_kwargs["name"]),
                    )
                    virt = action in _VIRTUAL_ACTIONS
                    note_lines = [
                        f"audit_mcp.{action}"
                        f"({normalized_kwargs['name']!r}) "
                        f"returned 0 results"
                        + (
                            " (interface / DI-dispatch name-matching was "
                            "already applied)" if virt else ""
                        )
                        + ". Likely causes:",
                        "  (a) the symbol does not exist in this index "
                        "(hallucinated name, or in a sibling repo not "
                        "indexed alongside the primary target);",
                        "  (b) the call site exists in source but the "
                        "parser dropped the edge entirely -- e.g. a call "
                        "through a qualified-this receiver in a nested / "
                        "anonymous class or a coroutine state machine, "
                        "which no call-graph query can surface. Confirm "
                        "textually with search_source(pattern=r'\\."
                        + str(normalized_kwargs['name'])
                        + r"\s*\(') or read the suspected caller with "
                        "read_lines(). Do NOT treat 0 callers as proof "
                        "of dead code on an Android / Kotlin target.",
                    ]
                    if suggestions:
                        note_lines.append(
                            "NEAREST INDEXED FUNCTION NAMES:",
                        )
                        note_lines.extend(f"  - {s}" for s in suggestions)
                    payload["_bridge_note"] = "\n".join(note_lines)

            # audit-mcp tools return clean payloads WITHOUT a top-level
            # ``status`` field (e.g. search_functions returns
            # ``{"matches": [...], "total": N}``). The consumer keys
            # success off ``raw.get("status")`` in _SUCCESS_STATUSES
            # and treats missing status as error. Inject the
            # normalised status so the consumer sees the right shape
            # regardless of which audit-mcp tool produced the payload.
            if isinstance(payload, dict) and "status" not in payload:
                payload["status"] = ctx.get("status") or "ready"
            return payload

    async def list_tool_specs(
        self, client: McpClient,
    ) -> list[dict[str, Any]]:
        """Fetch + project + augment the audit-mcp tool catalogue.

        Class-level TTL cache (300s). On fetch failure with a prior
        cache, back off TTL by 30s so the next call retries sooner
        (better stale than empty); flatten to ``[]`` only when no
        prior cache existed. Injects the bridge-side virtual
        ``read_lines`` spec. Derives ``_AUTO_ALIAS_MAP`` from the live
        catalog for the shared normaliser.
        """
        cls = self.__class__
        now = time.monotonic()
        cached_at = cls._SPEC_CACHE_FETCHED_AT
        if (
            cls._SPEC_CACHE is not None
            and cached_at is not None
            and (now - cached_at) < cls._SPEC_CACHE_TTL_S
        ):
            return cls._SPEC_CACHE
        if cls._SPEC_CACHE is not None and cached_at is not None:
            _log.info(
                "audit_mcp_bridge: schema cache stale (%.0fs old, TTL "
                "%.0fs) -- refetching",
                now - cached_at, cls._SPEC_CACHE_TTL_S,
            )
        # Force the transport client to refetch: middleware owns the
        # TTL policy, but the transport keeps a per-instance one-shot
        # cache. Without dropping it here, a stale [] on the client
        # (fetch failed once) would be re-served for the client's
        # lifetime and the middleware's TTL retry would never see
        # fresh data.
        client.invalidate_spec_cache()
        fetched = await client.list_tool_specs()
        if not fetched:
            # Transport failure OR truly empty catalog. Keep any prior
            # cache (better stale than empty) and back off TTL so we
            # retry sooner. Only flatten to [] when we never had a
            # cache to begin with.
            if cls._SPEC_CACHE is None:
                cls._SPEC_CACHE = []
                cls._SPEC_CACHE_FETCHED_AT = now
            else:
                cls._SPEC_CACHE_FETCHED_AT = (
                    now - (cls._SPEC_CACHE_TTL_S - 30.0)
                )
            return cls._SPEC_CACHE
        # Fresh fetch OK. Copy so we don't mutate the transport's
        # cache with our virtual-tool injection.
        augmented = list(fetched)
        # Inject the middleware-side virtual ``read_lines`` tool.
        # audit_mcp doesn't ship this; we resolve index_id ->
        # root_path locally and read the file slice from disk. The
        # agent sees it in the tool catalog and calls it like any
        # other audit_mcp tool.
        augmented.append({
            "name": "read_lines",
            "description": (
                "Read a verbatim slice of source from a file in the "
                "indexed repo. Bypasses every audit_mcp indexer -- "
                "gives you EXACTLY the lines you ask for. Use this "
                "when you know the file path and the line range you "
                "need to verify (e.g. after a semantic_search hit "
                "gave you the neighborhood). Lines are 1-indexed "
                "inclusive. Hard ceiling 1500 lines per call; "
                "default max 500."
            ),
            "params": [
                {
                    "name": "index_id", "type": "string",
                    "required": True,
                },
                {
                    "name": "file_path", "type": "string",
                    "required": True,
                    "description": (
                        "path relative to repo root (e.g. "
                        "src/http/v3/ngx_http_v3_filter_module.c)"
                    ),
                },
                {
                    "name": "start", "type": "integer", "required": True,
                    "description": "1-indexed start line (inclusive)",
                },
                {
                    "name": "end", "type": "integer", "required": True,
                    "description": "1-indexed end line (inclusive)",
                },
                {
                    "name": "max_lines", "type": "integer",
                    "required": False,
                    "description": (
                        "cap on returned lines (default 500, max 1500)"
                    ),
                },
            ],
            "required": ["index_id", "file_path", "start", "end"],
        })
        cls._SPEC_CACHE = augmented
        cls._SPEC_CACHE_FETCHED_AT = now
        cls._AUTO_ALIAS_MAP = build_alias_map(
            cls._SPEC_CACHE, cls._KW_FAMILIES, cls._MANUAL_OVERRIDES,
        )
        # fix #195 -- known-params index feeds
        # ``drop_unknown_pagination_kwargs`` in ``_normalize_kwargs``.
        cls._KNOWN_PARAMS = build_known_params(cls._SPEC_CACHE)
        _log.info(
            "audit_mcp_bridge: catalog loaded -- %d tools, %d with "
            "alias maps",
            len(cls._SPEC_CACHE), len(cls._AUTO_ALIAS_MAP),
        )
        return cls._SPEC_CACHE

    # ── Internal helpers ──────────────────────────────────────────────

    async def _list_tools(self, client: McpClient) -> dict[str, Any]:
        """Return available audit-mcp tool names + schemas."""
        specs = await self.list_tool_specs(client)
        return {
            "status": "ready",
            "tools": [s["name"] for s in specs],
            "count": len(specs),
            "specs": specs,
        }

    async def _suggest_function_names(
        self, client: McpClient, *, index_id: str, name: str,
    ) -> list[str]:
        """Return up to 5 indexed function names nearest to ``name``.

        Fires search_functions with a permissive prefix pattern (just
        the first 4-6 chars of the queried name) so the agent sees
        candidates even when its hallucinated name shares only a stem
        with anything real. Best-effort: empty list on any error.
        """
        if not index_id or not name:
            return []
        # Take the longest unambiguous prefix -- drop trailing
        # CamelCase tail. ``ensureStrBuf`` becomes ``ensureStrB`` then
        # ``ensureS`` and finally ``ensure`` so search_functions finds
        # appendStrBuf, emitStrBuf, etc. via the StrBuf stem.
        candidates: list[str] = []
        seen: set[str] = set()
        probes = [name, name[:6], name[:4]]
        # Add CamelCase-stem variants: 'ensureStrBuf' -> 'StrBuf'
        camel_parts = re.findall(r"[A-Z][a-z]+", name)
        probes.extend(camel_parts[-2:])
        for pattern in probes:
            if not pattern or len(pattern) < 3:
                continue
            body = await client.post(
                "search_functions",
                {"index_id": index_id, "pattern": pattern, "limit": 8},
                timeout=15.0,
            )
            if not isinstance(body, dict):
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
        return candidates

    async def _ensure_prewarmed(
        self, client: McpClient, index_id: str,
    ) -> None:
        """Fan out lightweight calls so every audit_mcp worker
        pre-loads the engine + semble caches for ``index_id``, exactly
        once per process per index. Subsequent calls are no-ops.

        Skipped entirely when ``AUDIT_MCP_WORKERS<=1`` -- 16 parallel
        calls onto a single GIL-bound worker just multiply the
        workload without warming anything else.

        Errors are swallowed by design: warming is best-effort. If
        audit-mcp is down or the index is broken, the real call that
        follows will surface the proper error.
        """
        if index_id in self._warmed_indexes:
            return
        workers = int(os.environ.get("AUDIT_MCP_WORKERS", "1") or "1")
        if workers <= 1:
            self._warmed_indexes.add(index_id)
            _log.info(
                "audit_mcp_bridge: pre-warm skipped for %s "
                "(AUDIT_MCP_WORKERS=%d, no fan-out needed)",
                index_id, workers,
            )
            return

        lock = self._warm_locks.get(index_id)
        if lock is None:
            lock = asyncio.Lock()
            self._warm_locks[index_id] = lock

        async with lock:
            if index_id in self._warmed_indexes:
                return  # another caller raced through while we waited

            # Fan-out sized to 4x worker count so round-robin
            # distribution statistically hits every worker at least
            # once (not a fixed 16).
            fanout = max(workers * 4, 4)
            _log.info(
                "audit_mcp_bridge: pre-warming index %s across %d "
                "workers (fan-out=%d, timeout=%.0fs)",
                index_id, workers, fanout,
                self.__class__._PREWARM_TIMEOUT_S,
            )

            async def _one(tool: str) -> None:
                # Best-effort: client.post already normalises transport
                # errors into ``{"status": "error", ...}`` and never
                # raises for connect/timeout/JSON. The return value is
                # intentionally discarded.
                await client.post(
                    tool,
                    {"index_id": index_id},
                    timeout=self.__class__._PREWARM_TIMEOUT_S,
                )

            t0 = asyncio.get_event_loop().time()
            tasks = []
            for i in range(fanout):
                tool = "summary" if i < fanout // 2 else "semble_stats"
                tasks.append(_one(tool))
            await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = asyncio.get_event_loop().time() - t0
            _log.info(
                "audit_mcp_bridge: pre-warm of %s complete in %.1fs",
                index_id, elapsed,
            )
            self._warmed_indexes.add(index_id)

    async def _validate_kwargs(
        self,
        client: McpClient,
        action: str,
        kwargs: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Validate ``kwargs`` against the live JSON Schema for ``action``.

        Returns None when the call is valid (or when validation must
        be skipped -- empty catalog, unknown action). Returns a
        structured error dict suitable for direct return from
        ``forward()`` when the call would fail at audit-mcp anyway.
        The error message names the offending kwarg + the closest
        valid kwarg name via :func:`difflib.get_close_matches` so the
        agent's next turn can self-correct without burning a retry.
        """
        specs = await self.list_tool_specs(client)
        if not specs:
            return None
        match = next((s for s in specs if s.get("name") == action), None)
        if match is None:
            _log.info(
                "audit_mcp_bridge: action %r not in /tools catalog "
                "(%d known) -- forwarding anyway",
                action, len(specs),
            )
            return None

        known_param_names = {p["name"] for p in (match.get("params") or [])}
        required = set(match.get("required") or [])

        # Auto-translate index_id -> path for tools that take a path
        # on disk (audit-mcp's ``detect_languages``, ``classify_strings``,
        # etc.). Callers pass index_id uniformly; rewriting them all
        # to look up the root_path themselves would touch every site,
        # so the middleware does it transparently here.
        if (
            "path" in known_param_names
            and "index_id" not in known_param_names
            and "path" not in kwargs
            and isinstance(kwargs.get("index_id"), str)
            and kwargs["index_id"]
        ):
            iid = kwargs["index_id"]
            cls = self.__class__
            if iid not in cls._INDEX_ROOTS:
                await self._refresh_index_roots(client)
            root = cls._INDEX_ROOTS.get(iid)
            if root:
                # Mutate the caller's dict in place so forward()'s POST
                # uses the translated kwargs. Rebinding (kwargs = ...)
                # only swapped the local name and left the upstream
                # normalized_kwargs reference unchanged.
                del kwargs["index_id"]
                kwargs["path"] = root
            else:
                return {
                    "status": "error",
                    "error": (
                        f"audit_mcp.{action} needs a `path` argument; the "
                        f"caller passed index_id={iid!r} but no root_path "
                        f"is cached for it. Known indexes: "
                        f"{sorted(cls._INDEX_ROOTS)}."
                    ),
                }

        # Unknown kwargs first -- they're the loud LLM-hallucination case.
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
                f"audit_mcp.{action} rejected: unknown kwarg(s) "
                f"{', '.join(hint_parts)}. "
                f"Valid params: {valid_list}. "
                f"Required: {sorted(required)}."
            )
            _log.warning(
                "audit_mcp_bridge: blocked %s call with unknown kwargs %s "
                "(suggestions: %s)", action, unknown, suggestions,
            )
            return {"status": "error", "error": error_msg}

        # Missing required kwargs -- fail loud rather than letting
        # audit-mcp return a less actionable error.
        missing = sorted(required - set(kwargs))
        if missing:
            valid_list = sorted(known_param_names)
            error_msg = (
                f"audit_mcp.{action} rejected: missing required kwarg(s) "
                f"{missing}. Valid params: {valid_list}."
            )
            _log.warning(
                "audit_mcp_bridge: blocked %s call missing required %s",
                action, missing,
            )
            return {"status": "error", "error": error_msg}

        return None

    async def _refresh_index_roots(self, client: McpClient) -> None:
        """Fetch list_indexes and cache index_id -> root_path mapping."""
        data = await client.post("list_indexes", {}, timeout=15.0)
        if not isinstance(data, dict):
            _log.warning(
                "audit_mcp_bridge: list_indexes returned non-dict payload "
                "(type=%s) -- keeping stale index roots",
                type(data).__name__,
            )
            return
        if data.get("status") == "error":
            _log.warning(
                "audit_mcp_bridge: list_indexes refresh failed: %s",
                data.get("error"),
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

    async def _read_lines_local(
        self, client: McpClient, kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Read lines [start, end] (1-indexed, inclusive) from a file
        in the indexed repo. Resolves index_id via list_indexes and
        reads the file directly from disk. Bypasses every audit_mcp
        indexer. NO recorder row: the read is local.

        Required kwargs: index_id, file_path, start, end.
        Optional: max_lines (cap, default 500, hard ceiling 1500).
        """
        # Signature-error suffix. Mirrors the ``_validate_kwargs``
        # "Valid params: [...]. Required: [...]." shape so the
        # tool_execution classifier can recognise the shared
        # ``missing required kwarg`` / ``must be integers`` /
        # ``invalid range`` / ``must be 1-indexed`` /
        # ``exceeds file length`` substrings and let the repeat-
        # failure circuit breaker fire on identical malformed calls.
        _valid_params = "['end', 'file_path', 'index_id', 'max_lines', 'start']"
        _required_params = "['file_path', 'index_id']"

        def _sig_error(msg: str, *, with_required: bool = True) -> dict[str, Any]:
            parts = [
                f"audit_mcp.read_lines rejected: {msg}.",
                f"Valid params: {_valid_params}.",
            ]
            if with_required:
                parts.append(f"Required: {_required_params}.")
            return {"status": "error", "error": " ".join(parts)}

        index_id = str(kwargs.get("index_id") or "").strip()
        file_path = str(kwargs.get("file_path") or "").strip()
        try:
            start = int(kwargs.get("start") or 0)
            end = int(kwargs.get("end") or 0)
        except (TypeError, ValueError):
            return _sig_error("start and end must be integers")
        try:
            max_lines = int(kwargs.get("max_lines") or 500)
        except (TypeError, ValueError):
            max_lines = 500
        max_lines = min(max(1, max_lines), 1500)

        if not index_id or not file_path:
            missing = [
                name
                for name, value in (
                    ("index_id", index_id),
                    ("file_path", file_path),
                )
                if not value
            ]
            return _sig_error(
                f"missing required kwarg(s) {sorted(missing)}",
                with_required=False,
            )
        if start < 1 or end < start:
            return _sig_error(
                f"invalid range start={start} end={end} "
                "(must be 1-indexed, end >= start)",
            )
        requested = end - start + 1
        if requested > max_lines:
            end = start + max_lines - 1

        cls = self.__class__
        if index_id not in cls._INDEX_ROOTS:
            await self._refresh_index_roots(client)
        root = cls._INDEX_ROOTS.get(index_id)
        if not root:
            return {
                "status": "error",
                "error": (
                    f"read_lines: unknown index_id={index_id!r}. "
                    f"Known indexes: {sorted(cls._INDEX_ROOTS)}"
                ),
            }

        # Normalize file_path and ensure the resolved path stays under
        # the index root.
        rel = file_path.lstrip("/\\").replace("\\", "/")
        abs_path = (Path(root) / rel).resolve()
        root_resolved = Path(root).resolve()
        try:
            abs_path.relative_to(root_resolved)
            in_scope = True
        except ValueError:
            in_scope = False

        # Second chance for APK targets: the index root often points
        # at one slice of the operator's android workdir
        # (jadx/<sha>/ or apk-unified-<sha>/), but MSTG-ARCH /
        # MSTG-PLATFORM audits need to read AndroidManifest.xml +
        # res/ + smali from the SIBLING apktool/<sha>/ dir. All four
        # trees are operator-owned under ``~/.android-mcp/work/``, so
        # when the index ALREADY lives there it's safe to extend the
        # allow-list to any path under the same workspace parent.
        if not in_scope:
            workdir = Path(os.environ.get(
                "ANDROID_MCP_WORKDIR", "~/.android-mcp/work",
            )).expanduser().resolve()
            try:
                root_resolved.relative_to(workdir)
                abs_path.relative_to(workdir)
                in_scope = True
            except ValueError:
                pass

        if not in_scope:
            return {
                "status": "error",
                "error": (
                    f"read_lines: file_path escapes index root: {file_path}"
                ),
            }

        # is_file() and the actual file read both touch the disk. Run
        # them in a worker thread so the asyncio event loop doesn't
        # block on multi-MB jadx-decompiled Java files.
        if not await asyncio.to_thread(abs_path.is_file):
            swap_path: Path | None = None
            if abs_path.suffix == ".kt":
                swap_path = abs_path.with_suffix(".java")
            elif abs_path.suffix == ".java":
                swap_path = abs_path.with_suffix(".kt")
            swap_exists = bool(
                swap_path is not None
                and await asyncio.to_thread(swap_path.is_file),
            )
            if swap_path is not None and swap_exists:
                _log.info(
                    "read_lines EXT_FALLBACK %s -> %s",
                    abs_path.name, swap_path.name,
                )
                abs_path = swap_path
                file_path = file_path.rsplit(".", 1)[0] + abs_path.suffix
            else:
                # JADX sibling resources fallback: APK investigations
                # want XML layouts, AndroidManifest, strings.xml. JADX
                # (with -r) emits these under a sibling ``resources/``
                # directory next to ``sources/``. audit_mcp typically
                # indexes ``sources/`` only, so a request for
                # ``res/layout/foo.xml`` misses. Walk up to the parent
                # and try ``resources/<path>`` before declaring the
                # file missing.
                resources_root = Path(root).parent / "resources"
                if rel.startswith(("res/", "assets/", "AndroidManifest.xml")):
                    alt_path = (resources_root / rel).resolve()
                    try:
                        alt_resolved_ok = (
                            alt_path.relative_to(resources_root.resolve())
                            and await asyncio.to_thread(alt_path.is_file)
                        )
                    except ValueError:
                        alt_resolved_ok = False
                    if alt_resolved_ok:
                        _log.info(
                            "read_lines RESOURCES_FALLBACK %s -> %s",
                            file_path, alt_path,
                        )
                        abs_path = alt_path
            # If we still haven't resolved abs_path to a real file,
            # the JADX-prefix walker + "did you mean" block runs
            # next. Check is_file once more so the walker only fires
            # if resources fallback ALSO missed.
            if not await asyncio.to_thread(abs_path.is_file):
                # JADX rename fuzzy match (p182ui pattern). Walk the
                # path: for every missing segment, scan the parent's
                # children for a ``p\d+<seg>`` match and rewrite the
                # path in place. If the rewrite succeeds and the
                # resulting file exists, use it.
                rewritten = await asyncio.to_thread(
                    _resolve_jadx_prefixes, Path(root), file_path,
                )
                if rewritten is not None and await asyncio.to_thread(
                    rewritten.is_file,
                ):
                    new_rel = str(
                        rewritten.relative_to(Path(root)),
                    ).replace("\\", "/")
                    _log.info(
                        "read_lines JADX_REWRITE %s -> %s",
                        file_path, new_rel,
                    )
                    abs_path = rewritten
                    file_path = new_rel
                else:
                    # Whole-tree basename fallback. If the leaf
                    # uniquely identifies ONE file under the index
                    # root, transparently resolve to it. Multiple or
                    # zero matches keep the error.
                    leaf = file_path.replace(
                        "\\", "/",
                    ).rsplit("/", 1)[-1]
                    hits = await asyncio.to_thread(
                        _search_by_basename, Path(root), leaf,
                    )
                    auto_resolved = False
                    if len(hits) == 1:
                        cand = Path(root) / hits[0]
                        if await asyncio.to_thread(cand.is_file):
                            _log.info(
                                "read_lines BASENAME_REWRITE %s -> %s",
                                file_path, hits[0],
                            )
                            abs_path = cand
                            file_path = hits[0]
                            auto_resolved = True
                    if not auto_resolved:
                        # Build a "did you mean" list by merging
                        # whole-tree basename hits with the
                        # deepest-existing-ancestor fuzzy scan. Dedupe
                        # while preserving order.
                        suggestions = await asyncio.to_thread(
                            _suggest_nearest_paths, Path(root), file_path,
                        )
                        merged: list[str] = []
                        seen: set[str] = set()
                        for item in [*hits, *suggestions]:
                            if item and item not in seen:
                                merged.append(item)
                                seen.add(item)
                        hint = (
                            f" NEAREST INDEXED PATHS: {', '.join(merged)}"
                            if merged
                            else (
                                " No similar path exists in the index. "
                                "Use semantic_search to find the "
                                "correct file."
                            )
                        )
                        is_jadx = await asyncio.to_thread(
                            _looks_like_jadx, Path(root),
                        )
                        if is_jadx:
                            guidance = (
                                "JADX renames colliding package names "
                                "(e.g. ``ui`` \u2192 ``p182ui``, "
                                "``do`` \u2192 ``p23do``); the path "
                                "in semantic_search output is the "
                                "on-disk path, USE IT VERBATIM."
                            )
                        else:
                            guidance = (
                                "The path in semantic_search output "
                                "is the on-disk path, USE IT VERBATIM."
                            )
                        return {
                            "status": "error",
                            "error": (
                                f"read_lines: file not found: "
                                f"{file_path} (resolved to {abs_path}). "
                                f"{guidance}{hint}"
                            ),
                        }

        def _read_all_lines(path: Path) -> list[str]:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                return f.readlines()

        try:
            all_lines = await asyncio.to_thread(_read_all_lines, abs_path)
        except OSError as exc:
            return {
                "status": "error",
                "error": f"read_lines: read failed: {exc}",
            }

        total = len(all_lines)
        if start > total:
            return _sig_error(
                f"start={start} exceeds file length {total}",
            )
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
