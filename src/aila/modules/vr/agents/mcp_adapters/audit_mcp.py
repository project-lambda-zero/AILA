"""Adapters for the audit-mcp source-audit MCP server.

Specialized adapters defined here ship structured payloads keyed by
``PayloadKind``. Every audit-mcp tool not listed here still works via
the generic fallback in ``generic.py`` (registered via ``KNOWN_TOOLS``).

Specialized v0.3 v2 set:
  - DECOMPILED_FUNCTION: read_function
  - XREF_VIEW:           callers_of, callees_of
  - TAINT_FLOW:          taint_paths_to, paths_between
  - GRAPH_VIEW:          export_graph
  - PATCH_DIFF:          diff_codebases
  - TEXT (structured):   attack_surface, complexity_hotspots,
                         fuzzing_targets
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.contracts import PayloadKind

from ._shared import (
    MAX_LIST_PREVIEW,
    bounded_dump,
    obs_key_for,
    provenance_stamp,
)
from .base import AdapterContext, AdapterResult

__all__ = [
    "adapt_fuzzing_targets",
    "adapt_attack_surface",
    "adapt_complexity_hotspots",
    "adapt_callers_of",
    "adapt_callees_of",
    "adapt_taint_paths_to",
    "adapt_paths_between",
    "adapt_export_graph",
    "adapt_diff_codebases",
    "adapt_read_function",
    "adapt_search_source",
    "adapt_search_macros",
    "adapt_search_constants",
    "adapt_search_types",
    "adapt_search_functions",
]


# Classify each hotspot/target entry into one of the categories below
# instead of silently dropping noise. Each category controls how the
# entry surfaces to the agent:
#
#   real            → audit-worthy implementation code; render normally
#   compiled_bundle → Emscripten / asm.js IIFE wrapping a whole codec.
#                     audit the UPSTREAM C source as a separate target.
#   vendored_library→ shipped third_party/vendor copy. audit the upstream
#                     as a separate target if you care about it.
#   test_payload    → regression test / benchmark / wpt suite. drop.
#   generated_code  → lex/yacc/protobuf/generated lookup table. read the
#                     GENERATOR instead.
#
# Without this classification the agent saw firefox's OpenJPEG IIFE
# (cyc=6969) ranked #1 in complexity_hotspots, called read_function
# on it, looped on "Function OpenJPEG not indexed" because the name is
# a namespace identifier inside a single ~7000-line wrapper. The fix
# is NOT to hide that signal — high complexity in a vendored codec is
# real information — but to TAG it so the agent's next move is "register
# uclouvain/openjpeg as its own target" rather than "read this function".
_DROP_CATEGORIES: frozenset[str] = frozenset({"test_payload", "generated_code"})

# Sample size per attack-surface kind when rendering. The kind summary
# is unbounded; per-kind entry lists are capped at this width so the
# agent sees diversity without paying for 5,000 bullets.
_PER_KIND_PREVIEW = 8

_VENDORED_DIR_SEGMENTS: frozenset[str] = frozenset({
    "third_party", "third-party", "vendor", "extern", "external",
    "node_modules",
})

_TEST_DIR_SEGMENTS: frozenset[str] = frozenset({
    "tests", "test", "jit-test", "non262", "regress", "wpt",
    "web-platform-tests", "testing", "benchmarks", "fixtures",
    "__tests__", "spec", "specs",
})

_BUILD_DIR_SEGMENTS: frozenset[str] = frozenset({
    "dist", "build", "out", "target",
})

_GENERATED_FILENAME_SUFFIXES: tuple[str, ...] = (
    ".min.js", ".min.css",
    "-bundle.js", "-bundle.min.js",
    ".generated.js", ".generated.ts", ".generated.py",
    ".gen.js", ".gen.ts", ".gen.go",
    "_pb.py", "_pb2.py",
    ".pb.cc", ".pb.h", ".pb.go",
    "lex.yy.c", "y.tab.c", "y.tab.h",
    "_find_header.c",  # aiohttp generated lookup table
)

_COMPILED_BUNDLE_SUFFIXES: tuple[str, ...] = (
    "_nowasm_fallback.js",  # Emscripten asm.js fallback
    "_emscripten.js",
    "_asm.js",
)


def _classify_hotspot(entry: dict[str, Any]) -> tuple[str, str]:
    """Return ``(category, hint)`` for a hotspot/fuzzing_target entry.

    Categories drive how the entry renders in the prompt. ``hint`` is
    a short action string shown next to vendored/bundle entries so
    the agent knows the right next move (it's NOT to call read_function
    on a 7000-line Emscripten IIFE).
    """
    if not isinstance(entry, dict):
        return "real", ""
    loc = entry.get("location") if isinstance(entry.get("location"), dict) else {}
    file_path = (
        loc.get("file_path")
        or entry.get("file")
        or entry.get("path")
        or ""
    )
    normalised = file_path.replace("\\", "/").lower()
    filename = normalised.rsplit("/", 1)[-1] if normalised else ""

    # Compiled-bundle check first — most actionable, most distinctive.
    if any(filename.endswith(suf) for suf in _COMPILED_BUNDLE_SUFFIXES):
        return (
            "compiled_bundle",
            "Emscripten/asm.js bundle. Find upstream C source and "
            "register it as a separate VR target — do NOT read_function this IIFE.",
        )
    # Emscripten IIFE signature (single moduleArg param) without the
    # filename giveaway — covers renamed bundles.
    params = entry.get("parameters") or []
    if (
        isinstance(params, list)
        and len(params) == 1
        and isinstance(params[0], dict)
        and params[0].get("name") == "moduleArg"
    ):
        return (
            "compiled_bundle",
            "Emscripten IIFE wrapping compiled code (single moduleArg param). "
            "Find upstream source — do NOT read_function this.",
        )

    if normalised:
        for seg in _VENDORED_DIR_SEGMENTS:
            if f"/{seg}/" in normalised:
                return (
                    "vendored_library",
                    f"Vendored copy under /{seg}/. If audit-relevant, "
                    "register the upstream repo as its own VR target.",
                )
        for seg in _TEST_DIR_SEGMENTS:
            if f"/{seg}/" in normalised:
                return "test_payload", ""
        for seg in _BUILD_DIR_SEGMENTS:
            if f"/{seg}/" in normalised:
                return (
                    "compiled_bundle",
                    f"Build output under /{seg}/. Audit the source that "
                    "generated it, not the artifact.",
                )
        for suf in _GENERATED_FILENAME_SUFFIXES:
            if filename.endswith(suf) or suf in filename:
                return (
                    "generated_code",
                    "Auto-generated. Read the generator/schema, not this file.",
                )

    # Single-IIFE bundle heuristic: function spans >2000 lines starting
    # within the first 5 lines of the file → almost certainly codegen.
    start = loc.get("start_line")
    end = loc.get("end_line")
    if (
        isinstance(start, int) and isinstance(end, int)
        and start <= 5 and (end - start) > 2000
    ):
        return (
            "compiled_bundle",
            f"Single function spans {end - start} lines from top of file — "
            "likely codegen. Find upstream source.",
        )

    return "real", ""


def _split_by_category(
    entries: list[Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """Return ``(real, attention_required, dropped_count)``.

    ``real`` and ``attention_required`` entries each get an injected
    ``_classification`` field carrying the ``(category, hint)`` pair so
    the renderer can format them differently. ``attention_required``
    holds compiled_bundle + vendored_library — kept in the response but
    rendered with category tag + drill-in hint so the agent knows the
    right next move. Test payloads and generated code are silently
    dropped (returned in ``dropped_count`` so the prompt can say
    "dropped N noise entries" without naming them).
    """
    real: list[dict[str, Any]] = []
    attention: list[dict[str, Any]] = []
    dropped = 0
    for e in entries:
        if not isinstance(e, dict):
            dropped += 1
            continue
        category, hint = _classify_hotspot(e)
        if category in _DROP_CATEGORIES:
            dropped += 1
            continue
        enriched = dict(e)
        enriched["_classification"] = {"category": category, "hint": hint}
        if category == "real":
            real.append(enriched)
        else:
            attention.append(enriched)
    return real, attention, dropped

# Observable cap for read_function output. Bumped progressively after
# observing the agent loop on functions that exceeded the cap:
#   3000  → ngx_http_script_regex_start_code (154 lines, 3669 chars)
#           agent saw head + truncation marker, looped re-issuing
#   12000 → ngx_http_proxy_merge_loc_conf (513 lines, ~40000 chars)
#           agent saw first ~150 lines (the prologue), missed the
#           body-compile block at line 4067 where complete_lengths=1
#           is set, submitted a false-positive "missing NULL sentinel"
#           finding (investigations 179f6db0 + 9f2c0b39)
#   50000 → covers ~600+ lines of typical C, enough for every
#           in-tree nginx function we've seen the agent need.
# The FULL body is always preserved in payload.pseudocode (message
# store) — this cap is only the per-turn slice the agent sees via
# observables. Future fix: stream a structured summary (signature
# + N anchor lines around each search_source hit) for functions
# that overflow this cap.
_MAX_OBS_READ_FUNCTION = 100000000


def _list_or_empty(raw: dict[str, Any], *keys: str) -> list[Any]:
    for k in keys:
        v = raw.get(k)
        if isinstance(v, list):
            return v
    return []


# ----------------------------------------------------------------------
# TEXT specializations
# ----------------------------------------------------------------------


def adapt_fuzzing_targets(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``fuzzing_targets`` to TEXT payload with ranked function list.

    Entries are classified into ``real`` (audit-worthy implementation) vs
    ``attention_required`` (compiled bundles + vendored libraries kept
    visible with explicit category tag + drill-in hint). Test payloads +
    generated code are silently dropped.
    """
    raw_targets = _list_or_empty(raw, "targets", "results")
    real, attention, dropped = _split_by_category(raw_targets)

    def _name(entry: dict[str, Any]) -> str:
        return (
            entry.get("function_name")
            or entry.get("name")
            or entry.get("symbol")
            or "<unnamed>"
        )

    def _suffix(entry: dict[str, Any]) -> str:
        bits: list[str] = []
        for k in ("risk_score", "score", "priority"):
            if entry.get(k) is not None:
                bits.append(f"score={entry[k]}")
                break
        if entry.get("blast_radius") is not None:
            bits.append(f"blast={entry['blast_radius']}")
        if entry.get("complexity") is not None:
            bits.append(f"complexity={entry['complexity']}")
        return f" ({', '.join(bits)})" if bits else ""

    real_lines: list[str] = []
    for entry in real[:MAX_LIST_PREVIEW]:
        real_lines.append(f"  - {_name(entry)}{_suffix(entry)}")
    if len(real) > MAX_LIST_PREVIEW:
        real_lines.append(f"  ... and {len(real) - MAX_LIST_PREVIEW} more")

    attention_lines: list[str] = []
    for entry in attention[:10]:  # cap subsystem listing at 10
        cls = entry.get("_classification") or {}
        cat = cls.get("category", "?")
        hint = cls.get("hint", "")
        loc = entry.get("location") or {}
        fp = (loc.get("file_path") or "").replace("\\", "/")
        fp_short = "/".join(fp.split("/")[-3:]) if fp else ""
        attention_lines.append(
            f"  - [{cat}] {_name(entry)}{_suffix(entry)} @ .../{fp_short}"
        )
        if hint:
            attention_lines.append(f"      → {hint}")
    if len(attention) > 10:
        attention_lines.append(f"  ... and {len(attention) - 10} more")

    drop_note = f" — dropped {dropped} test/generated entries" if dropped else ""

    sections: list[str] = [
        f"audit-mcp fuzzing_targets: {len(real)} real candidate(s), "
        f"{len(attention)} subsystem/vendored entry(ies){drop_note}",
        "",
        "REAL FUNCTIONS (audit these):",
        *(real_lines or ["  (none)"]),
    ]
    if attention_lines:
        sections.extend([
            "",
            "SUBSYSTEMS / VENDORED (do NOT read_function these — see hint):",
            *attention_lines,
        ])
    obs_value = "\n".join(sections)

    payload: dict[str, Any] = {
        "text": (
            f"audit-mcp fuzzing_targets returned {len(real)} real + "
            f"{len(attention)} subsystem candidates{drop_note}"
        ),
        "tool": f"{ctx.mcp_server_id}.{ctx.tool_name}",
        "targets": real,
        "subsystem_entries": attention,
        "total": len(real) + len(attention),
        "dropped_noise": dropped,
        "source_provenance": provenance_stamp(ctx),
    }
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx): obs_value},
        summary=f"{len(real)} real + {len(attention)} subsystem candidates",
    )


def adapt_attack_surface(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``attack_surface`` to TEXT payload (entry-point catalog).

    audit_mcp returns the list under the key ``entrypoints`` with
    fields ``{node_id, kind, trust_level, asset_value, description}``
    — NOT the ``surfaces|entries|results`` + ``name|symbol|route``
    shape the adapter previously assumed. As a result every call to
    attack_surface rendered as "0 entry points" even though firefox
    has 5,195 of them and openjpeg has 37.

    Output groups entries by ``kind`` (api / user_input / third_party
    / etc.) so the agent gets a digestible by-kind breakdown rather
    than 5,000 raw lines, and includes the trust_level + asset_value
    next to each entry so the agent can prioritize.
    """
    from collections import Counter  # noqa: PLC0415

    # Accept both the canonical 'entrypoints' key (current audit_mcp)
    # and the legacy 'surfaces|entries|results' keys (older servers,
    # cached fixtures, possible future renames).
    entries = _list_or_empty(
        raw, "entrypoints", "surfaces", "entries", "results",
    )
    entries = [e for e in entries if isinstance(e, dict)]

    by_kind: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        by_kind.setdefault(e.get("kind") or "unknown", []).append(e)

    sections: list[str] = [
        f"attack_surface: {len(entries)} entry point(s) across "
        f"{len(by_kind)} kind(s) — "
        + ", ".join(f"{k}:{len(v)}" for k, v in sorted(by_kind.items(), key=lambda kv: -len(kv[1])))
    ]
    for kind, kentries in sorted(by_kind.items(), key=lambda kv: -len(kv[1])):
        sections.append("")
        sections.append(f"## {kind} ({len(kentries)})")
        # Asset/trust distribution at the per-kind level
        trust = Counter(e.get("trust_level") or "?" for e in kentries)
        asset = Counter(e.get("asset_value") or "?" for e in kentries)
        sections.append(
            f"  trust: {dict(trust.most_common())}  asset: {dict(asset.most_common())}"
        )
        for e in kentries[:_PER_KIND_PREVIEW]:
            node_id = e.get("node_id") or e.get("name") or e.get("symbol") or "<?>"
            desc = (e.get("description") or "").strip()
            tl = e.get("trust_level") or ""
            av = e.get("asset_value") or ""
            tags = " ".join(f"[{t}]" for t in (tl, av) if t)
            line = f"  - {node_id}"
            if tags:
                line += f" {tags}"
            if desc:
                line += f" — {desc[:120]}"
            sections.append(line)
        if len(kentries) > _PER_KIND_PREVIEW:
            sections.append(f"  ... and {len(kentries) - _PER_KIND_PREVIEW} more {kind} entries")

    obs_value = "\n".join(sections)

    payload: dict[str, Any] = {
        "text": obs_value,
        "tool": f"{ctx.mcp_server_id}.{ctx.tool_name}",
        "entrypoints": entries,
        "by_kind": {k: len(v) for k, v in by_kind.items()},
        "total": len(entries),
        "source_provenance": provenance_stamp(ctx),
    }
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx): obs_value},
        summary=(
            f"{len(entries)} attack-surface entrypoints "
            f"({len(by_kind)} kinds)"
        ),
    )


def adapt_complexity_hotspots(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``complexity_hotspots`` to TEXT payload (top complex functions).

    Categorized the same way as ``adapt_fuzzing_targets``: real audit
    candidates render in the main list; compiled bundles + vendored
    libraries render in a SEPARATE 'do not read_function this' section
    with explicit category tag + drill-in hint; test payloads + generated
    code are dropped.
    """
    raw_hotspots = _list_or_empty(raw, "hotspots", "functions", "results")
    real, attention, dropped = _split_by_category(raw_hotspots)

    def _name(h: dict[str, Any]) -> str:
        return h.get("function_name") or h.get("name") or h.get("symbol") or "<?>"

    def _loc(h: dict[str, Any]) -> str:
        loc = h.get("location") or {}
        path = (
            loc.get("file_path") or h.get("file") or h.get("path") or ""
        ).replace("\\", "/")
        line = loc.get("start_line") or h.get("line")
        if path and line:
            return f" @ .../{'/'.join(path.split('/')[-3:])}:{line}"
        if path:
            return f" @ .../{'/'.join(path.split('/')[-3:])}"
        return ""

    def _suffix(h: dict[str, Any]) -> str:
        cyc = h.get("cyclomatic") or h.get("cyclomatic_complexity")
        cog = h.get("cognitive") or h.get("cognitive_complexity")
        bits: list[str] = []
        if cyc is not None:
            bits.append(f"cyc={cyc}")
        if cog is not None:
            bits.append(f"cog={cog}")
        return f" ({', '.join(bits)})" if bits else ""

    real_lines: list[str] = []
    for h in real[:MAX_LIST_PREVIEW]:
        real_lines.append(f"  - {_name(h)}{_loc(h)}{_suffix(h)}")
    if len(real) > MAX_LIST_PREVIEW:
        real_lines.append(f"  ... and {len(real) - MAX_LIST_PREVIEW} more")

    attention_lines: list[str] = []
    for h in attention[:10]:
        cls = h.get("_classification") or {}
        attention_lines.append(
            f"  - [{cls.get('category', '?')}] {_name(h)}{_loc(h)}{_suffix(h)}"
        )
        hint = cls.get("hint")
        if hint:
            attention_lines.append(f"      → {hint}")
    if len(attention) > 10:
        attention_lines.append(f"  ... and {len(attention) - 10} more")

    drop_note = f" — dropped {dropped} test/generated entries" if dropped else ""

    sections: list[str] = [
        f"complexity_hotspots: {len(real)} real function(s), "
        f"{len(attention)} subsystem/vendored entry(ies){drop_note}",
        "",
        "REAL FUNCTIONS:",
        *(real_lines or ["  (none)"]),
    ]
    if attention_lines:
        sections.extend([
            "",
            "SUBSYSTEMS / VENDORED (do NOT read_function these — see hint):",
            *attention_lines,
        ])
    obs_value = "\n".join(sections)

    payload: dict[str, Any] = {
        "text": obs_value,
        "tool": f"{ctx.mcp_server_id}.{ctx.tool_name}",
        "hotspots": real,
        "subsystem_entries": attention,
        "total": len(real) + len(attention),
        "dropped_noise": dropped,
        "source_provenance": provenance_stamp(ctx),
    }
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx): obs_value},
        summary=f"{len(real)} real hotspots + {len(attention)} subsystem entries",
    )


# ----------------------------------------------------------------------
# XREF_VIEW family
# ----------------------------------------------------------------------


def _audit_xref_compact_line(node: dict[str, Any]) -> str:
    name = node.get("function_name") or node.get("name") or node.get("symbol") or "<?>"
    path = node.get("file") or node.get("path") or ""
    line = node.get("line")
    loc_str = f" @ {path}:{line}" if path and line else (f" @ {path}" if path else "")
    return f"  - {name}{loc_str}"


def _audit_xref_result(
    raw: dict[str, Any],
    ctx: AdapterContext,
    *,
    target: str,
    list_keys: tuple[str, ...],
    target_field: str,
    obs_suffix: str,
    summary_noun: str,
) -> AdapterResult:
    refs = _list_or_empty(raw, *list_keys)
    note = raw.get("_bridge_note") if isinstance(raw, dict) else None
    payload: dict[str, Any] = {
        target_field: target,
        "xrefs": refs,
        "total": len(refs),
        "source_provenance": provenance_stamp(ctx),
    }
    if isinstance(note, str) and note.strip():
        payload["bridge_note"] = note
    lines = [
        _audit_xref_compact_line(r)
        for r in refs[:MAX_LIST_PREVIEW]
        if isinstance(r, dict)
    ]
    if len(refs) > MAX_LIST_PREVIEW:
        lines.append(f"  ... and {len(refs) - MAX_LIST_PREVIEW} more")
    body = "\n".join(lines) if lines else "  (none)"
    obs_value = f"{summary_noun} of {target} ({len(refs)}):\n{body}"
    if isinstance(note, str) and note.strip():
        # Surface the bridge's zero-result diagnostic to the agent.
        # The note already includes nearest-name suggestions when the
        # symbol resolved to something close.
        obs_value = f"{obs_value}\n\n{note}"
    return AdapterResult(
        payload_kind=PayloadKind.XREF_VIEW,
        payload=payload,
        observables_delta={obs_key_for(ctx, f"{obs_suffix}.{target}"): obs_value},
        summary=f"{len(refs)} {summary_noun} for {target}",
    )


def adapt_callers_of(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Map ``callers_of`` to XREF_VIEW payload."""
    target = str(
        ctx.args.get("function")
        or ctx.args.get("symbol")
        or raw.get("target")
        or "<target>",
    )
    return _audit_xref_result(
        raw, ctx,
        target=target,
        list_keys=("callers", "results", "nodes"),
        target_field="target",
        obs_suffix="callers_of",
        summary_noun="caller(s)",
    )


def adapt_callees_of(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Map ``callees_of`` to XREF_VIEW payload."""
    target = str(
        ctx.args.get("function")
        or ctx.args.get("symbol")
        or raw.get("target")
        or "<target>",
    )
    return _audit_xref_result(
        raw, ctx,
        target=target,
        list_keys=("callees", "results", "nodes"),
        target_field="target",
        obs_suffix="callees_of",
        summary_noun="callee(s)",
    )


# ----------------------------------------------------------------------
# TAINT_FLOW family
# ----------------------------------------------------------------------


def _audit_taint_summary_lines(paths: list[Any]) -> list[str]:
    lines: list[str] = []
    for p in paths[:MAX_LIST_PREVIEW]:
        if not isinstance(p, dict):
            continue
        src = p.get("source") or p.get("from") or "<src>"
        sink = p.get("sink") or p.get("to") or "<sink>"
        hops = p.get("hops") or p.get("length") or len(p.get("path", []) or [])
        lines.append(f"  - {src} → {sink} ({hops} hop(s))")
    if len(paths) > MAX_LIST_PREVIEW:
        lines.append(f"  ... and {len(paths) - MAX_LIST_PREVIEW} more")
    return lines


def adapt_taint_paths_to(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``taint_paths_to`` to TAINT_FLOW payload (source-level taint)."""
    sink = str(
        ctx.args.get("sink")
        or ctx.args.get("sink_function")
        or raw.get("sink")
        or "<sink>",
    )
    paths = _list_or_empty(raw, "paths", "results", "taint_paths")
    payload: dict[str, Any] = {
        "sink": sink,
        "paths": paths,
        "total": len(paths),
        "raw": raw,
        "source_provenance": provenance_stamp(ctx),
    }
    lines = _audit_taint_summary_lines(paths)
    body = "\n".join(lines) if lines else "  (no taint paths)"
    obs_value = f"taint_paths_to {sink}: {len(paths)} path(s)\n{body}"
    return AdapterResult(
        payload_kind=PayloadKind.TAINT_FLOW,
        payload=payload,
        observables_delta={obs_key_for(ctx, f"taint.{sink}"): obs_value},
        summary=f"taint_paths_to {sink}: {len(paths)} path(s)",
    )


def adapt_paths_between(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``paths_between`` to TAINT_FLOW payload (graph reachability)."""
    src = str(ctx.args.get("source") or ctx.args.get("from") or "<src>")
    dst = str(ctx.args.get("target") or ctx.args.get("to") or "<dst>")
    paths = _list_or_empty(raw, "paths", "results")
    payload: dict[str, Any] = {
        "source": src,
        "target": dst,
        "paths": paths,
        "total": len(paths),
        "raw": raw,
        "source_provenance": provenance_stamp(ctx),
    }
    lines = _audit_taint_summary_lines(paths)
    body = "\n".join(lines) if lines else "  (no paths)"
    obs_value = f"paths_between {src} → {dst}: {len(paths)} path(s)\n{body}"
    return AdapterResult(
        payload_kind=PayloadKind.TAINT_FLOW,
        payload=payload,
        observables_delta={obs_key_for(ctx, f"paths.{src}_to_{dst}"): obs_value},
        summary=f"paths_between {src} → {dst}: {len(paths)}",
    )


# ----------------------------------------------------------------------
# GRAPH_VIEW
# ----------------------------------------------------------------------


def adapt_export_graph(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``export_graph`` to GRAPH_VIEW payload (call/data graph snapshot)."""
    nodes = _list_or_empty(raw, "nodes")
    edges = _list_or_empty(raw, "edges")
    payload: dict[str, Any] = {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "format": raw.get("format"),
        "raw": raw,
        "source_provenance": provenance_stamp(ctx),
    }
    obs_value = f"export_graph: {len(nodes)} node(s), {len(edges)} edge(s)"
    return AdapterResult(
        payload_kind=PayloadKind.GRAPH_VIEW,
        payload=payload,
        observables_delta={obs_key_for(ctx): obs_value},
        summary=obs_value,
    )


# ----------------------------------------------------------------------
# PATCH_DIFF
# ----------------------------------------------------------------------


def adapt_diff_codebases(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``diff_codebases`` to PATCH_DIFF payload (multi-file diff)."""
    changes = _list_or_empty(raw, "changes", "files", "results")
    added = sum(1 for c in changes if isinstance(c, dict) and c.get("change") == "added")
    removed = sum(1 for c in changes if isinstance(c, dict) and c.get("change") == "removed")
    modified = sum(1 for c in changes if isinstance(c, dict) and c.get("change") == "modified")
    payload: dict[str, Any] = {
        "changes": changes,
        "total": len(changes),
        "added": added,
        "removed": removed,
        "modified": modified,
        "raw_preview": bounded_dump(raw),
        "source_provenance": provenance_stamp(ctx),
    }
    bullets: list[str] = []
    for c in changes[:MAX_LIST_PREVIEW]:
        if not isinstance(c, dict):
            continue
        bullets.append(
            f"  - [{c.get('change', '?')}] {c.get('path') or c.get('symbol') or '?'}",
        )
    if len(changes) > MAX_LIST_PREVIEW:
        bullets.append(f"  ... and {len(changes) - MAX_LIST_PREVIEW} more")
    obs_value = (
        f"diff_codebases: +{added} -{removed} ~{modified} "
        f"({len(changes)} total)\n"
        + ("\n".join(bullets) if bullets else "  (no changes)")
    )
    return AdapterResult(
        payload_kind=PayloadKind.PATCH_DIFF,
        payload=payload,
        observables_delta={obs_key_for(ctx): obs_value},
        summary=f"diff_codebases: +{added} -{removed} ~{modified}",
    )


# ----------------------------------------------------------------------
# DECOMPILED_FUNCTION
# ----------------------------------------------------------------------


def adapt_read_function(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``read_function`` (source) to DECOMPILED_FUNCTION payload.

    The shape is conceptually identical to IDA's decompile: a function
    body + identifying metadata. ``language`` is derived from the
    response (e.g. ``c``, ``rust``, ``go``) when present.
    """
    fn_name = str(
        raw.get("function_name")
        or raw.get("name")
        or ctx.args.get("function")
        or ctx.args.get("symbol")
        or "<unknown>",
    )
    # audit-mcp's read_function returns the actual function body in
    # `content`. The `source` field is the PROVIDER TAG (e.g. "semble",
    # "trailmark") — a literal string identifying which backend served
    # the read. Earlier adapter code read `source` first, took the
    # literal "semble" string, and stored THAT as the function body.
    # Every read_function observable for months was just the string
    # "semble". Agents re-read the same function 15+ times trying to
    # see the body. Order: content -> body -> text. NEVER source.
    raw_body = raw.get("content") or raw.get("body") or raw.get("text") or ""
    if isinstance(raw_body, list):
        body = "\n".join(str(line) for line in raw_body)
    else:
        body = str(raw_body)
    language = str(raw.get("language") or "")
    path = str(raw.get("file_path") or raw.get("file") or raw.get("path") or "")
    line = raw.get("start_line") or raw.get("line")
    line_count = int(raw.get("line_count") or (body.count("\n") + (1 if body else 0)))

    payload: dict[str, Any] = {
        "function_name": fn_name,
        "address": f"{path}:{line}" if path and line else path,
        "pseudocode": body,
        "line_count": line_count,
        "language": language,
        "source_provenance": provenance_stamp(ctx),
    }

    if len(body) <= _MAX_OBS_READ_FUNCTION:
        obs_value = body
        truncation_suffix = ""
    else:
        # Find the last newline within the cap so we cut on a line
        # boundary, not mid-statement.
        cut = body.rfind("\n", 0, _MAX_OBS_READ_FUNCTION)
        if cut < 0:
            cut = _MAX_OBS_READ_FUNCTION
        kept = body[:cut]
        kept_lines = kept.count("\n") + (1 if kept else 0)
        # Compute the file line where truncation happened so the agent
        # can read past it directly.
        try:
            visible_start = int(line) if line is not None else 1
        except (TypeError, ValueError):
            visible_start = 1
        visible_end = visible_start + kept_lines - 1
        next_start = visible_end + 1
        end_line_total = int(raw.get("end_line") or (visible_start + line_count - 1))
        # Loud banner at TOP so even if downstream renderers cut
        # further, the agent sees the truncation marker first.
        banner = (
            f"!! FUNCTION BODY TRUNCATED !! "
            f"{fn_name} is {line_count} lines total "
            f"({len(body)} chars); only the first {kept_lines} lines "
            f"({len(kept)} chars) fit in the observable cap. "
            f"You are seeing file {path}:{visible_start}-{visible_end}. "
            f"To read the rest, call:\n"
            f"  audit_mcp.read_lines(index_id=<I>, file_path={path!r}, "
            f"start={next_start}, end={min(next_start + 500, end_line_total)})\n"
            f"DO NOT draw conclusions about absence of code in the "
            f"unseen tail — call read_lines first.\n\n"
        )
        obs_value = banner + kept
        truncation_suffix = "  ⚠ TRUNCATED"
    return AdapterResult(
        payload_kind=PayloadKind.DECOMPILED_FUNCTION,
        payload=payload,
        observables_delta={obs_key_for(ctx, f"source.{fn_name}"): obs_value},
        summary=f"read_function {fn_name} ({line_count} lines, lang={language or '?'}){truncation_suffix}",
    )


# ----------------------------------------------------------------------
# search_* family — specialized dense rendering
# ----------------------------------------------------------------------

# Per-result observable cap for search_* adapters. 30000 chars covers
# ~200-400 matches in dense file:line:text format vs ~8 matches when
# the old generic JSON-dump path capped at MAX_OBS_DUMP_CHARS=100000000.
_MAX_OBS_SEARCH = 100000000


def _render_matches_dense(raw: dict[str, Any]) -> tuple[str, int]:
    """Render a search_* result as file:line: text matches, one per line.

    Returns ``(rendered_text, total_match_count)``. Output is at most
    ``_MAX_OBS_SEARCH`` chars with a trailing truncation marker when
    the full list overflows.
    """
    matches = (raw.get("matches") or raw.get("results")
               or raw.get("hits") or [])
    if not isinstance(matches, list):
        return bounded_dump(raw, max_chars=_MAX_OBS_SEARCH), 0
    lines: list[str] = []
    for m in matches:
        if not isinstance(m, dict):
            lines.append(str(m))
            continue
        fp = m.get("file_path") or m.get("file") or m.get("path") or "?"
        ln = m.get("line") or m.get("start_line") or "?"
        txt = (m.get("text") or m.get("snippet")
               or m.get("match") or m.get("body") or "")
        if isinstance(txt, list):
            txt = " ".join(str(x) for x in txt)
        txt = str(txt).strip()
        lines.append(f"{fp}:{ln}: {txt}")
    body = "\n".join(lines)
    if len(body) > _MAX_OBS_SEARCH:
        kept = body[:_MAX_OBS_SEARCH].rsplit("\n", 1)[0]
        body = kept + (
            f"\n... [truncated — {len(matches)} matches total, full"
            f" {len(body)} chars in message store; narrow your pattern"
            f" or add file_path scope to reduce noise]"
        )
    return body, len(matches)


def _adapt_search(tool_label: str) -> Any:
    """Factory: produce a specialized search_* adapter for one tool name.

    Same dense rendering for every search_* tool (search_source,
    search_macros, search_constants, search_types, search_functions) —
    only the summary label changes.
    """
    def _adapter(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
        body, count = _render_matches_dense(raw)
        summary = f"{tool_label}: count={count}, matches_len={count}"
        payload = {
            "tool": tool_label,
            "match_count": count,
            "matches_text": body,
            "raw": raw,
        }
        obs_key = obs_key_for(ctx, f"{tool_label}.{ctx.args.get('pattern') or ctx.args.get('name') or '_'}")
        return AdapterResult(
            payload_kind=PayloadKind.TEXT,
            payload=payload,
            observables_delta={obs_key: body},
            summary=summary,
        )
    _adapter.__name__ = f"adapt_{tool_label}"
    return _adapter


adapt_search_source = _adapt_search("search_source")
adapt_search_macros = _adapt_search("search_macros")
adapt_search_constants = _adapt_search("search_constants")
adapt_search_types = _adapt_search("search_types")
adapt_search_functions = _adapt_search("search_functions")


def _adapt_search_functions_specialized(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Override the generic search_* renderer for search_functions.

    Generic _render_matches_dense expects {file_path, line, text} per
    match, falls through to '?' for missing fields. search_functions
    returns {name, qualified_name, kind, file_path, line_start,
    line_end, cyclomatic_complexity} with file_path/line_start often
    null (trailmark loses source locations). The generic path then
    produced '?:?:' for every row — useless 'evidence' that agents
    cited as if it were a file:line reference.

    Render each match as:
      function_name [kind, complexity=N] @ file_path:line_start-line_end
      (qualified: qualified_name)
    Falls back to just the name + flags when location data missing.
    """
    matches = raw.get("matches") or raw.get("results") or []
    if not isinstance(matches, list):
        return _adapt_search("search_functions")(raw, ctx)
    lines: list[str] = []
    no_location = 0
    for m in matches:
        if not isinstance(m, dict):
            lines.append(str(m))
            continue
        name = m.get("name") or m.get("qualified_name") or "?"
        kind = m.get("kind") or "function"
        cyc = m.get("cyclomatic_complexity")
        fp = m.get("file_path")
        ls = m.get("line_start")
        le = m.get("line_end")
        qn = m.get("qualified_name")
        flags = [kind]
        if isinstance(cyc, (int, float)) and cyc:
            flags.append(f"cyc={cyc}")
        flag_str = ", ".join(flags)
        if fp and ls:
            loc = f"{fp}:{ls}" + (f"-{le}" if le else "")
        else:
            loc = "[no location indexed — use read_lines after locating via semantic_search]"
            no_location += 1
        line = f"{name} [{flag_str}] @ {loc}"
        if qn and qn != name:
            line += f"  (qualified: {qn})"
        lines.append(line)
    body = "\n".join(lines)
    if no_location:
        body += (
            f"\n\n[{no_location}/{len(matches)} matches have no indexed "
            f"file_path/line — audit_mcp's function indexer lost their "
            f"locations. Use semantic_search(query=\"<function_name>\") "
            f"to find the real definition, then read_lines for the body.]"
        )
    if len(body) > _MAX_OBS_SEARCH:
        body = body[:_MAX_OBS_SEARCH] + (
            f"\n... [truncated — {len(matches)} matches total, full body "
            f"in message store]"
        )
    payload = {
        "tool": "search_functions",
        "match_count": len(matches),
        "matches_text": body,
        "raw": raw,
    }
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={
            obs_key_for(ctx, f"search_functions.{ctx.args.get('pattern') or '_'}"): body,
        },
        summary=f"search_functions: count={len(matches)}, no_location={no_location}",
    )


# Override the generic adapter with the specialized one.
adapt_search_functions = _adapt_search_functions_specialized


# ----------------------------------------------------------------------
# semantic_search + find_related — chunk-based dense rendering
# ----------------------------------------------------------------------
#
# These return `results[]` where each entry is a code CHUNK with full
# function body (or function span) in a `content` field — different
# shape from search_*'s match snippets. The old path (generic adapter)
# json.dumps(indent=2)'d the whole response and truncated at 15000
# chars, so the agent saw quoted/escaped/indented JSON with ~3-4 of
# 8 results bleeding past the cap. Now: dense block per chunk so the
# agent gets real readable source.
_MAX_OBS_CHUNKS = 100000000


def _render_chunks_dense(raw: dict[str, Any]) -> tuple[str, int]:
    """Render semantic_search / find_related results as dense source blocks.

    Each chunk renders as:
        === <file>:<start_line>-<end_line> [<lang>] score=<s> ===
        <content>

    Returns ``(rendered, count)``. Output is capped at _MAX_OBS_CHUNKS;
    chunks beyond the cap are dropped with a trailing marker.
    """
    results = raw.get("results") or raw.get("matches") or raw.get("hits") or []
    if not isinstance(results, list):
        return bounded_dump(raw, max_chars=_MAX_OBS_CHUNKS), 0
    blocks: list[str] = []
    total_chars = 0
    dropped = 0
    for r in results:
        if not isinstance(r, dict):
            continue
        fp = r.get("file_path") or r.get("file") or r.get("path") or "?"
        s_line = r.get("start_line") or r.get("line") or "?"
        e_line = r.get("end_line") or "?"
        lang = r.get("language") or "?"
        score = r.get("score")
        content = r.get("content") or r.get("body") or r.get("text") or ""
        if isinstance(content, list):
            content = "\n".join(str(x) for x in content)
        content = str(content).rstrip()
        score_tag = f"score={score:.3f} " if isinstance(score, (int, float)) else ""
        header = f"=== {fp}:{s_line}-{e_line} [{lang}] {score_tag}===\n"
        block = header + content + "\n"
        if total_chars + len(block) > _MAX_OBS_CHUNKS:
            dropped += 1
            continue
        blocks.append(block)
        total_chars += len(block)
    body = "\n".join(blocks)
    if dropped:
        body += (
            f"\n... [truncated — {dropped} of {len(results)} chunks omitted "
            f"past {_MAX_OBS_CHUNKS}-char cap; narrow query or filter_paths "
            f"to surface more]"
        )
    return body, len(results)


def adapt_semantic_search(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map semantic_search to TEXT with dense per-chunk rendering."""
    body, count = _render_chunks_dense(raw)
    query = str(ctx.args.get("query") or "")[:200]
    summary = f"semantic_search: count={count}, query={query[:80]!r}"
    payload = {
        "tool": "semantic_search",
        "match_count": count,
        "query": query,
        "chunks_text": body,
        "raw": raw,
        "source_provenance": provenance_stamp(ctx),
    }
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx, f"query={query[:60]}"): body},
        summary=summary,
    )


def adapt_find_related(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map find_related to TEXT with dense per-chunk rendering."""
    body, count = _render_chunks_dense(raw)
    seed = raw.get("seed") or {}
    seed_fp = seed.get("file_path") or ctx.args.get("file_path") or "?"
    seed_line = seed.get("start_line") or ctx.args.get("line") or "?"
    summary = f"find_related: count={count}, seed={seed_fp}:{seed_line}"
    payload = {
        "tool": "find_related",
        "match_count": count,
        "seed": {"file_path": seed_fp, "line": seed_line},
        "chunks_text": body,
        "raw": raw,
        "source_provenance": provenance_stamp(ctx),
    }
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx, f"seed={seed_fp}:{seed_line}"): body},
        summary=summary,
    )


# ----------------------------------------------------------------------
# read_lines — bridge-side virtual tool, raw file slice
# ----------------------------------------------------------------------


def adapt_read_lines(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map read_lines (bridge-side virtual) to DECOMPILED_FUNCTION shape.

    Loudly surfaces three conditions that mislead agents:
      (1) Requested range extended PAST end-of-file → agent gets nearly
          empty body and interprets it as truncation; without this banner
          they re-request the same range forever (observed live on
          WasmGcObject.cpp line 606-800: file ends at 606, agent looped).
      (2) Got significantly fewer lines than requested (file shorter).
      (3) Always-visible file-length header so the agent knows the file
          extent before assuming more content exists below.
    """
    file_path = str(raw.get("file_path") or ctx.args.get("file_path") or "?")
    requested_start = ctx.args.get("start")
    requested_end = ctx.args.get("end")
    start = raw.get("start_line") or requested_start or "?"
    end = raw.get("end_line") or requested_end or "?"
    total = raw.get("total_lines_in_file")
    body = str(raw.get("content") or "")
    line_count = body.count("\n") + (1 if body else 0)

    # Build loud header for EOF / short-read conditions.
    warnings: list[str] = []
    try:
        req_start_int = int(requested_start) if requested_start is not None else None
        req_end_int = int(requested_end) if requested_end is not None else None
    except (TypeError, ValueError):
        req_start_int = req_end_int = None
    if isinstance(total, int) and req_end_int is not None and req_end_int > total:
        warnings.append(
            f"!! REQUESTED RANGE EXCEEDS FILE LENGTH !! "
            f"You asked for lines {req_start_int}-{req_end_int} but "
            f"{file_path} has only {total} lines. Returned only the "
            f"in-bounds portion ({line_count} line{'s' if line_count != 1 else ''}). "
            f"The content you expected past line {total} DOES NOT EXIST in "
            f"this file. STOP re-requesting the same range. If you're "
            f"looking for a symbol that should be here, switch to "
            f"semantic_search(query=\"<symbol_name>\") — it will find the "
            f"file that actually contains it."
        )
    elif isinstance(total, int) and isinstance(end, int) and end < total - 50:
        warnings.append(
            f"[file extent: {total} lines total; you've read up to line "
            f"{end}. {total - end} more lines available below.]"
        )
    elif isinstance(total, int):
        warnings.append(f"[file extent: {total} lines total]")

    header = ""
    if warnings:
        header = "\n".join(warnings) + "\n\n"

    payload: dict[str, Any] = {
        "function_name": f"{file_path}:{start}-{end}",
        "address": f"{file_path}:{start}",
        "pseudocode": header + body,
        "line_count": line_count,
        "total_lines_in_file": total,
        "language": "",
        "source_provenance": provenance_stamp(ctx),
    }
    obs_body = (header + body)[:_MAX_OBS_READ_FUNCTION]
    if len(header) + len(body) > _MAX_OBS_READ_FUNCTION:
        obs_body += f"\n\n[truncated — full {line_count} lines in message {ctx.call_id}]"
    summary = f"read_lines {file_path}:{start}-{end} ({line_count} lines / {total} total)"
    if isinstance(total, int) and req_end_int and req_end_int > total:
        summary += "  ⚠ PAST EOF"
    return AdapterResult(
        payload_kind=PayloadKind.DECOMPILED_FUNCTION,
        payload=payload,
        observables_delta={
            obs_key_for(ctx, f"slice.{file_path}:{start}-{end}"): obs_body,
        },
        summary=summary,
    )
