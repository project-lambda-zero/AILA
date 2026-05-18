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
]


# Bumped from 3000 → 12000 after observing the agent loop on
# read_function for nginx's ngx_http_script_regex_start_code (154
# lines, 3669 chars). At 3000 the agent saw a truncated head + a
# truncation marker pointing at a message id it couldn't fetch, so
# it kept re-issuing read_function expecting different results.
# 12000 chars covers ~99% of real-world C functions while still
# bounding case_state growth across many tool calls.
_MAX_OBS_READ_FUNCTION = 12000


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
    """Map ``fuzzing_targets`` to TEXT payload with ranked function list."""
    targets = _list_or_empty(raw, "targets", "results")
    summary_lines: list[str] = []
    for entry in targets[:MAX_LIST_PREVIEW]:
        if not isinstance(entry, dict):
            continue
        name = (
            entry.get("function_name")
            or entry.get("name")
            or entry.get("symbol")
            or "<unnamed>"
        )
        bits: list[str] = []
        for k in ("risk_score", "score", "priority"):
            if entry.get(k) is not None:
                bits.append(f"score={entry[k]}")
                break
        if entry.get("blast_radius") is not None:
            bits.append(f"blast={entry['blast_radius']}")
        if entry.get("complexity") is not None:
            bits.append(f"complexity={entry['complexity']}")
        suffix = f" ({', '.join(bits)})" if bits else ""
        summary_lines.append(f"  - {name}{suffix}")
    if len(targets) > MAX_LIST_PREVIEW:
        summary_lines.append(f"  ... and {len(targets) - MAX_LIST_PREVIEW} more")

    obs_value = (
        f"audit-mcp fuzzing_targets ({len(targets)} candidates):\n"
        + ("\n".join(summary_lines) if summary_lines else "  (none)")
    )

    payload: dict[str, Any] = {
        "text": (
            f"audit-mcp fuzzing_targets returned {len(targets)} candidates "
            f"(graph-aware ranking)"
        ),
        "tool": f"{ctx.mcp_server_id}.{ctx.tool_name}",
        "targets": targets,
        "total": len(targets),
        "source_provenance": provenance_stamp(ctx),
    }
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx): obs_value},
        summary=f"{len(targets)} ranked fuzzing target candidates",
    )


def adapt_attack_surface(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``attack_surface`` to TEXT payload (entry-point catalog)."""
    surfaces = _list_or_empty(raw, "surfaces", "entries", "results")
    bullets: list[str] = []
    for s in surfaces[:MAX_LIST_PREVIEW]:
        if not isinstance(s, dict):
            continue
        name = s.get("name") or s.get("symbol") or s.get("route") or "<?>"
        kind = s.get("kind") or s.get("surface_kind") or "entry"
        loc = s.get("file") or s.get("path") or ""
        line = s.get("line")
        loc_str = f" @ {loc}:{line}" if loc and line else (f" @ {loc}" if loc else "")
        bullets.append(f"  - [{kind}] {name}{loc_str}")
    if len(surfaces) > MAX_LIST_PREVIEW:
        bullets.append(f"  ... and {len(surfaces) - MAX_LIST_PREVIEW} more")
    obs_value = (
        f"attack_surface: {len(surfaces)} entry point(s)\n"
        + ("\n".join(bullets) if bullets else "  (none)")
    )
    payload: dict[str, Any] = {
        "text": obs_value,
        "tool": f"{ctx.mcp_server_id}.{ctx.tool_name}",
        "surfaces": surfaces,
        "total": len(surfaces),
        "source_provenance": provenance_stamp(ctx),
    }
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx): obs_value},
        summary=f"{len(surfaces)} attack surface entries",
    )


def adapt_complexity_hotspots(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``complexity_hotspots`` to TEXT payload (top complex functions)."""
    hotspots = _list_or_empty(raw, "hotspots", "functions", "results")
    bullets: list[str] = []
    for h in hotspots[:MAX_LIST_PREVIEW]:
        if not isinstance(h, dict):
            continue
        name = h.get("function_name") or h.get("name") or h.get("symbol") or "<?>"
        cyc = h.get("cyclomatic") or h.get("cyclomatic_complexity")
        cog = h.get("cognitive") or h.get("cognitive_complexity")
        path = h.get("file") or h.get("path") or ""
        line = h.get("line")
        loc_str = f" @ {path}:{line}" if path and line else (f" @ {path}" if path else "")
        bits: list[str] = []
        if cyc is not None:
            bits.append(f"cyc={cyc}")
        if cog is not None:
            bits.append(f"cog={cog}")
        suffix = f" ({', '.join(bits)})" if bits else ""
        bullets.append(f"  - {name}{loc_str}{suffix}")
    if len(hotspots) > MAX_LIST_PREVIEW:
        bullets.append(f"  ... and {len(hotspots) - MAX_LIST_PREVIEW} more")
    obs_value = (
        f"complexity_hotspots: {len(hotspots)} function(s)\n"
        + ("\n".join(bullets) if bullets else "  (none)")
    )
    payload: dict[str, Any] = {
        "text": obs_value,
        "tool": f"{ctx.mcp_server_id}.{ctx.tool_name}",
        "hotspots": hotspots,
        "total": len(hotspots),
        "source_provenance": provenance_stamp(ctx),
    }
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx): obs_value},
        summary=f"{len(hotspots)} complexity hotspots",
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
    payload: dict[str, Any] = {
        target_field: target,
        "xrefs": refs,
        "total": len(refs),
        "source_provenance": provenance_stamp(ctx),
    }
    lines = [
        _audit_xref_compact_line(r)
        for r in refs[:MAX_LIST_PREVIEW]
        if isinstance(r, dict)
    ]
    if len(refs) > MAX_LIST_PREVIEW:
        lines.append(f"  ... and {len(refs) - MAX_LIST_PREVIEW} more")
    body = "\n".join(lines) if lines else "  (none)"
    obs_value = f"{summary_noun} of {target} ({len(refs)}):\n{body}"
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
    # audit-mcp's read_function returns ``body`` as a list of source
    # lines (and ``start_line``/``end_line`` as int positions). Earlier
    # MCP versions and IDA's decompile return a flat ``source``/``text``
    # string. Accept both — when ``body`` is a list, join with newlines
    # so the agent sees real source instead of the Python list repr.
    raw_body = raw.get("source") or raw.get("body") or raw.get("text") or ""
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
    obs_value = body[:_MAX_OBS_READ_FUNCTION]
    if len(body) > _MAX_OBS_READ_FUNCTION:
        obs_value += f"\n\n[truncated — full {line_count} lines in message {ctx.call_id}]"
    return AdapterResult(
        payload_kind=PayloadKind.DECOMPILED_FUNCTION,
        payload=payload,
        observables_delta={obs_key_for(ctx, f"source.{fn_name}"): obs_value},
        summary=f"read_function {fn_name} ({line_count} lines, lang={language or '?'})",
    )
