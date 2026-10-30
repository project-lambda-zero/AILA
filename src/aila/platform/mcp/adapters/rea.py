"""Adapters for the REA MCP server (morluto/rea).

REA is the first external, MCP-native server: every result is a
canonical Evidence record (``normalized_result`` + ``limitations`` +
``evidence_id`` + optional ``analysis_profile``), delivered both as
text content and as ``structuredContent``. The transport layer
(:mod:`aila.platform.mcp.client`) already parsed the text projection
into the dispatch body, so adapters here read the Evidence fields
directly off the raw dict; the typed record is additionally available
under ``raw["_mcp_structured"]`` when a consumer needs the exact
envelope.

Specialized set (everything else flows through ``adapt_generic``):

  - DECOMPILED_FUNCTION: analyze_function (pseudocode facet of the
    function dossier; ``detail: "summary"`` replies carry an
    inspect-view reference instead of pseudocode -- the adapter says
    so in the summary rather than faking a body)
  - GRAPH_VIEW:          get_call_graph (depth-keyed graph), and
    trace_call_path (observed-edge path with residual unknowns)
  - PATCH_DIFF:          compare_functions (dimension-keyed equality
    report between two function dossiers)

REA facet-availability rule: a dossier facet may be declared
``{"available": false, "reason": ...}``; the adapters surface the
reason in the summary and an observable instead of inventing content.
"""
from __future__ import annotations

from typing import Any

from aila.platform.contracts.mcp_payload import PayloadKind

from ._shared import (
    MAX_LIST_PREVIEW,
    MAX_OBS_DUMP_CHARS,
    bounded_dump,
    obs_key_for,
    provenance_stamp,
)
from .base import AdapterContext, AdapterResult, is_read_tool

__all__ = [
    "adapt_rea_analyze_function",
    "adapt_rea_call_graph",
    "adapt_rea_trace_call_path",
    "adapt_rea_compare_functions",
    "adapt_rea_open_binary",
]



def _normalized(raw: dict[str, Any]) -> dict[str, Any]:
    """Return the Evidence normalized_result dict (empty when absent)."""
    inner = raw.get("normalized_result")
    return inner if isinstance(inner, dict) else {}


def _facet_unavailable(raw: dict[str, Any], facet: str) -> str | None:
    """Return the unavailable-reason for one dossier facet, or None.

    REA declares per-facet availability as
    ``normalized_result.facet_availability[facet] ==
    {"available": false, "reason": "..."}``.
    """
    availability = _normalized(raw).get("facet_availability")
    if not isinstance(availability, dict):
        return None
    entry = availability.get(facet)
    if not isinstance(entry, dict) or entry.get("available") is not False:
        return None
    reason = entry.get("reason")
    return str(reason) if reason else f"{facet} unavailable"


def _limitations(raw: dict[str, Any]) -> list[str]:
    """Return the Evidence limitations list (deduped, order-preserving)."""
    raw_limits = raw.get("limitations")
    if not isinstance(raw_limits, list):
        return []
    out: list[str] = []
    for item in raw_limits:
        text = str(item)
        if text not in out:
            out.append(text)
    return out


def _extract_pseudocode(normalized: dict[str, Any]) -> str:
    """Pull the pseudocode facet out of a function dossier defensively.

    The dossier facet layout is provider-versioned; try the known
    shapes (direct key, nested ``pseudocode.text``, decompiler result
    container) and return the first string found.
    """
    for key in ("pseudocode", "decompiled", "pseudo_code"):
        facet = normalized.get(key)
        if isinstance(facet, str) and facet.strip():
            return facet
        if isinstance(facet, dict):
            for inner_key in ("text", "code", "body", "content"):
                inner = facet.get(inner_key)
                if isinstance(inner, str) and inner.strip():
                    return inner
    return ""


@is_read_tool("rea", "analyze_function")
def adapt_rea_analyze_function(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map an ``analyze_function`` Evidence record to DECOMPILED_FUNCTION."""
    normalized = _normalized(raw)
    unavailable = _facet_unavailable(raw, "pseudocode")
    function_name = str(
        ctx.args.get("function_name")
        or ctx.args.get("name")
        or normalized.get("name")
        or normalized.get("function_name")
        or "<unknown>",
    )
    address = str(
        normalized.get("address")
        or normalized.get("entry_address")
        or ctx.args.get("address")
        or "",
    )
    pseudocode = "" if unavailable else _extract_pseudocode(normalized)
    parent_id = normalized.get("parent_evidence_id")

    payload: dict[str, Any] = {
        "function_name": function_name,
        "address": address,
        "pseudocode": pseudocode,
        "line_count": pseudocode.count("\n") + (1 if pseudocode else 0),
        "language": "c",
        "evidence_id": raw.get("evidence_id"),
        "limitations": _limitations(raw),
        "source_provenance": provenance_stamp(ctx),
    }
    if parent_id:
        # detail:"summary" replies name the retained complete dossier;
        # page it with inspect_analysis_view.
        payload["parent_evidence_id"] = parent_id

    obs_value = pseudocode[:MAX_OBS_DUMP_CHARS]
    if len(pseudocode) > MAX_OBS_DUMP_CHARS:
        obs_value += "\n\n[truncated -- full dossier retained server-side]"

    if unavailable:
        summary = (
            f"analyze_function {function_name}: pseudocode unavailable "
            f"({unavailable})"
        )
    elif not pseudocode and parent_id:
        summary = (
            f"analyze_function {function_name}: summary Evidence only; "
            f"dossier {parent_id} paged via inspect_analysis_view"
        )
    else:
        lines = payload["line_count"]
        summary = f"Decompiled {function_name} via REA ({lines} lines)"

    return AdapterResult(
        payload_kind=PayloadKind.DECOMPILED_FUNCTION,
        payload=payload,
        observables_delta={
            obs_key_for(ctx, f"rea.decompiled.{function_name}"): (
                obs_value if obs_value else summary
            ),
        },
        summary=summary,
    )


def _graph_nodes(raw: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    """Flatten REA's depth-keyed call graph into node rows."""
    normalized = _normalized(raw)
    graph = normalized.get("graph")
    if not isinstance(graph, dict):
        # Older/newer layouts may carry a plain node list.
        nodes = normalized.get("nodes")
        if isinstance(nodes, list):
            return [n for n in nodes if isinstance(n, dict)], len(nodes)
        return [], 0
    rows: list[dict[str, Any]] = []
    for level in sorted(graph.keys()):
        members = graph.get(level)
        if not isinstance(members, list):
            continue
        for node in members:
            if isinstance(node, dict):
                rows.append({"level": level, **node})
    return rows, len(rows)


@is_read_tool("rea", "get_call_graph")
def adapt_rea_call_graph(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``get_call_graph`` Evidence to GRAPH_VIEW."""
    rows, total = _graph_nodes(raw)
    root = str(
        ctx.args.get("function_name")
        or ctx.args.get("address")
        or _normalized(raw).get("root")
        or "",
    )
    preview = [
        {
            "level": row.get("level"),
            "name": row.get("name") or row.get("function_name"),
            "address": row.get("address"),
            "calls": row.get("calls") if isinstance(row.get("calls"), list) else None,
        }
        for row in rows[:MAX_LIST_PREVIEW]
    ]
    payload: dict[str, Any] = {
        "root": root,
        "nodes": rows,
        "total": total,
        "limitations": _limitations(raw),
        "source_provenance": provenance_stamp(ctx),
    }
    summary = f"REA call graph from {root or '<root>'}: {total} nodes"
    return AdapterResult(
        payload_kind=PayloadKind.GRAPH_VIEW,
        payload=payload,
        observables_delta={
            obs_key_for(ctx, f"rea.call_graph.{root or 'root'}"): bounded_dump(
                {"total": total, "preview": preview},
                max_chars=MAX_OBS_DUMP_CHARS,
            ),
        },
        summary=summary,
    )


@is_read_tool("rea", "trace_call_path")
def adapt_rea_trace_call_path(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``trace_call_path`` Evidence to GRAPH_VIEW (observed-edge path)."""
    normalized = _normalized(raw)
    path = normalized.get("path")
    path_rows = [p for p in path if isinstance(p, dict)] if isinstance(path, list) else []
    residual = normalized.get("residual_unknowns")
    residual_rows = (
        [r for r in residual if isinstance(r, dict)] if isinstance(residual, list) else []
    )
    truncated = normalized.get("truncated") is True
    goal_status = str(normalized.get("goal_status") or "")
    source = str(ctx.args.get("source") or ctx.args.get("from") or "")
    target = str(ctx.args.get("target") or ctx.args.get("to") or "")
    payload: dict[str, Any] = {
        "source": source,
        "target": target,
        "path": path_rows,
        "goal_status": goal_status,
        "truncated": truncated,
        "residual_unknowns": residual_rows,
        "limitations": _limitations(raw),
        "source_provenance": provenance_stamp(ctx),
    }
    summary = (
        f"REA path {source or '?'} -> {target or '?'}: "
        f"{len(path_rows)} observed edges, goal {goal_status or 'unknown'}"
        f"{', truncated' if truncated else ''}"
    )
    return AdapterResult(
        payload_kind=PayloadKind.GRAPH_VIEW,
        payload=payload,
        observables_delta={
            obs_key_for(ctx, f"rea.path.{source or 'src'}->{target or 'dst'}"): (
                bounded_dump(payload, max_chars=MAX_OBS_DUMP_CHARS)
            ),
        },
        summary=summary,
    )


@is_read_tool("rea", "compare_functions")
def adapt_rea_compare_functions(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``compare_functions`` Evidence to PATCH_DIFF (dimension report)."""
    normalized = _normalized(raw)
    dimensions = normalized.get("dimensions")
    dim_rows = (
        [d for d in dimensions if isinstance(d, dict)] if isinstance(dimensions, list) else []
    )
    if isinstance(dimensions, dict):
        dim_rows = [
            {"dimension": key, **value} if isinstance(value, dict) else {"dimension": key, "status": value}
            for key, value in dimensions.items()
        ]
    verdict = str(normalized.get("verdict") or normalized.get("status") or "unknown")
    payload: dict[str, Any] = {
        "verdict": verdict,
        "dimensions": dim_rows,
        "left": bounded_dump(normalized.get("left"), max_chars=4096),
        "right": bounded_dump(normalized.get("right"), max_chars=4096),
        "limitations": _limitations(raw),
        "source_provenance": provenance_stamp(ctx),
    }
    changed = [d for d in dim_rows if str(d.get("status")) == "changed"]
    summary = (
        f"REA compare_functions: {verdict} "
        f"({len(changed)}/{len(dim_rows)} dimensions changed)"
    )
    return AdapterResult(
        payload_kind=PayloadKind.PATCH_DIFF,
        payload=payload,
        observables_delta={
            obs_key_for(ctx, "rea.compare_functions"): bounded_dump(
                {"verdict": verdict, "dimensions": dim_rows[:MAX_LIST_PREVIEW]},
                max_chars=MAX_OBS_DUMP_CHARS,
            ),
        },
        summary=summary,
    )


def adapt_rea_open_binary(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``open_binary`` Evidence to a structured TEXT status payload."""
    normalized = _normalized(raw)
    target = str(
        normalized.get("target") or normalized.get("path") or ctx.args.get("path") or "",
    )
    provider = str(
        normalized.get("provider") or normalized.get("provider_id") or "",
    )
    status = str(normalized.get("status") or raw.get("status") or "ready")
    payload: dict[str, Any] = {
        "target": target,
        "provider": provider,
        "status": status,
        "evidence_id": raw.get("evidence_id"),
        "limitations": _limitations(raw),
        "source_provenance": provenance_stamp(ctx),
    }
    summary = f"REA target open: {target} ({provider or 'auto'}) -- {status}"
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx, "rea.target"): summary},
        summary=summary,
    )
