"""Adapters for the REA MCP server (morluto/rea).

REA is the first external, MCP-native server: every result is a
canonical Evidence record delivered both as text content and as
``structuredContent`` (attached by the transport layer under
``raw["_mcp_structured"]``). The parsed text projection is the
Evidence record itself, so adapters read ``raw["normalized_result"]``
plus the record-level fields (``limitations``, ``evidence_id``,
``subject``, ``provider``).

Live-shape notes (recorded against rea-agents 6.8.0, Ghidra provider,
2026-10-30; payloads under ``C:/tmp/rea_probe/``):

* ``normalized_result`` is tool-specific:
    - ``procedure_pseudo_code`` / ``procedure_assembly``: a plain
      string (pseudocode text / ``"<addr>: <ins>"`` lines).
    - ``list_procedures`` / ``list_strings`` / ``list_segments`` /
      ``xrefs`` / ``procedure_callers`` / ``procedure_callees``: a
      plain list of rows (procedure rows ``{address, value, symbol,
      procedure}``; string rows ``{address, value, string}``; xref
      rows: bare address strings).
    - ``analyze_function``: a dossier dict (``procedure``,
      ``pseudocode``, ``assembly``, ``callers``, ``callees``,
      ``incoming_references``, ``outgoing_references``,
      ``unresolved_calls``, ``referenced_strings``,
      ``facet_availability``, ...). With the default detail it is an
      ``inspect_analysis_view`` summary projection instead
      (``kind``/``view``/``parent_evidence_id``/``coverage``/
      ``summary``) carrying NO dossier content -- the adapter says so
      rather than faking a body.
    - ``get_call_graph``: ``{graph: {"<depth>": [{address, status,
      calls, ...}]}, limitations}``.
    - ``procedure_references``: ``{procedure, direction, references:
      [{source_address, target_address, ...}], unresolved_calls}``.
    - ``binary_overview``: ``{document, image_base, segments,
      segment_count, procedure_count, string_count}``.
    - ``read_bytes``: ``{address, requested_bytes, returned_bytes,
      bytes_hex, complete}``.
    - ``inspect_pe_imports``: ``{artifact, imports: [{name,
      functions: [{name, ordinal, iat_rva}]}], imphash, ...}``.
    - ``inspect_native_exports`` / ``inspect_byte_entropy``: parsed
      PE/entropy dicts.
    - ``open_binary``: NO normalized_result; the body is under
      ``raw["result"]`` ({path, format, kind, sha256, architecture}).

REA facet-availability rule: a dossier facet may be declared
``{"available": false, "reason": ...}``; the adapters surface the
reason in the summary and an observable instead of inventing content.

Specialized set (everything else flows through ``adapt_generic``):

  - DECOMPILED_FUNCTION: procedure_pseudo_code, analyze_function
  - CODE_POINTER:      procedure_assembly
  - GRAPH_VIEW:        get_call_graph, trace_call_path
  - XREF_VIEW:         xrefs, procedure_callers, procedure_callees,
                       procedure_references, search_bytes
  - PATCH_DIFF:        compare_functions
  - TEXT:              open_binary, binary_overview, list_procedures,
                       list_strings, list_segments, procedure_info,
                       read_bytes, inspect_pe_imports,
                       inspect_native_exports, inspect_byte_entropy
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
    "adapt_rea_binary_overview",
    "adapt_rea_byte_entropy",
    "adapt_rea_call_graph",
    "adapt_rea_compare_functions",
    "adapt_rea_disassembly",
    "adapt_rea_list_procedures",
    "adapt_rea_list_segments",
    "adapt_rea_list_strings",
    "adapt_rea_native_exports",
    "adapt_rea_open_binary",
    "adapt_rea_pe_imports",
    "adapt_rea_procedure_callers",
    "adapt_rea_procedure_callees",
    "adapt_rea_procedure_info",
    "adapt_rea_procedure_references",
    "adapt_rea_pseudocode",
    "adapt_rea_read_bytes",
    "adapt_rea_search_bytes",
    "adapt_rea_trace_call_path",
    "adapt_rea_xrefs",
]


# ----------------------------------------------------------------------
# Evidence-record helpers
# ----------------------------------------------------------------------


def _normalized(raw: dict[str, Any]) -> Any:
    """Return the Evidence ``normalized_result`` (None when absent)."""
    return raw.get("normalized_result")


def _norm_dict(raw: dict[str, Any]) -> dict[str, Any]:
    """Return ``normalized_result`` when it is a dict, else {}."""
    inner = _normalized(raw)
    return inner if isinstance(inner, dict) else {}


def _norm_list(raw: dict[str, Any]) -> list[Any]:
    """Return ``normalized_result`` when it is a list, else []."""
    inner = _normalized(raw)
    return inner if isinstance(inner, list) else []


def _facet_unavailable(raw: dict[str, Any], facet: str) -> str | None:
    """Return the unavailable-reason for one dossier facet, or None.

    REA declares per-facet availability as
    ``normalized_result.facet_availability[facet] ==
    {"available": false, "reason": "..."}``.
    """
    availability = _norm_dict(raw).get("facet_availability")
    if not isinstance(availability, dict):
        return None
    entry = availability.get(facet)
    if not isinstance(entry, dict) or entry.get("available") is not False:
        return None
    reason = entry.get("reason")
    return str(reason) if reason else f"{facet} unavailable"


def _limitations(raw: dict[str, Any]) -> list[str]:
    """Return the Evidence limitations list (deduped, order-preserving).

    Dossier-shaped normalized results also carry their own
    ``limitations`` list; merge both levels.
    """
    out: list[str] = []
    sources: list[Any] = [raw.get("limitations")]
    norm = _norm_dict(raw).get("limitations")
    if norm is not None:
        sources.append(norm)
    for source in sources:
        if not isinstance(source, list):
            continue
        for item in source:
            text = str(item)
            if text not in out:
                out.append(text)
    return out


def _extract_pseudocode(normalized: dict[str, Any]) -> str:
    """Pull the pseudocode facet out of a function dossier defensively.

    The dossier facet layout is provider-versioned; try the known
    shapes (direct string, nested ``pseudocode.text``) and return the
    first non-empty string found.
    """
    facet = normalized.get("pseudocode")
    if isinstance(facet, str) and facet.strip():
        return facet
    if isinstance(facet, dict):
        for inner_key in ("text", "code", "body", "content"):
            inner = facet.get(inner_key)
            if isinstance(inner, str) and inner.strip():
                return inner
    return ""


def _proc_brief(proc: Any) -> str:
    """Render one procedure row/record as ``name@address`` (or str)."""
    if isinstance(proc, str):
        return proc
    if not isinstance(proc, dict):
        return str(proc)
    name = proc.get("name") or proc.get("value") or "<?>"
    address = proc.get("address")
    return f"{name}@{address}" if address else str(name)


def _procedure_arg(ctx: AdapterContext, *keys: str) -> str:
    """First non-empty string among ctx args and common spellings."""
    for key in keys or ("procedure", "function_name", "name", "address"):
        value = ctx.args.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _rows_preview(
    rows: list[Any], render, *, noun: str, target: str,
) -> str:
    """Dense multi-line observable body with a pagination hint.

    Mirrors the ida_headless xref renderer: when the result exceeds
    MAX_LIST_PREVIEW, the observable says exactly how to page (the
    full rows ride on the message payload).
    """
    lines = [render(row) for row in rows[:MAX_LIST_PREVIEW]]
    if len(rows) > MAX_LIST_PREVIEW:
        lines.append(
            f"  ... {len(rows) - MAX_LIST_PREVIEW} more row(s) suppressed "
            f"from this observable preview (cap={MAX_LIST_PREVIEW}). The "
            f"full list is on the message payload."
        )
    body = "\n".join(lines) if lines else "  (none)"
    return f"{len(rows)} {noun} for {target}:\n{body}"


# ----------------------------------------------------------------------
# DECOMPILED_FUNCTION family
# ----------------------------------------------------------------------


@is_read_tool("rea", "procedure_pseudo_code")
def adapt_rea_pseudocode(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``procedure_pseudo_code`` (plain-text result) to
    DECOMPILED_FUNCTION."""
    function_name = _procedure_arg(ctx) or "<unknown>"
    text = _normalized(raw)
    pseudocode = text.strip() if isinstance(text, str) else ""
    line_count = pseudocode.count("\n") + (1 if pseudocode else 0)

    payload: dict[str, Any] = {
        "function_name": function_name,
        "address": str(ctx.args.get("address") or ""),
        "pseudocode": pseudocode,
        "line_count": line_count,
        "language": "c",
        "evidence_id": raw.get("evidence_id"),
        "limitations": _limitations(raw),
        "source_provenance": provenance_stamp(ctx),
    }
    obs_value = pseudocode[:MAX_OBS_DUMP_CHARS]
    if len(pseudocode) > MAX_OBS_DUMP_CHARS:
        obs_value += "\n\n[truncated -- full text retained server-side]"

    if pseudocode:
        summary = f"Decompiled {function_name} via REA ({line_count} lines)"
    else:
        summary = (
            f"procedure_pseudo_code {function_name}: REA returned no "
            f"pseudocode text (provider may lack a decompiler view for "
            f"this procedure)"
        )
    return AdapterResult(
        payload_kind=PayloadKind.DECOMPILED_FUNCTION,
        payload=payload,
        observables_delta={
            obs_key_for(ctx, f"decompiled.{function_name}"): (
                obs_value if obs_value else summary
            ),
        },
        summary=summary,
    )


@is_read_tool("rea", "analyze_function")
def adapt_rea_analyze_function(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map an ``analyze_function`` Evidence record to DECOMPILED_FUNCTION.

    Two live shapes:

    * ``detail="complete"``: the full dossier -- pseudocode, assembly,
      callers, callees, reference edges, unresolved calls.
    * default detail: an ``inspect_analysis_view`` summary projection
      (kind/view/parent_evidence_id/coverage/summary) with NO dossier
      content; the adapter reports the retained parent evidence id and
      row counts instead of faking a body.
    """
    normalized = _norm_dict(raw)
    dossier = "pseudocode" in normalized or "procedure" in normalized
    if not dossier:
        # Summary projection: surface what the view actually carries.
        view_summary = normalized.get("summary")
        summary_fields = view_summary if isinstance(view_summary, dict) else {}
        row_count = summary_fields.get("row_count")
        parent_id = normalized.get("parent_evidence_id")
        proc_addr = normalized.get("procedure_address")
        function_name = _procedure_arg(ctx) or (
            str(proc_addr) if proc_addr else "<unknown>"
        )
        payload: dict[str, Any] = {
            "function_name": function_name,
            "address": str(proc_addr or ""),
            "pseudocode": "",
            "line_count": 0,
            "language": "c",
            "evidence_id": raw.get("evidence_id"),
            "parent_evidence_id": parent_id,
            "summary_projection": True,
            "view_summary": summary_fields,
            "limitations": _limitations(raw),
            "source_provenance": provenance_stamp(ctx),
        }
        summary = (
            f"analyze_function {function_name}: summary Evidence only"
            f" (row_count={row_count}); complete dossier retained as "
            f"{parent_id} -- re-call with detail=\"complete\" for "
            f"pseudocode/callers/callees"
        )
        return AdapterResult(
            payload_kind=PayloadKind.DECOMPILED_FUNCTION,
            payload=payload,
            observables_delta={
                obs_key_for(ctx, f"dossier.{function_name}"): summary,
            },
            summary=summary,
        )

    # Complete dossier.
    unavailable = _facet_unavailable(raw, "pseudocode")
    proc = normalized.get("procedure")
    proc = proc if isinstance(proc, dict) else {}
    function_name = str(proc.get("name") or _procedure_arg(ctx) or "<unknown>")
    address = str(proc.get("address") or normalized.get("address") or "")
    pseudocode = "" if unavailable else _extract_pseudocode(normalized)
    line_count = pseudocode.count("\n") + (1 if pseudocode else 0)

    callers = [
        _proc_brief(p) for p in normalized.get("callers") or [] if p
    ]
    callees = [
        _proc_brief(p) for p in normalized.get("callees") or [] if p
    ]
    unresolved = [
        str(u) for u in normalized.get("unresolved_calls") or []
    ]
    classification = proc.get("classification")
    body = proc.get("body")

    payload = {
        "function_name": function_name,
        "address": address,
        "pseudocode": pseudocode,
        "line_count": line_count,
        "language": "c",
        "evidence_id": raw.get("evidence_id"),
        "callers": callers,
        "callees": callees,
        "caller_count": len(callers),
        "callee_count": len(callees),
        "unresolved_calls": unresolved,
        "incoming_reference_count": len(
            normalized.get("incoming_references") or [],
        ),
        "outgoing_reference_count": len(
            normalized.get("outgoing_references") or [],
        ),
        "referenced_string_count": len(
            normalized.get("referenced_strings") or [],
        ),
        "classification": classification if isinstance(classification, dict) else {},
        "body": body if isinstance(body, dict) else {},
        "limitations": _limitations(raw),
        "source_provenance": provenance_stamp(ctx),
    }
    obs_value = pseudocode[:MAX_OBS_DUMP_CHARS]
    if len(pseudocode) > MAX_OBS_DUMP_CHARS:
        obs_value += "\n\n[truncated -- full dossier retained server-side]"

    if unavailable:
        summary = (
            f"analyze_function {function_name}: pseudocode unavailable "
            f"({unavailable}); {len(callees)} callees, {len(callers)} callers"
        )
    elif not pseudocode:
        summary = (
            f"analyze_function {function_name}: dossier has no pseudocode "
            f"facet; {len(callees)} callees, {len(callers)} callers"
        )
    else:
        summary = (
            f"Decompiled {function_name} via REA ({line_count} lines, "
            f"{len(callees)} callees, {len(callers)} callers)"
        )
    return AdapterResult(
        payload_kind=PayloadKind.DECOMPILED_FUNCTION,
        payload=payload,
        observables_delta={
            obs_key_for(ctx, f"decompiled.{function_name}"): (
                obs_value if obs_value else summary
            ),
        },
        summary=summary,
    )


# ----------------------------------------------------------------------
# CODE_POINTER family
# ----------------------------------------------------------------------


@is_read_tool("rea", "procedure_assembly")
def adapt_rea_disassembly(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``procedure_assembly`` (plain-text result) to CODE_POINTER."""
    function_name = _procedure_arg(ctx) or "<unknown>"
    text = _normalized(raw)
    body = text.strip() if isinstance(text, str) else ""
    lines = body.splitlines() if body else []
    payload: dict[str, Any] = {
        "label": f"assembly:{function_name}",
        "body": body,
        "line_count": len(lines),
        "instructions": lines,
        "raw": raw,
        "source_provenance": provenance_stamp(ctx),
    }
    obs_body = body[:MAX_OBS_DUMP_CHARS]
    if len(body) > MAX_OBS_DUMP_CHARS:
        obs_body += (
            f"\n... [truncated -- {len(lines)} lines total in message "
            f"{ctx.call_id}]"
        )
    obs_value = f"assembly:{function_name}:\n{obs_body}" if obs_body else (
        f"assembly:{function_name}: (no assembly returned)"
    )
    return AdapterResult(
        payload_kind=PayloadKind.CODE_POINTER,
        payload=payload,
        observables_delta={obs_key_for(ctx, f"asm.{function_name}"): obs_value},
        summary=f"assembly:{function_name} ({len(lines)} instructions)",
    )


# ----------------------------------------------------------------------
# GRAPH_VIEW family
# ----------------------------------------------------------------------


def _graph_nodes(raw: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    """Flatten REA's depth-keyed call graph into node rows."""
    normalized = _norm_dict(raw)
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
                rows.append({"depth": level, **node})
    return rows, len(rows)


@is_read_tool("rea", "get_call_graph")
def adapt_rea_call_graph(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``get_call_graph`` Evidence to GRAPH_VIEW.

    Live shape: ``normalized_result.graph`` maps depth -> node list;
    each node is ``{address, status, calls: [address...],
    relationship_coverage, limitations}``. Nodes carry addresses, not
    names -- the agent resolves a name via ``list_procedures`` or
    ``analyze_function``.
    """
    rows, total = _graph_nodes(raw)
    root = str(ctx.args.get("address") or ctx.args.get("procedure") or "")
    direction = str(ctx.args.get("direction") or "forward")
    preview = [
        {
            "depth": row.get("depth"),
            "address": row.get("address"),
            "status": row.get("status"),
            "calls": row.get("calls") if isinstance(row.get("calls"), list) else [],
        }
        for row in rows[:MAX_LIST_PREVIEW]
    ]
    depth_counts: dict[str, int] = {}
    for row in rows:
        depth = str(row.get("depth"))
        depth_counts[depth] = depth_counts.get(depth, 0) + 1
    payload: dict[str, Any] = {
        "root": root,
        "direction": direction,
        "nodes": rows,
        "depth_counts": depth_counts,
        "total": total,
        "limitations": _limitations(raw),
        "source_provenance": provenance_stamp(ctx),
    }
    summary = (
        f"REA call graph from {root or '<root>'} ({direction}): "
        f"{total} nodes across {len(depth_counts)} depth levels"
    )
    return AdapterResult(
        payload_kind=PayloadKind.GRAPH_VIEW,
        payload=payload,
        observables_delta={
            obs_key_for(ctx, f"call_graph.{root or 'root'}"): bounded_dump(
                {
                    "total": total,
                    "depth_counts": depth_counts,
                    "preview": preview,
                },
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
    normalized = _norm_dict(raw)
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
            obs_key_for(ctx, f"path.{source or 'src'}->{target or 'dst'}"): (
                bounded_dump(payload, max_chars=MAX_OBS_DUMP_CHARS)
            ),
        },
        summary=summary,
    )


# ----------------------------------------------------------------------
# XREF_VIEW family
# ----------------------------------------------------------------------


def _xref_payload_result(
    raw: dict[str, Any],
    ctx: AdapterContext,
    *,
    noun: str,
    target: str,
    obs_suffix: str,
    summary: str,
    rows: list[Any],
    payload: dict[str, Any],
) -> AdapterResult:
    """Shared XREF_VIEW envelope with the dense-rows observable."""
    payload.setdefault("limitations", _limitations(raw))
    payload.setdefault("source_provenance", provenance_stamp(ctx))
    obs_value = _rows_preview(rows, lambda r: f"  {_proc_brief(r)}", noun=noun, target=target)
    return AdapterResult(
        payload_kind=PayloadKind.XREF_VIEW,
        payload=payload,
        observables_delta={obs_key_for(ctx, f"{obs_suffix}.{target}"): obs_value},
        summary=summary,
    )


@is_read_tool("rea", "xrefs")
def adapt_rea_xrefs(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``xrefs`` (list of referencing addresses) to XREF_VIEW.

    Live shape: ``normalized_result`` is a bare list of hex address
    strings referencing the queried address (REA's xrefs_to analogue).
    """
    target = str(ctx.args.get("address") or "")
    rows = [str(r) for r in _norm_list(raw)]
    summary = f"REA xrefs to {target or '<?>'}: {len(rows)} referencing addresses"
    return _xref_payload_result(
        raw,
        ctx,
        noun="referencing addresses",
        target=target or "<?>",
        obs_suffix="xrefs_to",
        summary=summary,
        rows=rows,
        payload={"target_address": target, "xrefs": rows},
    )


@is_read_tool("rea", "procedure_callers")
def adapt_rea_procedure_callers(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``procedure_callers`` (list of caller rows) to XREF_VIEW."""
    procedure = _procedure_arg(ctx)
    rows = _norm_list(raw)
    briefs = [_proc_brief(r) for r in rows]
    summary = f"REA callers of {procedure or '<?>'}: {len(rows)} resolved"
    return _xref_payload_result(
        raw,
        ctx,
        noun="callers",
        target=procedure or "<?>",
        obs_suffix="callers",
        summary=summary,
        rows=rows,
        payload={"procedure": procedure, "callers": briefs},
    )


@is_read_tool("rea", "procedure_callees")
def adapt_rea_procedure_callees(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``procedure_callees`` (list of callee rows) to XREF_VIEW."""
    procedure = _procedure_arg(ctx)
    rows = _norm_list(raw)
    briefs = [_proc_brief(r) for r in rows]
    summary = f"REA callees of {procedure or '<?>'}: {len(rows)} resolved"
    return _xref_payload_result(
        raw,
        ctx,
        noun="callees",
        target=procedure or "<?>",
        obs_suffix="callees",
        summary=summary,
        rows=rows,
        payload={"procedure": procedure, "callees": briefs},
    )


@is_read_tool("rea", "procedure_references")
def adapt_rea_procedure_references(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``procedure_references`` edge list to XREF_VIEW.

    Live shape: ``normalized_result.references`` rows carry
    ``source_address`` / ``target_address`` (plus optional resolved
    procedure records per endpoint) and there may be
    ``unresolved_calls`` alongside.
    """
    normalized = _norm_dict(raw)
    proc = normalized.get("procedure")
    proc = proc if isinstance(proc, dict) else {}
    procedure = str(proc.get("name") or _procedure_arg(ctx) or "")
    address = str(proc.get("address") or ctx.args.get("procedure") or "")
    direction = str(normalized.get("direction") or ctx.args.get("direction") or "")
    references = normalized.get("references")
    rows = [r for r in references if isinstance(r, dict)] if isinstance(references, list) else []
    unresolved = [
        str(u) for u in normalized.get("unresolved_calls") or []
    ]

    def _edge_line(row: dict[str, Any]) -> str:
        src = row.get("source_address") or "<?>"
        dst = row.get("target_address") or "<?>"
        kind = row.get("kind") or row.get("reference_kind")
        if isinstance(kind, dict):
            # Ghidra reference-manager descriptor: surface the type.
            kind = kind.get("type")
        label = f"  {src} -> {dst}"
        if kind:
            label += f" ({kind})"
        return label

    target = procedure or address or "<?>"
    summary = (
        f"REA {direction or 'all'} references for {target}: "
        f"{len(rows)} edges, {len(unresolved)} unresolved"
    )
    payload: dict[str, Any] = {
        "procedure": procedure,
        "address": address,
        "direction": direction,
        "references": rows,
        "unresolved_calls": unresolved,
    }
    payload.setdefault("limitations", _limitations(raw))
    payload.setdefault("source_provenance", provenance_stamp(ctx))
    lines = [_edge_line(r) for r in rows[:MAX_LIST_PREVIEW]]
    if len(rows) > MAX_LIST_PREVIEW:
        lines.append(
            f"  ... {len(rows) - MAX_LIST_PREVIEW} more edge(s) on the "
            f"message payload (cap={MAX_LIST_PREVIEW})"
        )
    if unresolved:
        lines.append(f"  unresolved_calls: {', '.join(unresolved[:10])}")
    body = "\n".join(lines) if lines else "  (none)"
    obs_value = f"{len(rows)} {direction or 'all'} reference edges for {target}:\n{body}"
    return AdapterResult(
        payload_kind=PayloadKind.XREF_VIEW,
        payload=payload,
        observables_delta={obs_key_for(ctx, f"refs.{target}"): obs_value},
        summary=summary,
    )


@is_read_tool("rea", "search_bytes")
def adapt_rea_search_bytes(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``search_bytes`` matches to XREF_VIEW.

    Live shape: ``normalized_result.matches`` rows carry ``address``,
    ``segment``, ``file_offset`` and the containing ``procedure``
    record; ``next_cursor`` pages further matches.
    """
    normalized = _norm_dict(raw)
    matches = normalized.get("matches")
    rows = [m for m in matches if isinstance(m, dict)] if isinstance(matches, list) else []
    pattern = str(ctx.args.get("pattern") or "")
    next_cursor = normalized.get("next_cursor")
    complete = normalized.get("complete")

    def _match_line(row: dict[str, Any]) -> str:
        proc = row.get("procedure")
        proc_name = (
            (proc.get("name") or proc.get("address")) if isinstance(proc, dict) else None
        )
        label = f"  {row.get('address')} ({row.get('segment') or '?'})"
        if proc_name:
            label += f" in {proc_name}"
        return label

    summary = f"REA byte search '{pattern}': {len(rows)} matches"
    if next_cursor:
        summary += " (more pages available)"
    payload: dict[str, Any] = {
        "pattern": pattern,
        "matches": rows,
        "complete": complete,
        "next_cursor": next_cursor,
        "limitations": _limitations(raw),
        "source_provenance": provenance_stamp(ctx),
    }
    lines = [_match_line(r) for r in rows[:MAX_LIST_PREVIEW]]
    if len(rows) > MAX_LIST_PREVIEW:
        lines.append(
            f"  ... {len(rows) - MAX_LIST_PREVIEW} more match(es) on the "
            f"message payload (cap={MAX_LIST_PREVIEW})"
        )
    body = "\n".join(lines) if lines else "  (none)"
    obs_value = f"byte search '{pattern}': {len(rows)} matches\n{body}"
    return AdapterResult(
        payload_kind=PayloadKind.XREF_VIEW,
        payload=payload,
        observables_delta={obs_key_for(ctx, "byte_search"): obs_value},
        summary=summary,
    )


# ----------------------------------------------------------------------
# PATCH_DIFF family
# ----------------------------------------------------------------------


@is_read_tool("rea", "compare_functions")
def adapt_rea_compare_functions(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``compare_functions`` Evidence to PATCH_DIFF (dimension report)."""
    normalized = _norm_dict(raw)
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
            obs_key_for(ctx, "compare_functions"): bounded_dump(
                {"verdict": verdict, "dimensions": dim_rows[:MAX_LIST_PREVIEW]},
                max_chars=MAX_OBS_DUMP_CHARS,
            ),
        },
        summary=summary,
    )


# ----------------------------------------------------------------------
# TEXT specializations
# ----------------------------------------------------------------------


def _text_result(
    raw: dict[str, Any],
    ctx: AdapterContext,
    *,
    payload: dict[str, Any],
    summary: str,
    obs_suffix: str = "",
) -> AdapterResult:
    """Shared TEXT envelope: full structured payload + summary obs."""
    payload.setdefault("limitations", _limitations(raw))
    payload.setdefault("source_provenance", provenance_stamp(ctx))
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx, obs_suffix): summary},
        summary=summary,
    )


@is_read_tool("rea", "open_binary")
def adapt_rea_open_binary(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``open_binary`` to a structured TEXT status payload.

    Live shape: open_binary's Evidence has NO ``normalized_result``;
    the body is ``raw["result"]`` ({path, format, kind, sha256,
    architecture}). REA opens by absolute local path; the middleware
    drives it from the injected ``target_path``.
    """
    result = raw.get("result")
    result = result if isinstance(result, dict) else _norm_dict(raw)
    subject = raw.get("subject")
    if not result and isinstance(subject, dict):
        result = subject
    target = str(
        result.get("path")
        or result.get("target")
        or ctx.args.get("path")
        or ctx.args.get("target_path")
        or "",
    )
    provider = str(
        raw.get("provider")
        or result.get("provider")
        or result.get("provider_id")
        or "",
    )
    fmt = str(result.get("format") or "")
    architecture = str(result.get("architecture") or "")
    sha256 = str(result.get("sha256") or "")
    status = str(result.get("status") or raw.get("status") or "ready")
    payload: dict[str, Any] = {
        "target": target,
        "provider": provider,
        "format": fmt,
        "architecture": architecture,
        "sha256": sha256,
        "status": status,
        "evidence_id": raw.get("evidence_id"),
    }
    bits = [target] if target else []
    if fmt:
        bits.append(fmt)
    if architecture:
        bits.append(architecture)
    summary = f"REA target open: {' '.join(bits) or '(unknown)'}{f' ({provider})' if provider else ''} -- {status}"
    return _text_result(
        raw,
        ctx,
        payload=payload,
        summary=summary,
        obs_suffix="target",
    )


@is_read_tool("rea", "binary_overview")
def adapt_rea_binary_overview(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``binary_overview`` to a TEXT survey payload."""
    normalized = _norm_dict(raw)
    segments = normalized.get("segments")
    segment_rows = [s for s in segments if isinstance(s, dict)] if isinstance(segments, list) else []
    document = str(normalized.get("document") or "")
    image_base = str(normalized.get("image_base") or "")
    procedure_count = normalized.get("procedure_count")
    string_count = normalized.get("string_count")
    segment_count = normalized.get("segment_count")
    payload: dict[str, Any] = {
        "document": document,
        "image_base": image_base,
        "segment_count": segment_count,
        "procedure_count": procedure_count,
        "string_count": string_count,
        "segments": segment_rows,
    }
    seg_lines = [
        f"  {s.get('name')} {s.get('start')}-{s.get('end')}"
        for s in segment_rows[:MAX_LIST_PREVIEW]
    ]
    seg_body = "\n".join(seg_lines) if seg_lines else "  (none reported)"
    summary = (
        f"REA overview {document or '<?>'}: base {image_base or '?'}, "
        f"{procedure_count} procedures, {string_count} strings, "
        f"{segment_count} segments"
    )
    obs_value = (
        f"{summary}\nsegments:\n{seg_body}"
    )
    payload.setdefault("limitations", _limitations(raw))
    payload.setdefault("source_provenance", provenance_stamp(ctx))
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx, "overview"): obs_value},
        summary=summary,
    )


@is_read_tool("rea", "list_procedures")
def adapt_rea_list_procedures(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``list_procedures`` rows to a TEXT inventory payload.

    Live shape: list of ``{address, value, symbol, procedure}`` rows;
    ``address`` may be an ``EXTERNAL:0xN`` pseudo-address for imports.
    The summary-projection variant (detail default on some providers)
    carries no rows -- reported honestly.
    """
    normalized = _normalized(raw)
    if isinstance(normalized, dict) and "parent_evidence_id" in normalized and not isinstance(normalized.get("rows"), list):
        # inspect_analysis_view projection without row content.
        view_summary = normalized.get("summary")
        fields = view_summary.get("row_count") if isinstance(view_summary, dict) else None
        summary = (
            f"REA list_procedures: summary projection only "
            f"(row_count={fields}); re-call with detail=\"complete\" "
            f"for the address/name rows"
        )
        return _text_result(
            raw,
            ctx,
            payload={
                "summary_projection": True,
                "view_summary": view_summary if isinstance(view_summary, dict) else {},
                "procedures": [],
                "total": 0,
            },
            summary=summary,
            obs_suffix="procedures",
        )
    rows = [r for r in _norm_list(raw) if isinstance(r, dict)]
    total = len(rows)
    external = sum(
        1 for r in rows if str(r.get("address") or "").startswith("EXTERNAL:")
    )

    def _row_line(row: dict[str, Any]) -> str:
        return f"  {row.get('address')}  {row.get('value') or row.get('name') or '<?>'}"

    lines = [_row_line(r) for r in rows[:MAX_LIST_PREVIEW]]
    if total > MAX_LIST_PREVIEW:
        lines.append(
            f"  ... {total - MAX_LIST_PREVIEW} more procedure(s) on the "
            f"message payload (cap={MAX_LIST_PREVIEW})"
        )
    body = "\n".join(lines) if lines else "  (none)"
    payload = {
        "procedures": rows,
        "total": total,
        "external_count": external,
        "internal_count": total - external,
    }
    summary = f"REA procedures: {total} total ({external} external imports)"
    obs_value = f"{summary}\n{body}"
    payload.setdefault("limitations", _limitations(raw))
    payload.setdefault("source_provenance", provenance_stamp(ctx))
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx, "procedures"): obs_value},
        summary=summary,
    )


@is_read_tool("rea", "list_strings")
def adapt_rea_list_strings(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``list_strings`` rows to a TEXT inventory payload.

    Live shape: list of ``{address, value, string: {encoding,
    termination, byte_length}}`` rows.
    """
    rows = [r for r in _norm_list(raw) if isinstance(r, dict)]
    total = len(rows)

    def _row_line(row: dict[str, Any]) -> str:
        value = str(row.get("value") or "")
        meta = row.get("string")
        enc = meta.get("encoding") if isinstance(meta, dict) else None
        label = f"  {row.get('address')}  {value!r}"
        if enc:
            label += f" ({enc})"
        return label

    lines = [_row_line(r) for r in rows[:MAX_LIST_PREVIEW]]
    if total > MAX_LIST_PREVIEW:
        lines.append(
            f"  ... {total - MAX_LIST_PREVIEW} more string(s) on the "
            f"message payload (cap={MAX_LIST_PREVIEW})"
        )
    body = "\n".join(lines) if lines else "  (none)"
    payload = {"strings": rows, "total": total}
    summary = f"REA strings: {total} provider-reported strings"
    obs_value = f"{summary}\n{body}"
    payload.setdefault("limitations", _limitations(raw))
    payload.setdefault("source_provenance", provenance_stamp(ctx))
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx, "strings"): obs_value},
        summary=summary,
    )


@is_read_tool("rea", "list_segments")
def adapt_rea_list_segments(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``list_segments`` rows to a TEXT segments payload."""
    rows = [r for r in _norm_list(raw) if isinstance(r, dict)]
    total = len(rows)

    def _perm_flags(row: dict[str, Any]) -> str:
        flags = []
        perms = row.get("permissions")
        readable = writable = executable = None
        if isinstance(perms, dict) and perms.get("available"):
            readable = perms.get("readable")
            writable = perms.get("writable")
            executable = perms.get("executable")
        # Fall back to the top-level provider booleans (live Ghidra
        # rows carry both shapes).
        if readable is None:
            readable = row.get("readable")
        if writable is None:
            writable = row.get("writable")
        if executable is None:
            executable = row.get("executable")
        if readable:
            flags.append("r")
        if writable:
            flags.append("w")
        if executable:
            flags.append("x")
        return "".join(flags) or "?"

    def _row_line(row: dict[str, Any]) -> str:
        return (
            f"  {row.get('name')} {row.get('start')}-{row.get('end')} "
            f"[{_perm_flags(row)}]"
        )

    lines = [_row_line(r) for r in rows[:MAX_LIST_PREVIEW]]
    if total > MAX_LIST_PREVIEW:
        lines.append(
            f"  ... {total - MAX_LIST_PREVIEW} more segment(s) on the "
            f"message payload (cap={MAX_LIST_PREVIEW})"
        )
    body = "\n".join(lines) if lines else "  (none)"
    payload = {"segments": rows, "total": total}
    summary = f"REA segments: {total} memory blocks"
    obs_value = f"{summary}\n{body}"
    payload.setdefault("limitations", _limitations(raw))
    payload.setdefault("source_provenance", provenance_stamp(ctx))
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx, "segments"): obs_value},
        summary=summary,
    )


@is_read_tool("rea", "procedure_info")
def adapt_rea_procedure_info(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``procedure_info`` to a TEXT procedure metadata payload.

    Live shape: ``{name, symbol, entrypoint, basicblock_count, length,
    signature, locals, classification, body}`` -- the stack-frame /
    signature analogue of the old ida ``stack_frame`` mapping.
    """
    normalized = _norm_dict(raw)
    name = str(normalized.get("name") or _procedure_arg(ctx) or "<unknown>")
    locals_rows = [
        row for row in normalized.get("locals") or [] if isinstance(row, dict)
    ]
    body = normalized.get("body")
    body = body if isinstance(body, dict) else {}
    ranges = body.get("ranges") if isinstance(body.get("ranges"), list) else []
    payload: dict[str, Any] = {
        "name": name,
        "entrypoint": str(normalized.get("entrypoint") or ""),
        "signature": str(normalized.get("signature") or ""),
        "basicblock_count": normalized.get("basicblock_count"),
        "length": normalized.get("length"),
        "locals": locals_rows,
        "local_count": len(locals_rows),
        "symbol": normalized.get("symbol"),
        "classification": normalized.get("classification"),
        "body_ranges": ranges,
    }
    summary = (
        f"REA procedure_info {name}: entry {payload['entrypoint'] or '?'}, "
        f"{payload['basicblock_count']} basic blocks, {len(locals_rows)} "
        f"locals, sig {payload['signature'] or '?'}"
    )
    return _text_result(
        raw,
        ctx,
        payload=payload,
        summary=summary,
        obs_suffix=f"proc_info.{name}",
    )


def _ascii_preview(data: bytes, limit: int = 64) -> str:
    """Render a printable-ASCII preview of raw bytes ('.' otherwise)."""
    chunk = data[:limit]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


@is_read_tool("rea", "read_bytes")
def adapt_rea_read_bytes(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``read_bytes`` to a TEXT hex+ASCII payload.

    Live shape: ``{address, requested_bytes, returned_bytes, bytes_hex,
    complete}`` -- the read_memory analogue.
    """
    normalized = _norm_dict(raw)
    hex_text = str(normalized.get("bytes_hex") or "")
    data = b""
    try:
        data = bytes.fromhex(hex_text) if hex_text else b""
    except ValueError:
        data = b""
    payload: dict[str, Any] = {
        "address": str(normalized.get("address") or ctx.args.get("address") or ""),
        "requested_bytes": normalized.get("requested_bytes"),
        "returned_bytes": normalized.get("returned_bytes"),
        "bytes_hex": hex_text,
        "ascii_preview": _ascii_preview(data),
        "complete": normalized.get("complete"),
    }
    summary = (
        f"REA read_bytes {payload['address'] or '?'}: "
        f"{normalized.get('returned_bytes')} bytes returned"
        f"{'' if normalized.get('complete') else ' (incomplete)'}"
    )
    return _text_result(
        raw,
        ctx,
        payload=payload,
        summary=summary,
        obs_suffix=f"bytes.{payload['address'] or 'addr'}",
    )


@is_read_tool("rea", "inspect_pe_imports")
def adapt_rea_pe_imports(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``inspect_pe_imports`` to a TEXT import-table payload.

    Live shape: ``{artifact, imports: [{name, functions: [{name,
    ordinal, iat_rva, ...}]}], delay_imports, imphash}``.
    """
    normalized = _norm_dict(raw)
    imports = normalized.get("imports")
    dll_rows = [d for d in imports if isinstance(d, dict)] if isinstance(imports, list) else []
    delay = normalized.get("delay_imports")
    delay_rows = [d for d in delay if isinstance(d, dict)] if isinstance(delay, list) else []
    imphash = normalized.get("imphash")
    imphash_md5 = imphash.get("md5") if isinstance(imphash, dict) else None
    function_count = sum(
        len(d.get("functions") or []) for d in dll_rows if isinstance(d.get("functions"), list)
    )
    lines = []
    for dll in dll_rows[:MAX_LIST_PREVIEW]:
        functions = dll.get("functions")
        names = [
            str(f.get("name") or f"?ordinal {f.get('ordinal')}")
            for f in functions[:12]
            if isinstance(f, dict)
        ] if isinstance(functions, list) else []
        more = len(functions) - len(names) if isinstance(functions, list) else 0
        suffix = f", +{more} more" if more > 0 else ""
        lines.append(f"  {dll.get('name')}: {', '.join(names)}{suffix}")
    if len(dll_rows) > MAX_LIST_PREVIEW:
        lines.append(
            f"  ... {len(dll_rows) - MAX_LIST_PREVIEW} more DLL(s) on the "
            f"message payload (cap={MAX_LIST_PREVIEW})"
        )
    body = "\n".join(lines) if lines else "  (no import directory)"
    payload: dict[str, Any] = {
        "artifact": normalized.get("artifact"),
        "format": normalized.get("format"),
        "architecture": normalized.get("architecture"),
        "imports": dll_rows,
        "delay_imports": delay_rows,
        "dll_count": len(dll_rows),
        "function_count": function_count,
        "imphash": imphash,
    }
    summary = (
        f"REA PE imports: {len(dll_rows)} DLLs, {function_count} functions"
        f"{f', imphash {imphash_md5}' if imphash_md5 else ''}"
    )
    obs_value = f"{summary}\n{body}"
    payload.setdefault("limitations", _limitations(raw))
    payload.setdefault("source_provenance", provenance_stamp(ctx))
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx, "pe_imports"): obs_value},
        summary=summary,
    )


@is_read_tool("rea", "inspect_native_exports")
def adapt_rea_native_exports(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``inspect_native_exports`` to a TEXT export-table payload."""
    normalized = _norm_dict(raw)
    exports = normalized.get("exports")
    rows = [e for e in exports if isinstance(e, dict)] if isinstance(exports, list) else []
    coverage = normalized.get("coverage")
    coverage = coverage if isinstance(coverage, dict) else {}

    def _row_line(row: dict[str, Any]) -> str:
        name = row.get("name") or f"ordinal {row.get('ordinal')}"
        return f"  {name} @ {row.get('rva') or row.get('address') or '?'}"

    lines = [_row_line(r) for r in rows[:MAX_LIST_PREVIEW]]
    if len(rows) > MAX_LIST_PREVIEW:
        lines.append(
            f"  ... {len(rows) - MAX_LIST_PREVIEW} more export(s) on the "
            f"message payload (cap={MAX_LIST_PREVIEW})"
        )
    body = "\n".join(lines) if lines else "  (no exports)"
    payload: dict[str, Any] = {
        "artifact": normalized.get("artifact"),
        "format": normalized.get("format"),
        "exports": rows,
        "export_count": len(rows),
        "coverage": coverage,
        "issues": normalized.get("issues") or [],
    }
    summary = (
        f"REA native exports: {len(rows)} exports "
        f"(coverage {coverage.get('status') or '?'})"
    )
    obs_value = f"{summary}\n{body}"
    payload.setdefault("limitations", _limitations(raw))
    payload.setdefault("source_provenance", provenance_stamp(ctx))
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx, "exports"): obs_value},
        summary=summary,
    )


@is_read_tool("rea", "inspect_byte_entropy")
def adapt_rea_byte_entropy(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``inspect_byte_entropy`` to a TEXT entropy report.

    Live shape: ``{file_entropy, block_size, blocks: [{offset,
    entropy}], runs, thresholds}`` -- the entropy_analysis analogue.
    """
    normalized = _norm_dict(raw)
    blocks = normalized.get("blocks")
    block_rows = [b for b in blocks if isinstance(b, dict)] if isinstance(blocks, list) else []
    thresholds = normalized.get("thresholds")
    thresholds = thresholds if isinstance(thresholds, dict) else {}
    high = thresholds.get("high")
    high_blocks = [
        b for b in block_rows
        if isinstance(b.get("entropy"), (int, float))
        and isinstance(high, (int, float))
        and b["entropy"] >= high
    ]
    runs = normalized.get("runs")
    run_rows = [r for r in runs if isinstance(r, dict)] if isinstance(runs, list) else []
    file_entropy = normalized.get("file_entropy")
    payload: dict[str, Any] = {
        "artifact": normalized.get("artifact"),
        "file_entropy": file_entropy,
        "block_size": normalized.get("block_size"),
        "thresholds": thresholds,
        "blocks": block_rows,
        "high_entropy_blocks": high_blocks,
        "high_entropy_block_count": len(high_blocks),
        "runs": run_rows,
    }
    summary = (
        f"REA byte entropy: file {file_entropy}"
        f"{f' (high>={high})' if high is not None else ''}: "
        f"{len(high_blocks)}/{len(block_rows)} blocks over threshold, "
        f"{len(run_rows)} runs"
    )
    return _text_result(
        raw,
        ctx,
        payload=payload,
        summary=summary,
        obs_suffix="entropy",
    )
