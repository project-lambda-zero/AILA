"""Adapters for the IDA Headless MCP server.

Specialized adapters defined here ship structured payloads keyed by
``PayloadKind``. Every IDA tool not listed here still works via the
generic fallback in ``generic.py`` (registered via ``KNOWN_TOOLS``).

Specialized v0.3 v2 set:
  - DECOMPILED_FUNCTION: decompile
  - XREF_VIEW:           find_api_call_sites, xrefs_to, xrefs_from
  - TAINT_FLOW:          interprocedural_taint, trace_dataflow, def_use
  - GRAPH_VIEW:          call_graph, call_chain
  - CODE_POINTER:        disassemble_function, get_microcode,
                         pseudocode_slice_view
  - PATCH_DIFF:          diff_function
  - TEXT (structured):   checksec, classify_behavior, capa_scan
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.contracts import PayloadKind

from ._shared import (
    MAX_LIST_PREVIEW,
    MAX_OBS_DUMP_CHARS,
    bounded_dump,
    obs_key_for,
    provenance_stamp,
)
from .base import AdapterContext, AdapterResult, is_read_tool

__all__ = [
    "adapt_decompile",
    "adapt_find_api_call_sites",
    "adapt_xrefs_to",
    "adapt_xrefs_from",
    "adapt_interprocedural_taint",
    "adapt_trace_dataflow",
    "adapt_def_use",
    "adapt_call_graph",
    "adapt_call_chain",
    "adapt_disassemble_function",
    "adapt_get_microcode",
    "adapt_pseudocode_slice_view",
    "adapt_diff_function",
    "adapt_checksec",
    "adapt_classify_behavior",
    "adapt_capa_scan",
]


# fix §278 — pseudocode / disasm observable caps are the shared
# MAX_OBS_DUMP_CHARS (32 KiB). The prior comment narrated a "50000
# chars covers ~600 lines" budget but the constants had drifted to
# 100 MB — the bounded-slice rationale was code-comment fiction.
# Specialised renderers downstream still keep the raw response in
# the message store; only the observable preview rides this cap.
# fix §279 — _MAX_OBS_CALLSITES previously sat at 25 alongside the
# shared MAX_LIST_PREVIEW (20). One list-preview convention across
# every adapter; if a specific tool ever needs a wider preview we
# pass the cap explicitly at the call site instead of growing the
# global constant.


def _list_or_empty(raw: dict[str, Any], *keys: str) -> list[Any]:
    """Return the first list-valued key from ``raw`` (or [])."""
    for k in keys:
        v = raw.get(k)
        if isinstance(v, list):
            return v
    return []


# ----------------------------------------------------------------------
# DECOMPILED_FUNCTION
# ----------------------------------------------------------------------


@is_read_tool("ida_headless", "decompile")
def adapt_decompile(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Map ``decompile`` response to DECOMPILED_FUNCTION payload."""
    function_name = str(raw.get("function_name") or raw.get("name") or "<unknown>")
    address = str(raw.get("address") or ctx.args.get("address_or_name") or "")
    pseudocode = str(raw.get("pseudocode") or "")
    line_count = pseudocode.count("\n") + (1 if pseudocode else 0)

    payload: dict[str, Any] = {
        "function_name": function_name,
        "address": address,
        "pseudocode": pseudocode,
        "line_count": line_count,
        "language": "c",
        "source_provenance": provenance_stamp(ctx),
    }

    obs_value = pseudocode[:MAX_OBS_DUMP_CHARS]
    if len(pseudocode) > MAX_OBS_DUMP_CHARS:
        obs_value += f"\n\n[truncated — full {line_count} lines in message {ctx.call_id}]"

    return AdapterResult(
        payload_kind=PayloadKind.DECOMPILED_FUNCTION,
        payload=payload,
        observables_delta={obs_key_for(ctx, f"decompiled.{function_name}"): obs_value},
        summary=f"Decompiled {function_name} ({line_count} lines)",
    )


# ----------------------------------------------------------------------
# XREF_VIEW family
# ----------------------------------------------------------------------


def _xref_compact_line(ref: dict[str, Any]) -> str:
    fn = (
        ref.get("function_name")
        or ref.get("caller_function_name")
        or ref.get("caller")
        or "<?>"
    )
    addr = (
        ref.get("function_address")
        or ref.get("caller_function_address")
        or ref.get("address")
        or ref.get("from")
        or "?"
    )
    kind = ref.get("xref_kind") or ref.get("type") or ""
    suffix = f" [{kind}]" if kind else ""
    return f"  - {fn} @ {addr}{suffix}"


def _xref_view_result(
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
    lines = [_xref_compact_line(r) for r in refs[:MAX_LIST_PREVIEW] if isinstance(r, dict)]
    if len(refs) > MAX_LIST_PREVIEW:
        lines.append(f"  ... and {len(refs) - MAX_LIST_PREVIEW} more")
    body = "\n".join(lines) if lines else "  (none)"
    obs_value = f"{len(refs)} {summary_noun} for {target}:\n{body}"
    return AdapterResult(
        payload_kind=PayloadKind.XREF_VIEW,
        payload=payload,
        observables_delta={obs_key_for(ctx, f"{obs_suffix}.{target}"): obs_value},
        summary=f"{len(refs)} {summary_noun} for {target}",
    )


def adapt_find_api_call_sites(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``find_api_call_sites`` response to XREF_VIEW payload."""
    api_name = str(raw.get("api_name") or ctx.args.get("api_name") or "<unknown>")
    return _xref_view_result(
        raw, ctx,
        target=api_name,
        list_keys=("call_sites",),
        target_field="api_name",
        obs_suffix="callsites",
        summary_noun="call site(s)",
    )


@is_read_tool("ida_headless", "xrefs_to")
def adapt_xrefs_to(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Map ``xrefs_to`` response to XREF_VIEW payload (incoming references)."""
    target = str(
        raw.get("target")
        or raw.get("address")
        or ctx.args.get("address_or_name")
        or "<unknown>",
    )
    return _xref_view_result(
        raw, ctx,
        target=target,
        list_keys=("xrefs", "results"),
        target_field="target",
        obs_suffix="xrefs_to",
        summary_noun="xref(s) to",
    )


@is_read_tool("ida_headless", "xrefs_from")
def adapt_xrefs_from(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Map ``xrefs_from`` response to XREF_VIEW payload (outgoing references)."""
    source = str(
        raw.get("source")
        or raw.get("address")
        or ctx.args.get("address_or_name")
        or "<unknown>",
    )
    return _xref_view_result(
        raw, ctx,
        target=source,
        list_keys=("xrefs", "results"),
        target_field="source",
        obs_suffix="xrefs_from",
        summary_noun="xref(s) from",
    )


# ----------------------------------------------------------------------
# TAINT_FLOW family
# ----------------------------------------------------------------------


def _taint_summary_lines(paths: list[Any]) -> list[str]:
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


def _taint_result(
    raw: dict[str, Any],
    ctx: AdapterContext,
    *,
    list_keys: tuple[str, ...],
    obs_suffix: str,
    label: str,
) -> AdapterResult:
    paths = _list_or_empty(raw, *list_keys)
    payload: dict[str, Any] = {
        "paths": paths,
        "total": len(paths),
        "label": label,
        "raw": raw,
        "source_provenance": provenance_stamp(ctx),
    }
    lines = _taint_summary_lines(paths)
    body = "\n".join(lines) if lines else "  (no taint paths reported)"
    obs_value = f"{label}: {len(paths)} path(s)\n{body}"
    return AdapterResult(
        payload_kind=PayloadKind.TAINT_FLOW,
        payload=payload,
        observables_delta={obs_key_for(ctx, obs_suffix): obs_value},
        summary=f"{label}: {len(paths)} path(s)",
    )


@is_read_tool("ida_headless", "interprocedural_taint")
def adapt_interprocedural_taint(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``interprocedural_taint`` to TAINT_FLOW payload."""
    sink = str(ctx.args.get("sink_function") or "<sink>")
    return _taint_result(
        raw, ctx,
        list_keys=("chains", "paths", "taint_paths", "results"),
        obs_suffix=f"itp_taint.{sink}",
        label=f"interprocedural_taint to {sink}",
    )


@is_read_tool("ida_headless", "trace_dataflow")
def adapt_trace_dataflow(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Map ``trace_dataflow`` to TAINT_FLOW payload."""
    sink = str(ctx.args.get("sink_function") or "<sink>")
    return _taint_result(
        raw, ctx,
        list_keys=("hops", "trace", "results", "paths"),
        obs_suffix=f"trace.{sink}",
        label=f"trace_dataflow to {sink}",
    )


@is_read_tool("ida_headless", "def_use")
def adapt_def_use(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Map ``def_use`` to TAINT_FLOW payload (def/use chains)."""
    function = str(ctx.args.get("address_or_name") or "<fn>")
    return _taint_result(
        raw, ctx,
        list_keys=("chains", "def_use", "uses", "results"),
        obs_suffix=f"def_use.{function}",
        label=f"def_use chains in {function}",
    )


# ----------------------------------------------------------------------
# GRAPH_VIEW family
# ----------------------------------------------------------------------


def _graph_result(
    raw: dict[str, Any],
    ctx: AdapterContext,
    *,
    obs_suffix: str,
    label: str,
) -> AdapterResult:
    nodes = _list_or_empty(raw, "nodes")
    edges = _list_or_empty(raw, "edges")
    payload: dict[str, Any] = {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "label": label,
        "raw": raw,
        "source_provenance": provenance_stamp(ctx),
    }
    obs_value = (
        f"{label}: {len(nodes)} node(s), {len(edges)} edge(s)"
    )
    return AdapterResult(
        payload_kind=PayloadKind.GRAPH_VIEW,
        payload=payload,
        observables_delta={obs_key_for(ctx, obs_suffix): obs_value},
        summary=obs_value,
    )


def adapt_call_graph(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Map ``call_graph`` to GRAPH_VIEW payload."""
    root = str(ctx.args.get("address_or_name") or "<root>")
    return _graph_result(raw, ctx, obs_suffix=f"call_graph.{root}", label=f"call_graph @ {root}")


def adapt_call_chain(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Map ``call_chain`` to GRAPH_VIEW payload (chain rooted at a target)."""
    target = str(ctx.args.get("target_function") or "<target>")
    direction = str(ctx.args.get("direction") or "callers")
    chain = _list_or_empty(raw, "chain", "nodes")
    payload: dict[str, Any] = {
        "target": target,
        "direction": direction,
        "chain": chain,
        "node_count": len(chain),
        "edges": _list_or_empty(raw, "edges"),
        "raw": raw,
        "source_provenance": provenance_stamp(ctx),
    }
    obs_value = f"call_chain {direction} of {target}: {len(chain)} node(s)"
    return AdapterResult(
        payload_kind=PayloadKind.GRAPH_VIEW,
        payload=payload,
        observables_delta={obs_key_for(ctx, f"call_chain.{target}"): obs_value},
        summary=obs_value,
    )


# ----------------------------------------------------------------------
# CODE_POINTER family
# ----------------------------------------------------------------------


def _code_pointer_result(
    raw: dict[str, Any],
    ctx: AdapterContext,
    *,
    body_keys: tuple[str, ...],
    obs_suffix: str,
    label: str,
    max_chars: int = MAX_OBS_DUMP_CHARS,
) -> AdapterResult:
    body = ""
    for k in body_keys:
        v = raw.get(k)
        if isinstance(v, str) and v:
            body = v
            break
        if isinstance(v, list):
            body = "\n".join(str(x) for x in v)
            break
    line_count = body.count("\n") + (1 if body else 0)
    payload: dict[str, Any] = {
        "label": label,
        "body": body,
        "line_count": line_count,
        "raw": raw,
        "source_provenance": provenance_stamp(ctx),
    }
    obs_body = body[:max_chars]
    if len(body) > max_chars:
        obs_body += f"\n... [truncated — {line_count} lines total in message {ctx.call_id}]"
    obs_value = f"{label}:\n{obs_body}" if obs_body else f"{label}: (empty)"
    return AdapterResult(
        payload_kind=PayloadKind.CODE_POINTER,
        payload=payload,
        observables_delta={obs_key_for(ctx, obs_suffix): obs_value},
        summary=f"{label} ({line_count} lines)",
    )


@is_read_tool("ida_headless", "disassemble_function")
def adapt_disassemble_function(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``disassemble_function`` to CODE_POINTER payload."""
    fn = str(ctx.args.get("address_or_name") or "<fn>")
    return _code_pointer_result(
        raw, ctx,
        body_keys=("disassembly", "asm", "listing", "lines"),
        obs_suffix=f"disasm.{fn}",
        label=f"disassembly of {fn}",
    )


def adapt_get_microcode(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Map ``get_microcode`` to CODE_POINTER payload (Hex-Rays microcode)."""
    fn = str(ctx.args.get("address_or_name") or "<fn>")
    maturity = str(ctx.args.get("maturity") or "current")
    return _code_pointer_result(
        raw, ctx,
        body_keys=("microcode", "text", "lines"),
        obs_suffix=f"microcode.{fn}",
        label=f"microcode of {fn} ({maturity})",
    )


@is_read_tool("ida_headless", "pseudocode_slice_view")
def adapt_pseudocode_slice_view(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``pseudocode_slice_view`` to CODE_POINTER payload (slice around addresses)."""
    fn = str(ctx.args.get("address_or_name") or "<fn>")
    return _code_pointer_result(
        raw, ctx,
        body_keys=("slices", "text", "lines"),
        obs_suffix=f"slice.{fn}",
        label=f"pseudocode slices in {fn}",
        max_chars=MAX_OBS_DUMP_CHARS,
    )


# ----------------------------------------------------------------------
# PATCH_DIFF family
# ----------------------------------------------------------------------


def adapt_diff_function(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Map ``diff_function`` to PATCH_DIFF payload."""
    old_name = str(ctx.args.get("address_or_name_old") or "<old>")
    new_name = str(ctx.args.get("address_or_name_new") or "<new>")
    unified = str(raw.get("unified_diff") or raw.get("diff") or "")
    side_by_side = raw.get("side_by_side") or []
    line_count = unified.count("\n") + (1 if unified else 0)
    payload: dict[str, Any] = {
        "old": old_name,
        "new": new_name,
        "unified_diff": unified,
        "side_by_side": side_by_side,
        "line_count": line_count,
        "source_provenance": provenance_stamp(ctx),
    }
    obs_body = unified[:MAX_OBS_DUMP_CHARS]
    if len(unified) > MAX_OBS_DUMP_CHARS:
        obs_body += f"\n... [truncated — {line_count} lines total in message {ctx.call_id}]"
    obs_value = (
        f"diff_function {old_name} vs {new_name} ({line_count} lines):\n{obs_body}"
        if obs_body
        else f"diff_function {old_name} vs {new_name}: (no diff body)"
    )
    return AdapterResult(
        payload_kind=PayloadKind.PATCH_DIFF,
        payload=payload,
        observables_delta={obs_key_for(ctx, f"diff.{old_name}_vs_{new_name}"): obs_value},
        summary=f"diff_function {old_name} vs {new_name} ({line_count} lines)",
    )


# ----------------------------------------------------------------------
# TEXT specializations
# ----------------------------------------------------------------------


def adapt_checksec(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Map ``checksec`` response to TEXT payload (mitigations summary)."""
    flag_keys = ("nx", "aslr", "pie", "canary", "cet", "cfi", "relro_full", "relro_partial")
    flags = {k: raw[k] for k in flag_keys if k in raw}
    sanitizers = raw.get("sanitizers") or []
    if not isinstance(sanitizers, list):
        sanitizers = []

    bullets: list[str] = []
    for key in ("nx", "aslr", "pie", "canary", "cet", "cfi"):
        v = flags.get(key)
        if v is True:
            bullets.append(f"  - {key.upper()}: ON")
        elif v is False:
            bullets.append(f"  - {key.upper()}: OFF")
        else:
            bullets.append(f"  - {key.upper()}: unknown")
    if flags.get("relro_full"):
        bullets.append("  - RELRO: full")
    elif flags.get("relro_partial"):
        bullets.append("  - RELRO: partial")
    if sanitizers:
        bullets.append(f"  - sanitizers: {', '.join(str(s) for s in sanitizers)}")

    summary_text = "checksec mitigations:\n" + (
        "\n".join(bullets) if bullets else "  (no flags reported)"
    )
    on_count = sum(1 for v in flags.values() if v is True)

    payload: dict[str, Any] = {
        "text": summary_text,
        "tool": f"{ctx.mcp_server_id}.{ctx.tool_name}",
        "flags": flags,
        "sanitizers": sanitizers,
        "raw": raw,
        "source_provenance": provenance_stamp(ctx),
    }
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx): summary_text},
        summary=f"checksec: {on_count} mitigations ON",
    )


def adapt_classify_behavior(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map ``classify_behavior`` to TEXT payload (ATT&CK-aligned categories)."""
    categories = raw.get("categories") or raw.get("behaviors") or {}
    if not isinstance(categories, dict):
        categories = {}

    bullets: list[str] = []
    for cat_name in sorted(categories):
        entries = categories[cat_name]
        count = len(entries) if isinstance(entries, list | dict) else 1
        bullets.append(f"  - {cat_name}: {count} API(s)")

    summary_text = (
        f"classify_behavior: {len(categories)} category(ies)\n"
        + ("\n".join(bullets) if bullets else "  (no categorized behaviors)")
    )
    payload: dict[str, Any] = {
        "text": summary_text,
        "tool": f"{ctx.mcp_server_id}.{ctx.tool_name}",
        "categories": categories,
        "total_categories": len(categories),
        "source_provenance": provenance_stamp(ctx),
    }
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx): summary_text},
        summary=f"classify_behavior: {len(categories)} categories",
    )


def adapt_capa_scan(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Map ``capa_scan`` to TEXT payload (capability matches)."""
    matches = _list_or_empty(raw, "matches", "results", "capabilities")
    bullets: list[str] = []
    for m in matches[:MAX_LIST_PREVIEW]:
        if not isinstance(m, dict):
            continue
        rule = m.get("rule") or m.get("name") or "<rule>"
        attck = m.get("attack") or m.get("attck") or []
        if isinstance(attck, list) and attck:
            bullets.append(f"  - {rule} [ATT&CK: {', '.join(str(a) for a in attck[:3])}]")
        else:
            bullets.append(f"  - {rule}")
    if len(matches) > MAX_LIST_PREVIEW:
        bullets.append(f"  ... and {len(matches) - MAX_LIST_PREVIEW} more")

    summary_text = (
        f"capa_scan: {len(matches)} capability match(es)\n"
        + ("\n".join(bullets) if bullets else "  (none)")
    )
    payload: dict[str, Any] = {
        "text": summary_text,
        "tool": f"{ctx.mcp_server_id}.{ctx.tool_name}",
        "matches": matches,
        "total": len(matches),
        "raw_preview": bounded_dump(raw),
        "source_provenance": provenance_stamp(ctx),
    }
    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx): summary_text},
        summary=f"capa_scan: {len(matches)} matches",
    )
