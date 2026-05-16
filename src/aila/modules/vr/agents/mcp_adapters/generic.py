"""Generic fallback adapter — used for any registered MCP tool without a
specialized adapter.

This means the engine can invoke ALL 135 MCP tools (81 ida-headless +
54 audit-mcp) immediately. Tools with structured rendering value
(decompile, xrefs_to, call_graph, taint paths, diffs, etc.) get
specialized adapters in their respective modules; everything else
defaults to this TEXT adapter.

Design contract: NEVER fabricate fields. The generic adapter does not
invent semantics — it just packages the raw response, stamps
provenance, and pushes a bounded preview into observables. Frontend
renderers branching on ``payload_kind == TEXT`` see the raw response
under ``data`` for inspection.
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.contracts import PayloadKind

from ._shared import bounded_dump, obs_key_for, provenance_stamp
from .base import AdapterContext, AdapterResult

__all__ = ["adapt_generic"]


def adapt_generic(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Wrap any MCP response as a TEXT payload with bounded observables."""
    summary_line = _summarize_raw(raw, ctx)
    preview = bounded_dump(raw)

    payload: dict[str, Any] = {
        "text": summary_line + "\n\n" + preview,
        "tool": f"{ctx.mcp_server_id}.{ctx.tool_name}",
        "data": raw,
        "source_provenance": provenance_stamp(ctx),
    }

    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={obs_key_for(ctx): summary_line + "\n" + preview},
        summary=summary_line,
    )


def _summarize_raw(raw: dict[str, Any], ctx: AdapterContext) -> str:
    """One-line human-readable summary of an MCP response.

    Tries common keys (status, count, total, results length) before
    falling back to a key-count description. Never invents semantics.
    """
    tool_id = f"{ctx.mcp_server_id}.{ctx.tool_name}"
    if not isinstance(raw, dict):
        return f"{tool_id}: non-dict response ({type(raw).__name__})"

    status = raw.get("status")
    bits: list[str] = []
    if status is not None:
        bits.append(f"status={status}")

    for k in ("count", "total", "total_matches", "total_candidates"):
        if k in raw and isinstance(raw[k], int):
            bits.append(f"{k}={raw[k]}")
            break

    for k in ("results", "matches", "items", "entries", "targets"):
        v = raw.get(k)
        if isinstance(v, list):
            bits.append(f"{k}_len={len(v)}")
            break

    if "error" in raw:
        bits.append(f"error={raw['error']!r}")

    if not bits:
        bits.append(f"{len(raw)} field(s): {sorted(raw.keys())[:5]}")

    return f"{tool_id}: " + ", ".join(bits)
