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

from aila.platform.contracts.mcp_payload import PayloadKind

from ._shared import bounded_dump, obs_key_for, provenance_stamp
from .base import AdapterContext, AdapterResult

__all__ = ["adapt_generic"]


def adapt_generic(raw: dict[str, Any], ctx: AdapterContext) -> AdapterResult:
    """Wrap any MCP response as a TEXT payload with bounded observables.

    fix §277 — the per-call observable cap comes from
    ``_shared.MAX_OBS_DUMP_CHARS`` via :func:`bounded_dump`; there is
    no local override. After the §271 shrink (100 MB → 32 KiB) this
    means a 50 MB raw response no longer rides verbatim in
    ``case_state_json``; the full body still lives in the message
    store, untruncated, for the operator UI.
    """
    summary_line = _summarize_raw(raw, ctx)
    preview = bounded_dump(raw)

    payload: dict[str, Any] = {
        "text": summary_line + "\n\n" + preview,
        "tool": f"{ctx.mcp_server_id}.{ctx.tool_name}",
        "data": raw,
        "source_provenance": provenance_stamp(ctx),
    }

    # fix §276 — surface upstream error state. The summary line already
    # mentions ``error=...`` when the MCP response carries it, but the
    # AdapterResult was kind=TEXT with no other signal so the executor
    # treated the call as a success and the agent saw an "ok"-marked
    # tool result with error text embedded. Setting ``is_error: True``
    # on the payload matches the convention tool_executor already uses
    # covering its own synthesised error messages (see
    # ``_write_error_message``), so downstream readers (loops scanning
    # covering repeat failures, the prompt builder, the frontend) treat
    # MCP-reported errors and executor-reported errors the same way.
    if isinstance(raw, dict) and (
        "error" in raw or str(raw.get("status") or "").lower() == "error"
    ):
        payload["is_error"] = True

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
