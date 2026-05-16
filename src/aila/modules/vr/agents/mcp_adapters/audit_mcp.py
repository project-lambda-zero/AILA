"""Adapters for the audit-mcp source-audit MCP server.

v0.3 v1 ships one adapter:
  - fuzzing_targets -> TEXT payload with ranked function list

Add per-tool adapters when investigations actually invoke them.
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.contracts import PayloadKind

from .base import AdapterContext, AdapterResult

__all__ = ["adapt_fuzzing_targets"]


_MAX_OBS_TARGETS = 20


def adapt_fuzzing_targets(
    raw: dict[str, Any], ctx: AdapterContext,
) -> AdapterResult:
    """Map audit-mcp `fuzzing_targets` response to a structured TEXT payload.

    fuzzing_targets returns a ranked 'what's worth fuzzing' list,
    already graph-aware with blast_radius / complexity / taint signals.
    The adapter preserves the full list in the message payload and
    surfaces the top-K names + key scores into observables.
    """
    targets = raw.get("targets") or raw.get("results") or []
    if not isinstance(targets, list):
        targets = []

    payload: dict[str, Any] = {
        "text": (
            f"audit-mcp fuzzing_targets returned {len(targets)} candidates "
            f"(graph-aware ranking)"
        ),
        "tool": "audit_mcp.fuzzing_targets",
        "targets": targets,
        "total": len(targets),
        "source_provenance": {
            "mcp_server": ctx.mcp_server_id,
            "mcp_tool": ctx.tool_name,
            "call_id": ctx.call_id,
        },
    }

    summary_lines: list[str] = []
    for entry in targets[:_MAX_OBS_TARGETS]:
        if not isinstance(entry, dict):
            continue
        name = (
            entry.get("function_name")
            or entry.get("name")
            or entry.get("symbol")
            or "<unnamed>"
        )
        score = entry.get("risk_score") or entry.get("score") or entry.get("priority")
        blast = entry.get("blast_radius")
        complexity = entry.get("complexity")
        bits: list[str] = []
        if score is not None:
            bits.append(f"score={score}")
        if blast is not None:
            bits.append(f"blast={blast}")
        if complexity is not None:
            bits.append(f"complexity={complexity}")
        suffix = f" ({', '.join(bits)})" if bits else ""
        summary_lines.append(f"  - {name}{suffix}")
    if len(targets) > _MAX_OBS_TARGETS:
        summary_lines.append(f"  ... and {len(targets) - _MAX_OBS_TARGETS} more")

    obs_value = (
        f"audit-mcp fuzzing_targets ({len(targets)} candidates):\n"
        + ("\n".join(summary_lines) if summary_lines else "  (none)")
    )

    return AdapterResult(
        payload_kind=PayloadKind.TEXT,
        payload=payload,
        observables_delta={"audit_mcp.fuzzing_targets": obs_value},
        summary=f"{len(targets)} ranked fuzzing target candidates",
    )
