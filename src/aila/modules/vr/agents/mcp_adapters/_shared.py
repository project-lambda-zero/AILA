"""Shared adapter helpers — bounded preview + provenance stamping.

These helpers are used by:
  - the generic fallback adapter (generic.py)
  - the family adapters (xref / taint / graph / code_pointer / patch_diff)

They centralize the "keep the heavy raw data in the message store, surface
only a bounded preview into observables" pattern so a 50KB tool response
never bloats subsequent prompts.
"""
from __future__ import annotations

import json
from typing import Any

from .base import AdapterContext

__all__ = [
    "MAX_OBS_DUMP_CHARS",
    "MAX_LIST_PREVIEW",
    "bounded_dump",
    "provenance_stamp",
    "obs_key_for",
]


# fix §271 — single source of truth for the bounded preview cap. The
# prior value (100MB) made "bounded" a misnomer: a 50MB JSON dump
# landed verbatim in observables, which then rode in case_state_json
# through every prompt build, parent_reconciler scan, and frontend
# fetch. 32 KiB is the working budget — roughly one Platypus PDF
# paragraph rendered at body_sm, or ~8000 tokens of plain text —
# which is enough for the agent to recognise the next move without
# stuffing whole files into the reasoning state. Specialised renderers
# (audit_mcp._render_matches_dense, _render_chunks_dense, ida_headless
# pseudocode/disasm) reference this constant directly; raw responses
# still live in the message store untruncated for the operator UI.
MAX_OBS_DUMP_CHARS = 32 * 1024

# Cap on per-list previews surfaced into observables.
MAX_LIST_PREVIEW = 20


def provenance_stamp(ctx: AdapterContext) -> dict[str, str]:
    """Standard source_provenance dict embedded in every adapter payload."""
    return {
        "mcp_server": ctx.mcp_server_id,
        "mcp_tool": ctx.tool_name,
        "call_id": ctx.call_id,
    }


def obs_key_for(ctx: AdapterContext, suffix: str = "") -> str:
    """Canonical observables key for a tool call.

    Format: ``<server>.<tool>[.<suffix-or-arg-fingerprint>]``. When the
    caller supplies an explicit ``suffix`` (e.g. a function name) we use
    it verbatim. Otherwise we derive a short fingerprint from
    ``ctx.args`` so two calls with different arguments do NOT collide
    on the same key — the prior behaviour silently overwrote each
    other, which caused the agent to forget what it had already
    looked up and keep re-issuing the same call.
    """
    base = f"{ctx.mcp_server_id}.{ctx.tool_name}"
    if suffix:
        return f"{base}.{suffix}"
    arg_fp = _args_fingerprint(ctx.args)
    if arg_fp:
        return f"{base}.{arg_fp}"
    return base


def _args_fingerprint(args: dict[str, Any]) -> str:
    """Stable short fingerprint of significant tool args.

    Drops noise that's identical across all calls of one tool
    (``index_id``, ``binary_id``) and pagination knobs that don't
    change the conceptual question (``limit``, ``offset``). What's
    left identifies WHAT the agent asked about — e.g. ``pattern`` for
    a search, ``name`` for read_function. The fingerprint is the
    sorted ``key=value`` list joined with ``__``, truncated to keep
    the observable key readable.
    """
    noise = {"index_id", "binary_id", "limit", "offset"}
    significant = {k: v for k, v in (args or {}).items() if k not in noise and v not in (None, "", [])}
    if not significant:
        return ""
    parts = [f"{k}={significant[k]}" for k in sorted(significant)]
    joined = "__".join(parts)
    # Cap individual args at ~40 chars so a giant value doesn't blow
    # out the observable key; the full args still go to the message
    # payload for the operator UI.
    if len(joined) > 120:
        joined = joined[:117] + "..."
    return joined


def bounded_dump(value: Any, max_chars: int = MAX_OBS_DUMP_CHARS) -> str:
    """Render a JSON-ish preview of ``value`` capped at ``max_chars``.

    Uses indent=2 for readability. Appends a truncation marker when cut.
    Falls back to ``repr`` for values json.dumps refuses (e.g. bytes).
    """
    try:
        text = json.dumps(value, indent=2, default=str)
    except (TypeError, ValueError):
        text = repr(value)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n... [truncated, full {len(text)} chars in message store]"
