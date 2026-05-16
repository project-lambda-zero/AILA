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


# Cap on JSON-ish dumps pushed into observables. ~2KB ≈ 500 tokens per
# observation entry — enough context for the next reasoning turn without
# blowing the prompt budget at turn 25.
MAX_OBS_DUMP_CHARS = 2000

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

    Format: ``<server>.<tool>[.<suffix>]``. Suffix lets adapters disambiguate
    multiple calls of the same tool in one branch (e.g. different functions).
    """
    base = f"{ctx.mcp_server_id}.{ctx.tool_name}"
    if suffix:
        return f"{base}.{suffix}"
    return base


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
