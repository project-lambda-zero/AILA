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

# fix §274 — curated set of args dropped from the obs-key fingerprint.
# Two buckets, both opaque to "what the agent actually asked":
#   - target-handle identifiers (``index_id``, ``binary_id``) that
#     stay constant across every call on one branch;
#   - pagination cursors that page the same conceptual question.
# Adding ``page``, ``cursor``, ``next_token``, ``page_size``, ``from``,
# ``to`` was operator-observed: without them, three pages of the
# same search produced three different obs-keys and three side-by-side
# observation entries instead of overwriting cleanly. Contributors
# adding new pagination knobs to a tool MUST extend this set.
_PAGINATION_NOISE_KEYS: frozenset[str] = frozenset({
    "index_id",
    "binary_id",
    "limit",
    "offset",
    "page",
    "page_size",
    "cursor",
    "next_token",
    "from",
    "to",
})


def provenance_stamp(ctx: AdapterContext) -> dict[str, str]:
    """Standard source_provenance dict embedded in every adapter payload."""
    return {
        "mcp_server": ctx.mcp_server_id,
        "mcp_tool": ctx.tool_name,
        "call_id": ctx.call_id,
    }


def obs_key_for(ctx: AdapterContext, suffix: str = "") -> str:
    """Canonical observables key for a tool call.

    Format: ``<server>.<tool>[.<suffix-or-arg-fingerprint-or-call-id>]``.
    When the caller supplies an explicit ``suffix`` (e.g. a function
    name) we use it verbatim. Otherwise we derive a short fingerprint
    from ``ctx.args`` so two calls with different arguments do NOT
    collide on the same key — the prior behaviour silently overwrote
    each other, which caused the agent to forget what it had already
    looked up and keep re-issuing the same call.

    fix §275 — for no-arg tools (e.g. ``audit_mcp.list_indexes``,
    ``cache_stats``) neither the suffix nor the fingerprint produces
    a discriminator. Two consecutive calls would land at the same
    ``<server>.<tool>`` key and overwrite each other's observation,
    so the agent saw "what happened last" with no record that the
    earlier call ever ran. Fall back to ``ctx.call_id`` (the
    message-store id, already monotonically unique per call) so each
    no-arg invocation gets a distinct key.
    """
    base = f"{ctx.mcp_server_id}.{ctx.tool_name}"
    if suffix:
        return f"{base}.{suffix}"
    arg_fp = _args_fingerprint(ctx.args)
    if arg_fp:
        return f"{base}.{arg_fp}"
    if ctx.call_id:
        return f"{base}.call_{ctx.call_id}"
    return base


def _args_fingerprint(args: dict[str, Any]) -> str:
    """Stable short fingerprint of significant tool args.

    Drops pagination noise (``_PAGINATION_NOISE_KEYS``) and keeps what
    identifies WHAT the agent asked about — e.g. ``pattern`` for a
    search, ``name`` for read_function. The fingerprint is the sorted
    ``key=value`` list joined with ``__``, truncated to keep the
    observable key readable.

    fix §273 — caps each per-value at 30 chars BEFORE joining so a
    single 1000-char arg can't dominate the budget and elide every
    other arg. The prior single global truncate let one big value
    swallow siblings; two calls with the same big first arg but
    different second args produced IDENTICAL fingerprints and
    silently overwrote each other's observation entries.
    """
    significant = {k: v for k, v in (args or {}).items() if k not in _PAGINATION_NOISE_KEYS and v not in (None, "", [])}
    if not significant:
        return ""
    parts: list[str] = []
    for k in sorted(significant):
        rendered = str(significant[k])
        if len(rendered) > 30:
            rendered = rendered[:27] + "..."
        parts.append(f"{k}={rendered}")
    joined = "__".join(parts)
    # Global cap after per-value truncation so the whole fingerprint
    # still fits into a readable observable key on tools with many args.
    if len(joined) > 120:
        joined = joined[:117] + "..."
    return joined


def bounded_dump(value: Any, max_chars: int = MAX_OBS_DUMP_CHARS) -> str:
    """Render a JSON-ish preview of ``value`` capped at ``max_chars``.

    fix §272 — drops ``indent=2`` so the cap budget reflects real data
    rather than whitespace. Pretty-printed JSON triples byte count
    over compact form; under the 32 KiB cap that meant the agent saw
    ~10 KiB of actual content and 22 KiB of indentation. Compact
    serialisation puts the full budget into structure that matters.
    Falls back to ``repr`` for values json.dumps refuses (e.g. bytes).
    """
    try:
        text = json.dumps(value, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        text = repr(value)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n... [truncated, full {len(text)} chars in message store]"
