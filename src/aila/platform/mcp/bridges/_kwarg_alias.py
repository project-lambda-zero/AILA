"""Shared kwarg alias builder for MCP bridges.

Both ``AuditMcpBridgeTool`` and ``IDABridgeTool`` proxy ~60-80 tools each.
LLM agents routinely use synonyms (limit/top_k/n, name/function_name/fn,
addr/address/ea) that don't match the canonical names. Hand-maintained
per-tool synonym maps decay every time the upstream MCP adds a new tool.

Solution: define families of kwarg names that share an intent ("how
many results", "entity name", "address", ...), then walk the live tool
catalog and ask, for each tool, "which member of this family does THIS
tool actually accept?" -- and alias every other family member to it.

The families are intentionally tight. Two name groups that look similar
but have distinct semantics (``path`` = repo root vs ``file_path`` = a
specific file; ``depth`` vs ``limit``; ``query`` natural-language vs
``pattern`` regex) stay in separate families. When a tool accepts two
members of the same family, that family is skipped for that tool --
ambiguity is left to the upstream validator to reject loudly rather
than silently picking the wrong one.

This module is bridge-agnostic. Caller supplies its own ``families``
dict; same code works for audit_mcp, ida_headless, or any future MCP.
"""
from __future__ import annotations

from typing import Any

__all__ = [
    "build_alias_map",
    "build_known_params",
    "drop_unknown_pagination_kwargs",
    "normalize_kwargs",
]


# Pagination-style kwargs the LLM commonly attaches out of habit to
# tools that do not support pagination (every snapshot/scan/poll/
# read-once-and-return endpoint). Dropping these silently keeps the
# call going through; legitimately-paginated tools always declare the
# canonical name in their schema so the drop never triggers on them.
# Keep the set tight: only names whose semantic intent is universally
# "page through results". Other unknown kwargs still surface as
# upstream validation errors so the agent learns the real signature.
_PAGINATION_NOISE: frozenset[str] = frozenset({
    "offset", "limit", "page", "page_size",
    "cursor", "next_token", "top_k",
})


def build_alias_map(
    specs: list[dict[str, Any]],
    families: dict[str, set[str]],
    manual_overrides: dict[str, dict[str, str]] | None = None,
) -> dict[str, dict[str, str]]:
    """Derive a per-action {alias: canonical} map from a tool catalog.

    Args:
        specs: List of tool spec dicts. Each must have ``name`` and
            ``params`` keys, where ``params`` is a list of
            ``{"name": ..., ...}`` entries.
        families: Mapping ``family_label -> set of kwarg names``. Members
            of the same family are interchangeable in intent.
        manual_overrides: Optional ``{action_name: {alias: canonical}}``
            applied on top of the derived map. Use for edge cases the
            family algorithm cannot infer (upstream renames, deprecated
            aliases).

    Returns:
        ``{action_name: {alias: canonical}}`` covering every tool that
        accepts at least one family member. Tools whose canonical names
        don't intersect any family don't appear in the map.

    Algorithm:
        For every tool, for every family:
          * If exactly ONE family member appears in the tool's params,
            map the OTHER family members to it.
          * If zero or two+ members appear, do nothing for that family
            on that tool (ambiguous -- let the validator reject).
    """
    out: dict[str, dict[str, str]] = {}
    overrides = manual_overrides or {}
    for spec in specs:
        name = spec.get("name")
        if not name:
            continue
        param_names = {p["name"] for p in spec.get("params") or []}
        aliases: dict[str, str] = {}
        for family_members in families.values():
            canonical_in_tool = family_members & param_names
            if len(canonical_in_tool) != 1:
                continue
            canonical = next(iter(canonical_in_tool))
            for alias in family_members:
                if alias != canonical:
                    aliases[alias] = canonical
        manual = overrides.get(name, {})
        aliases.update(manual)
        if aliases:
            out[name] = aliases
    return out


def normalize_kwargs(
    action: str,
    kwargs: dict[str, Any],
    auto_map: dict[str, dict[str, str]],
) -> tuple[dict[str, Any], list[str]]:
    """Rewrite kwargs through the per-action alias map.

    Returns ``(normalized, notes)``. ``notes`` is a list of human-readable
    strings (one per rename) the caller logs so operators see when the
    LLM is mis-naming params.

    Resolution per kwarg:
        1. If the key is already a canonical name (a value in the map),
           pass it through unchanged. This protects canonicals from
           being rewritten to themselves or accidentally swapped.
        2. Look up the key in ``auto_map[action]``.
        3. If found, rename to the canonical name unless one is already
           set (in which case drop the duplicate and emit a note).
        4. Otherwise pass through -- the schema validator will catch
           genuinely unknown args.
    """
    if not kwargs:
        return {}, []
    per_action = auto_map.get(action, {})
    canonicals = set(per_action.values())
    out: dict[str, Any] = {}
    notes: list[str] = []
    for key, value in kwargs.items():
        if key in canonicals:
            out[key] = value
            continue
        canonical = per_action.get(key)
        if canonical is None or canonical == key:
            out[key] = value
            continue
        if canonical in kwargs:
            notes.append(
                f"{action}: dropping kwarg '{key}' (alias for "
                f"'{canonical}' which is already set)",
            )
            continue
        if canonical in out:
            notes.append(
                f"{action}: dropping kwarg '{key}' (alias for "
                f"'{canonical}', already set by an earlier synonym)",
            )
            continue
        out[canonical] = value
        notes.append(
            f"{action}: rewrote kwarg '{key}' -> '{canonical}'",
        )
    return out, notes


def build_known_params(
    specs: list[dict[str, Any]],
) -> dict[str, frozenset[str]]:
    """Return ``{action_name: frozenset(canonical_param_names)}``.

    Companion to :func:`build_alias_map`. Used by
    :func:`drop_unknown_pagination_kwargs` to decide whether a kwarg
    the agent attached is real for that tool or noise that should be
    stripped before the bridge POST.
    """
    out: dict[str, frozenset[str]] = {}
    for spec in specs:
        name = spec.get("name")
        if not name:
            continue
        out[name] = frozenset(
            p["name"] for p in spec.get("params") or [] if "name" in p
        )
    return out


def drop_unknown_pagination_kwargs(
    action: str,
    kwargs: dict[str, Any],
    known_params: dict[str, frozenset[str]],
) -> tuple[dict[str, Any], list[str]]:
    """Strip pagination-style kwargs the target tool does not declare.

    The LLM commonly attaches ``offset`` / ``limit`` / ``cursor`` to
    every tool out of habit. Snapshot endpoints (capa_scan,
    pseudocode_slice_view, verify_capabilities, ...) reject the call
    with TypeError, which lands as a synthetic bridge error that
    burns turns in the repeat-failure breaker. Silently dropping the
    kwarg when the tool's schema doesn't declare it lets the call go
    through; the note explains what happened so the operator sees the
    drop in the bridge log.

    Drops are limited to the curated ``_PAGINATION_NOISE`` set --
    other unknown kwargs still pass through so the upstream validator
    can reject them loudly and teach the agent the real signature.

    Args:
        action: tool name.
        kwargs: kwargs as resolved by :func:`normalize_kwargs`.
        known_params: per-action canonical params (see
            :func:`build_known_params`).

    Returns:
        ``(filtered_kwargs, notes)``. Notes are one string per drop;
        when ``known_params`` lacks an entry for ``action`` (unknown
        tool, catalog fetch failed, schema absent) the function is a
        no-op so it never drops legitimate args.
    """
    if not kwargs:
        return {}, []
    declared = known_params.get(action)
    if not declared:
        return dict(kwargs), []
    out: dict[str, Any] = {}
    notes: list[str] = []
    for key, value in kwargs.items():
        if key in declared:
            out[key] = value
            continue
        if key in _PAGINATION_NOISE:
            notes.append(
                f"{action}: dropping kwarg {key!r}={value!r} "
                f"(pagination noise; tool does not declare it)",
            )
            continue
        # Unknown non-pagination kwargs pass through so the upstream
        # validator surfaces them as a real error the agent must fix.
        out[key] = value
    return out, notes
