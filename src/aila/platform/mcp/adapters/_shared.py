"""Shared adapter helpers — bounded preview + provenance stamping.

These helpers are used by:
  - the generic fallback adapter (generic.py)
  - the family adapters (xref / taint / graph / code_pointer / patch_diff)

They centralize the "keep the heavy raw data in the message store, surface
only a bounded preview into observables" pattern so a 50KB tool response
never bloats subsequent prompts.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

from .base import AdapterContext

__all__ = [
    "MAX_OBS_DUMP_CHARS",
    "MAX_LIST_PREVIEW",
    "bounded_dump",
    "provenance_stamp",
    "obs_key_for",
    "try_decode_string",
    "enrich_strings_with_decodes",
]


# Heuristic decoder cap -- a single string longer than this is
# unlikely to be a meaningful base64 / hex blob the agent needs
# decoded inline; if anything that big DOES decode, the decoded
# preview is itself capped via bounded_dump downstream.
_DECODE_INPUT_CAP: int = 4096

# Minimum decoded length we bother surfacing. Very short decodes
# ("ok", "hi") are noise -- the same bytes show up in every
# false-positive base64 / hex / ascii roll.
_DECODE_MIN_OUTPUT: int = 4

# At least this fraction of the decoded bytes must look like printable
# ASCII before we surface the decode as plaintext. Below the threshold
# it's almost certainly random bytes (encrypted payload / shellcode)
# and we skip the decoded field to avoid drowning the observation row
# in mojibake -- the encoded form alone is the useful signal there.
_DECODE_PRINTABLE_RATIO: float = 0.85

_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_HEX_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    # Printable = ASCII 0x20-0x7E + \t \n \r. Everything else flags as
    # non-printable, including UTF-8 multi-byte (which we won't try to
    # decode here -- ida-headless strings are already utf-8 normalized).
    printable = sum(
        1 for b in data
        if (0x20 <= b <= 0x7E) or b in (0x09, 0x0A, 0x0D)
    )
    return printable / len(data)


def try_decode_string(raw: str) -> dict[str, str] | None:
    """Attempt base64 / base64url / hex decode and return the plaintext.

    Returns ``{"encoding": str, "decoded": str}`` when ONE of the
    candidates produces meaningful printable output, otherwise
    ``None``. Multiple candidates are tried in order (standard
    base64 -> url-safe base64 -> hex); the first success wins.

    Used by ida-headless string-family adapters to enrich observation
    payloads so the agent sees decoded C2 URLs / file paths / config
    keys inline instead of having to call out to a separate decoder.
    """
    if not raw:
        return None
    s = raw.strip()
    if len(s) < 8 or len(s) > _DECODE_INPUT_CAP:
        # Too short to be meaningful, or too long to bother (likely
        # already binary that decode would explode on).
        return None

    # Standard base64 (length divisible by 4 after stripping padding).
    if _BASE64_PATTERN.match(s) and len(s) % 4 == 0:
        try:
            decoded = base64.b64decode(s, validate=True)
        except (binascii.Error, ValueError):
            decoded = None
        if (
            decoded is not None
            and len(decoded) >= _DECODE_MIN_OUTPUT
            and _printable_ratio(decoded) >= _DECODE_PRINTABLE_RATIO
        ):
            try:
                return {"encoding": "base64", "decoded": decoded.decode("utf-8", errors="replace")}
            except UnicodeDecodeError:
                pass

    # URL-safe base64 (uses - _ instead of + /). Distinct enough from
    # standard base64 that we test it separately; the regex anchors
    # prevent a string with both alphabets from double-matching.
    if _BASE64URL_PATTERN.match(s) and ("-" in s or "_" in s) and len(s) % 4 == 0:
        try:
            decoded = base64.urlsafe_b64decode(s)
        except (binascii.Error, ValueError):
            decoded = None
        if (
            decoded is not None
            and len(decoded) >= _DECODE_MIN_OUTPUT
            and _printable_ratio(decoded) >= _DECODE_PRINTABLE_RATIO
        ):
            try:
                return {"encoding": "base64url", "decoded": decoded.decode("utf-8", errors="replace")}
            except UnicodeDecodeError:
                pass

    # Plain hex (every char in [0-9a-f], length even). False-positive
    # candidate -- so the printable-ratio gate must clear or we skip.
    if _HEX_PATTERN.match(s):
        try:
            decoded = bytes.fromhex(s)
        except ValueError:
            decoded = None
        if (
            decoded is not None
            and len(decoded) >= _DECODE_MIN_OUTPUT
            and _printable_ratio(decoded) >= _DECODE_PRINTABLE_RATIO
        ):
            try:
                return {"encoding": "hex", "decoded": decoded.decode("utf-8", errors="replace")}
            except UnicodeDecodeError:
                pass

    return None


def enrich_strings_with_decodes(
    strings: list[Any], *, key: str = "value",
) -> list[Any]:
    """Walk a list of string records and add ``decoded`` / ``encoding``
    fields when a base64 / hex decode looks meaningful.

    Each record can be a bare string OR a dict carrying the actual
    string under ``key`` (defaults to "value"; ida-headless string
    tools commonly use "string" or "text" as well -- callers pass
    the right key). Records without a decodable value are returned
    unchanged; dict records get ``decoded`` + ``encoding`` keys
    appended in-place (the input list is not mutated -- a new list
    of new dicts is returned).

    Bare-string inputs are wrapped: ``["a", "b"]`` becomes
    ``[{"value": "a", "decoded": "...", "encoding": "..."}, ...]``
    when the decode succeeds, OR ``["a", "b"]`` when it does not.
    The list shape stays homogeneous for the common case (all decode
    or none decode) so renderers don't need to test per-entry.
    """
    if not isinstance(strings, list):
        return strings
    out: list[Any] = []
    for entry in strings:
        if isinstance(entry, str):
            decode = try_decode_string(entry)
            if decode is None:
                out.append(entry)
            else:
                out.append({key: entry, **decode})
        elif isinstance(entry, dict):
            value = entry.get(key)
            if not isinstance(value, str):
                # Fall back to common alternate keys without forcing
                # callers to enumerate every adapter-specific shape.
                for alt in ("string", "text", "raw", "data"):
                    if isinstance(entry.get(alt), str):
                        value = entry[alt]
                        break
            if isinstance(value, str):
                decode = try_decode_string(value)
                if decode is not None:
                    merged = dict(entry)
                    merged.setdefault("decoded", decode["decoded"])
                    merged.setdefault("encoding", decode["encoding"])
                    out.append(merged)
                    continue
            out.append(entry)
        else:
            out.append(entry)
    return out


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
