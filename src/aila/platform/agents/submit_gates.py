"""Defense-check submit gates -- structural enforcement of the 5-step rule.

RFC #94. The VR system prompt's 5-step overflow verification rule has
~60% compliance. These gates enforce the load-bearing steps structurally:
a ``direct_finding`` or ``assessment_report`` with confidence >= medium
is rejected unless the branch's tool-call history shows the agent verified
defenses and traced reachability.

The gate mirrors the existing submit-gate pattern in ``turn_runner.py``
(sibling-open-hyp gate, unresolved-hypothesis gate, etc.): on rejection,
the decision is converted to ``action='reasoning'`` and a steering
directive tells the agent exactly what tool call to make next.

Platform-bound so malware/forensics inherit the same enforcement.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import text as _sql_text

__all__ = [
    "check_defense_verification",
    "classify_claim",
]

_log = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
#  Known allocator and input-reader function names.                    #
#  The gate checks whether the agent called read_function on any of   #
#  these BEFORE submitting an overflow/allocation claim.               #
# ------------------------------------------------------------------ #
KNOWN_ALLOCATORS: frozenset[str] = frozenset({
    # FFmpeg
    "av_malloc", "av_mallocz", "av_calloc", "av_realloc",
    "av_fast_realloc", "av_buffer_alloc", "av_frame_get_buffer",
    "av_realloc_f", "av_malloc_array", "av_calloc_array",
    # libc / POSIX
    "malloc", "calloc", "realloc", "reallocarray",
    # nginx
    "ngx_palloc", "ngx_pnalloc", "ngx_pcalloc", "ngx_alloc",
    # Apache httpd
    "apr_palloc", "apr_pcalloc",
    # OpenSSL
    "OPENSSL_malloc", "OPENSSL_zalloc", "CRYPTO_malloc",
    # GLib
    "g_malloc", "g_malloc0", "g_new", "g_new0",
    # Linux kernel
    "kmalloc", "kzalloc", "kcalloc", "vmalloc",
    # Go (via cgo or audit-mcp representation)
    "make", "append",
})

INPUT_READERS: frozenset[str] = frozenset({
    # FFmpeg I/O
    "avio_r8", "avio_rb16", "avio_rb32", "avio_rb64",
    "avio_rl16", "avio_rl32", "avio_rl64",
    # FFmpeg bitstream
    "get_bits", "get_bits_long", "get_bits1", "show_bits",
    "get_bits_le", "get_sbits",
    # FFmpeg bytestream
    "bytestream2_get_le16", "bytestream2_get_le32",
    "bytestream2_get_be16", "bytestream2_get_be32",
    "bytestream2_get_byte",
    # Generic read macros
    "AV_RL16", "AV_RL32", "AV_RB16", "AV_RB32",
    "AV_RL64", "AV_RB64",
    # Network / protocol
    "recv", "read", "fread",
})

# Claim classes that require allocator + input-range verification.
_OVERFLOW_CLASSES: frozenset[str] = frozenset({
    "overflow", "integer_overflow", "allocation", "heap_oob",
    "buffer_overflow", "oob_write",
})

# Keywords in the answer text that signal each claim class.
_CLAIM_KEYWORDS: list[tuple[str, str]] = [
    ("integer overflow", "overflow"),
    ("int overflow", "overflow"),
    ("heap overflow", "heap_oob"),
    ("heap-based buffer overflow", "heap_oob"),
    ("heap oob", "heap_oob"),
    ("out-of-bounds write", "oob_write"),
    ("out-of-bounds read", "oob_read"),
    ("buffer overflow", "buffer_overflow"),
    ("use-after-free", "uaf"),
    ("double free", "double_free"),
    ("type confusion", "type_confusion"),
    ("bypass", "bypass"),
    ("injection", "injection"),
    ("allocation", "allocation"),
    ("unchecked allocation", "allocation"),
]


def classify_claim(outcome_kind: str, payload: dict[str, Any]) -> str:
    """Derive the vulnerability claim class from the outcome payload.

    Scans the ``answer`` field for keywords. Returns the dominant class
    or ``"generic"`` if no specific class is detected. ``audit_memo``
    and ``no_finding`` outcomes always return ``"none"`` (not subject
    to defense checks).
    """
    if outcome_kind in ("audit_memo",):
        return "none"
    answer = str(payload.get("answer") or "").lower()
    for keyword, cls in _CLAIM_KEYWORDS:
        if keyword in answer:
            return cls
    return "generic"


async def check_defense_verification(
    *,
    session: Any,
    branch_id: str,
    claim_class: str,
    message_table: str,
) -> tuple[bool, str | None]:
    """Check whether the branch's tool-call history shows defense verification.

    Queries the branch's ``tool_call`` message rows from the DB (same
    pattern as ``_survey_streak_hint`` in the VR tool executor). Checks:

    - For overflow/allocation claims: did the agent call ``read_function``
      on a known allocator AND on an input reader?
    - For ALL finding claims: did the agent call ``callers_of`` at least
      once to verify reachability?

    Returns ``(True, None)`` if checks pass, ``(False, rejection_msg)``
    if not. The rejection message is injected as a steering directive.
    """
    if claim_class in ("none", "generic"):
        return True, None

    # Query tool-call history from the DB.
    rows = (await session.execute(
        _sql_text(
            f"SELECT payload_json FROM {message_table} "
            "WHERE branch_id = :bid AND payload_kind = 'tool_call' "
            "ORDER BY created_at"
        ).bindparams(bid=branch_id),
    )).all()

    # Parse tool names and read_function targets from the history.
    read_targets: set[str] = set()
    tools_used: set[str] = set()
    for (payload_json,) in rows:
        try:
            p = json.loads(payload_json or "{}")
            cmd = json.loads(p.get("command") or "{}")
            tool = cmd.get("tool", "")
            tools_used.add(tool)
            if tool.endswith("read_function"):
                name = (cmd.get("args") or {}).get("name", "")
                if name:
                    read_targets.add(name)
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue

    has_callers_of = any(t.endswith("callers_of") for t in tools_used)

    # Check 1: overflow/allocation claims need allocator + input-range reads.
    if claim_class in _OVERFLOW_CLASSES:
        if not read_targets & KNOWN_ALLOCATORS:
            return False, (
                "SUBMIT REJECTED (defense-check gate): you claimed an "
                "overflow or allocation bug but never called read_function "
                "on the allocator used at the vulnerability site. Read the "
                "allocator implementation (e.g. av_calloc, av_malloc, "
                "ngx_palloc) to check whether it handles overflow "
                "internally, then resubmit."
            )
        if not read_targets & INPUT_READERS:
            return False, (
                "SUBMIT REJECTED (defense-check gate): state the bit-width "
                "and maximum value of the input reader feeding the overflow "
                "operand. Call read_function on the read primitive (e.g. "
                "avio_rb16 returns uint16_t, max 65535) to determine "
                "whether the overflow is arithmetically possible, then "
                "resubmit."
            )

    # Check 2: ALL finding claims need a callers_of reachability trace.
    if not has_callers_of:
        return False, (
            "SUBMIT REJECTED (defense-check gate): you never called "
            "callers_of to verify that untrusted input can reach the "
            "vulnerable function. Trace the call chain from the "
            "vulnerability site back to a demuxer/decoder/protocol "
            "callback or an API handler before resubmitting."
        )

    return True, None
