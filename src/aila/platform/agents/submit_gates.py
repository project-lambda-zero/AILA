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
#  Domain vocabulary the gate consults is module-supplied:            #
#  ``known_allocators`` and ``known_input_readers`` reach the gate    #
#  as arguments, sourced from the active turn runner's ClassVars.     #
#  A module with an empty vocabulary (malware, forensics today) is    #
#  a no-op for the overflow-class allocator/reader check; the         #
#  reachability check (``callers_of``) still runs for every claim.    #
# ------------------------------------------------------------------ #

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
    known_allocators: frozenset[str] = frozenset(),
    known_input_readers: frozenset[str] = frozenset(),
) -> tuple[bool, str | None]:
    """Check whether the branch's tool-call history shows defense verification.

    Queries the branch's ``tool_call`` message rows from the DB (same
    pattern as ``_survey_streak_hint`` in the VR tool executor). Checks:

    - For overflow/allocation claims: when the caller supplies non-empty
      ``known_allocators`` / ``known_input_readers`` vocabularies, the
      agent must have called ``read_function`` on at least one entry
      from each set. A module with an empty vocabulary skips the
      allocator / reader check for that side (the check that stays live
      still fires if its vocabulary is populated).
    - For ALL finding claims: did the agent call ``callers_of`` at least
      once to verify reachability?

    ``known_allocators`` / ``known_input_readers`` are module-supplied
    vocabulary hooks. The turn runner reads them off its ClassVars
    (``AgentTurnRunnerBase.known_allocators`` /
    ``known_input_readers``) and passes them through here; each module
    subclass populates the sets. Empty defaults keep the gate a no-op
    for modules that never author overflow-shaped claims.

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

    # Check 1: overflow/allocation claims need allocator + input-range
    # reads. Only fires when the module actually declared vocabulary for
    # the side under test; an empty side is a no-op so modules whose
    # findings are not overflow-shaped (malware, forensics today) don't
    # get rejected on a check they don't participate in.
    if claim_class in _OVERFLOW_CLASSES:
        if known_allocators and not read_targets & known_allocators:
            return False, (
                "SUBMIT REJECTED (defense-check gate): you claimed an "
                "overflow or allocation bug but never called read_function "
                "on the allocator used at the vulnerability site. Read "
                "the allocator implementation to check whether it handles "
                "overflow internally, then resubmit."
            )
        if known_input_readers and not read_targets & known_input_readers:
            return False, (
                "SUBMIT REJECTED (defense-check gate): state the bit-width "
                "and maximum value of the input reader feeding the overflow "
                "operand. Call read_function on the read primitive to "
                "determine whether the overflow is arithmetically possible, "
                "then resubmit."
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
