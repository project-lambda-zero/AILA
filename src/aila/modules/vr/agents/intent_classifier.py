"""Operator message intent classifier (D-43 GA-30).

The engine's per-turn prompt includes any pending operator messages with
their classified intent so the model can interpret a one-liner the right
way:

  "stop that branch"             -> BRANCH_COMMAND
  "what's the alias chain?"      -> QUESTION
  "you missed the alias check"   -> CORRECTION
  "drop that hypothesis"         -> DISMISSAL
  "promote h3 as the finding"    -> OUTCOME_SELECTION
  "look at the parse_header fn"  -> STEERING

v0.3 v2 ships a deterministic keyword-based heuristic classifier. It is
cheap (no LLM call), deterministic (so tests are stable), and covers the
common cases. Ambiguous inputs fall back to ``UNCLASSIFIED`` — the
engine still sees the raw text and can interpret freely.

A future commit can layer a Haiku-based fallback for genuinely ambiguous
messages, but the heuristic stays the primary path for cost reasons.
"""
from __future__ import annotations

import re

from aila.modules.vr.contracts import OperatorIntent

__all__ = ["classify_intent"]


# Each (pattern, intent) is checked in order. First match wins. Patterns
# are anchored with word boundaries to avoid false matches on substrings.
_RULES: list[tuple[re.Pattern[str], OperatorIntent]] = [
    # Wh-word at start → question. Earlier than DISMISSAL so
    # "Why did you reject h2?" classifies as QUESTION, not DISMISSAL.
    (re.compile(
        r"^\s*(what|why|how|when|where|which|who|is\s+it|does\s+it|can\s+you)\b",
        re.I),
     OperatorIntent.QUESTION),

    # Branch commands — operator wants flow control on branches
    (re.compile(r"\b(stop|halt|abort|kill|pause|resume|fork|merge|abandon|promote\s+branch)\b", re.I),
     OperatorIntent.BRANCH_COMMAND),

    # Outcome selection — operator promotes / picks a specific hypothesis or
    # outcome. Allow up to 3 filler words between verb and noun so phrases
    # like "publish the audit memo" or "accept that hypothesis" match.
    (re.compile(
        r"\b(promote|pick|select|accept|finalize|finalise|publish)\b"
        r"(?:\s+\w+){0,3}\s+(h\d+|hypothesis|outcome|finding|memo|m\d+)\b",
        re.I),
     OperatorIntent.OUTCOME_SELECTION),

    # Dismissal — drop / discard hypotheses or directions
    (re.compile(r"\b(ignore|skip|drop|discard|reject|forget|never\s*mind)\b", re.I),
     OperatorIntent.DISMISSAL),

    # Correction — operator says the engine is wrong about something
    (re.compile(r"\b(you('re|\s+are)?\s+wrong|incorrect|that('s|\s+is)\s+wrong|you\s+missed|actually(\s+no)?|no,\s)\b", re.I),
     OperatorIntent.CORRECTION),

    # Steering — operator points the engine at a new direction
    (re.compile(r"\b(look\s+at|focus\s+on|try|instead|check\s+out|consider|investigate|explore|pivot)\b", re.I),
     OperatorIntent.STEERING),
]


def classify_intent(text: str) -> OperatorIntent:
    """Classify an operator message into one of the OperatorIntent values.

    Returns ``OperatorIntent.UNCLASSIFIED`` when no rule matches or when
    the message contains a literal '?' but doesn't start with a wh-word
    (treated as a question regardless).

    The order of the rule table matters — earlier patterns take precedence
    so 'stop and look at X' is BRANCH_COMMAND, not STEERING.
    """
    if not text:
        return OperatorIntent.UNCLASSIFIED

    stripped = text.strip()
    if not stripped:
        return OperatorIntent.UNCLASSIFIED

    for pattern, intent in _RULES:
        if pattern.search(stripped):
            return intent

    # Trailing '?' heuristic — covers question forms our wh-rule misses
    # (e.g. "the parser is utf8?", "that flag set?").
    if stripped.endswith("?"):
        return OperatorIntent.QUESTION

    return OperatorIntent.UNCLASSIFIED
