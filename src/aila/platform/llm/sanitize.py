"""Input and output sanitization for the AILA LLM pipeline.

Input sanitization strips prompt injection patterns from untrusted text
(CVE descriptions, user input) before it becomes part of an LLM prompt.
This is a utility function called at agent call sites, NOT a pipeline step.

Output sanitization strips XSS patterns and control characters from LLM
response text before database storage.

Both use compiled regex patterns at module level for performance,
following the same pattern as classify.py.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Injection pattern dataclass and registry (D-01, D-05)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class InjectionPattern:
    """A compiled regex pattern for prompt injection detection."""

    name: str
    regex: re.Pattern[str]


# Module-level registry -- built-in patterns compiled at import time.
# Stored as a dict keyed by ``name`` so ``register_injection_pattern``
# is idempotent for hot-reload / repeated module import (fix §155).
_INJECTION_PATTERNS: dict[str, InjectionPattern] = {}


def register_injection_pattern(name: str, regex: str) -> None:
    """Register a new injection pattern for sanitize_input.

    Patterns are compiled with IGNORECASE (fix §153). If ``name`` is
    already registered the old entry is replaced (fix §155) and a
    DEBUG line records the replacement -- repeated registration is now
    a no-op for the steady-state list, not a leak.
    """
    if name in _INJECTION_PATTERNS:
        _log.debug(
            "register_injection_pattern: replacing existing entry %r", name,
        )
    _INJECTION_PATTERNS[name] = InjectionPattern(
        name=name, regex=re.compile(regex, re.IGNORECASE),
    )


# ---------------------------------------------------------------------------
# Built-in injection patterns (D-02)
# ---------------------------------------------------------------------------

register_injection_pattern(
    "system_override",
    r"(?:ignore\s+(?:all\s+)?previous\s+instructions|you\s+are\s+now)",
)

register_injection_pattern(
    "system_tag",
    r"(?:system\s*:|<<SYS>>|<</SYS>>|\[INST\]|\[/INST\])",
)

register_injection_pattern(
    "role_injection",
    r"(?:^|\n)\s*(?:assistant|user|human)\s*:",
)

register_injection_pattern(
    "delimiter_injection",
    r"(?:^|\n)\s*(?:---+|===+)\s*(?:\n|$)",
)

register_injection_pattern(
    "backtick_boundary",
    r"```+\s*(?:system|assistant|user|human)",
)


# ---------------------------------------------------------------------------
# Input sanitization (D-03)
# ---------------------------------------------------------------------------

# Match runs of Unicode zero-width / direction-override characters so they
# can't smuggle injection markers past the ASCII patterns (fix §154).
# Includes: ZWSP / ZWNJ / ZWJ / RLO / LRO / RLE / LRE / PDF / WORD JOINER /
# zero-width no-break space. NFKC normalisation handles the rest (fullwidth
# Latin, compatibility forms, NBSP -> regular space).
_ZERO_WIDTH_RE: re.Pattern[str] = re.compile(
    "[\u200b\u200c\u200d\u2060\u202a-\u202e\u2066-\u2069\ufeff]",
)


def sanitize_input(content: str) -> str:
    """Strip known prompt injection patterns from untrusted text.

    Pre-normalises with NFKC + zero-width strip so unicode look-alikes
    (fullwidth Latin, zero-width joiners, right-to-left overrides) don't
    bypass ASCII regex patterns (fix §154). Then iterates all registered
    injection patterns and applies ``regex.sub`` to remove matches.
    Idempotent: calling twice produces the same result (D-03).
    """
    # NFKC folds fullwidth Latin "ＩＧＮＯＲＥ" to "IGNORE" and decomposes the
    # NBSP family to regular ASCII space, after which the case-insensitive
    # ASCII patterns at module load time can match.
    normalised = unicodedata.normalize("NFKC", content)
    normalised = _ZERO_WIDTH_RE.sub("", normalised)
    result = normalised
    for pattern in _INJECTION_PATTERNS.values():
        result = pattern.regex.sub("", result)
    return result


# ---------------------------------------------------------------------------
# XSS patterns for output sanitization (D-07)
# ---------------------------------------------------------------------------

_XSS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<script\b[^>]*/?>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"\bon\w+\s*=", re.IGNORECASE),
    re.compile(r"<iframe\b[^>]*>.*?</iframe>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<iframe\b[^>]*/?>", re.IGNORECASE),
    re.compile(r"<object\b[^>]*>.*?</object>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<object\b[^>]*/?>", re.IGNORECASE),
    re.compile(r"<embed\b[^>]*/?>", re.IGNORECASE),
]

# Control chars: 0x00-0x08, 0x0B-0x0C, 0x0E-0x1F (preserve \t \n \r) (D-08)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


# ---------------------------------------------------------------------------
# Output sanitization (D-06)
# ---------------------------------------------------------------------------

def sanitize_output(content: str) -> tuple[str, int]:
    """Strip XSS patterns and control characters from LLM response content.

    Returns (cleaned_content, count_of_patterns_stripped).
    """
    count = 0
    result = content
    for pattern in _XSS_PATTERNS:
        result, n = pattern.subn("", result)
        count += n
    result, n = _CONTROL_CHAR_RE.subn("", result)
    count += n
    return result, count
