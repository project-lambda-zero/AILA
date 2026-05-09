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

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Injection pattern dataclass and registry (D-01, D-05)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class InjectionPattern:
    """A compiled regex pattern for prompt injection detection."""

    name: str
    regex: re.Pattern[str]


# Module-level registry -- built-in patterns compiled at import time
_INJECTION_PATTERNS: list[InjectionPattern] = []


def register_injection_pattern(name: str, regex: str) -> None:
    """Register a new injection pattern for sanitize_input.

    Patterns are compiled with IGNORECASE. Called at module load time for
    built-in patterns, and available for runtime extension (D-05).
    """
    _INJECTION_PATTERNS.append(
        InjectionPattern(name=name, regex=re.compile(regex, re.IGNORECASE))
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

def sanitize_input(content: str) -> str:
    """Strip known prompt injection patterns from untrusted text.

    Iterates all registered injection patterns and applies regex.sub to
    remove matches. Idempotent: calling twice produces the same result (D-03).
    """
    result = content
    for pattern in _INJECTION_PATTERNS:
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
