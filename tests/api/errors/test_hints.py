"""Phase 176a Task 1: ERROR_HINTS registry tests (D-31).

Verifies:
- Every D-20 code + framework codes (DEFAULT, INTERNAL_ERROR, VALIDATION_ERROR)
  has a non-empty operator-facing hint string containing an action verb.
- No hint leaks HTTP status numbers, traceback noise, or the word "Exception".
"""
from __future__ import annotations

import re

import pytest

from aila.api.errors.hints import ERROR_HINTS

_REQUIRED_KEYS = [
    "MISSING_API_KEY",
    "SSH_CONNECTION_FAILED",
    "ROUTER_ERROR",
    "MODULE_PLATFORM_NOT_READY",
    "CONFIG_VALUE_MISSING",
    "WORKER_UNREACHABLE",
    "VALIDATION_ERROR",
    "INTERNAL_ERROR",
    "DEFAULT",
]

_ACTION_VERB_RE = re.compile(
    r"\b(Go|Set|Check|Run|Contact|Configure|Fix|Wait|Add|Retry)\b",
    re.IGNORECASE,
)

_LEAK_PATTERNS = ("401", "500", "502", "503", "504", "traceback", "Exception")


@pytest.mark.parametrize("code", _REQUIRED_KEYS)
def test_hints_has_entry_for_every_code(code: str) -> None:
    """Every required code maps to a non-empty operator-facing hint."""
    assert code in ERROR_HINTS, f"ERROR_HINTS missing required code: {code}"
    hint = ERROR_HINTS[code]
    assert isinstance(hint, str) and hint.strip(), f"hint for {code} is empty"
    assert _ACTION_VERB_RE.search(hint), (
        f"hint for {code} lacks an operator-facing action verb: {hint!r}"
    )


@pytest.mark.parametrize("code,hint", list(ERROR_HINTS.items()))
def test_hints_values_do_not_leak_stack_or_status(code: str, hint: str) -> None:
    """Hints must not contain HTTP numbers, 'traceback', or 'Exception'."""
    for leak in _LEAK_PATTERNS:
        assert leak not in hint, f"hint for {code} leaks {leak!r}: {hint!r}"
