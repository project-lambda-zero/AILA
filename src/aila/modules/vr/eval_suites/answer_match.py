"""Reference-answer matching for the benchmark harness.

A benchmark task is solved when the VR investigation produced the task's
known reference answer. Public CTF-style benchmarks wrap the answer in a
marker such as ``flag{...}`` or ``CTF{...}``; the comparison tolerates the
wrapper and surrounding whitespace, and is case-insensitive by default
(flags are conventionally compared verbatim, but the surrounding prose an
agent emits varies in case, so a normalized compare avoids false misses).

Pure functions only -- no DB, no IO -- so the scoring rule is unit-tested
exhaustively and reused unchanged by ``suite_runner.collect_suite_run``.
"""
from __future__ import annotations

import re

__all__ = ["normalize_answer", "is_match"]

# A leading ``name{`` wrapper with a trailing ``}`` -- e.g. flag{...},
# CTF{...}, picoCTF{...}. Only the inner payload is compared.
_WRAPPER = re.compile(r"^[A-Za-z0-9_]{1,16}\{(?P<inner>.*)\}$", re.DOTALL)


def normalize_answer(value: str, *, case_insensitive: bool = True) -> str:
    """Strip whitespace and an optional ``name{...}`` wrapper from ``value``."""
    text = value.strip()
    match = _WRAPPER.match(text)
    if match is not None:
        text = match.group("inner").strip()
    return text.casefold() if case_insensitive else text


def is_match(
    reference_answer: str,
    candidate_texts: list[str],
    *,
    case_insensitive: bool = True,
) -> bool:
    """True when the reference answer appears in any candidate text.

    The reference answer is normalized once; each candidate is scanned
    both as a normalized whole (exact match after wrapper stripping) and
    as a substring (the agent usually emits the flag inside a sentence).
    An empty reference answer never matches -- a task with no known answer
    cannot be auto-scored as solved.
    """
    needle = normalize_answer(reference_answer, case_insensitive=case_insensitive)
    if not needle:
        return False
    for raw in candidate_texts:
        if not raw:
            continue
        whole = normalize_answer(raw, case_insensitive=case_insensitive)
        if whole == needle:
            return True
        haystack = raw.casefold() if case_insensitive else raw
        if needle in haystack:
            return True
    return False
