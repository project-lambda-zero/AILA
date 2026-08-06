"""Pure tests for the forensics writeup bounding helpers (#48-3.5).

These tests exercise `_check_bundle_size` and `_truncate_output` in
isolation: no database, no LLM client, no service factory. They pin
the Decision 8 refusal semantics (refuse structurally unanswerable
work) and the post-truncation contract (bounded output plus a
detectable marker) so a downstream regression trips a unit test
before it reaches a real investigation.
"""
from __future__ import annotations

import pytest

from aila.modules.forensics.reporting.writeup_builder import (
    _BUNDLE_HARD_LIMIT,
    _OUTPUT_CHAR_CAP,
    _OUTPUT_TRUNCATION_MARKER,
    _USER_BUNDLE_CHAR_CAP,
    _check_bundle_size,
    _truncate_output,
)

# ---------------------------------------------------------------------------
# _check_bundle_size
# ---------------------------------------------------------------------------

def test_hard_limit_matches_soft_cap_multiplier() -> None:
    # Design 3.5: refusal fires at _USER_BUNDLE_CHAR_CAP * 4. Pin the
    # relationship so a future edit to either constant does not
    # silently relax the refusal threshold.
    assert _BUNDLE_HARD_LIMIT == _USER_BUNDLE_CHAR_CAP * 4


def test_under_hard_limit_does_not_raise() -> None:
    # A bundle exactly at the limit is accepted; refusal is strict `>`.
    bundle = "a" * _BUNDLE_HARD_LIMIT
    _check_bundle_size(bundle)
    # Comfortably below the limit -- the ordinary large investigation.
    _check_bundle_size("a" * (_BUNDLE_HARD_LIMIT // 2))


def test_over_hard_limit_raises_value_error_with_byte_overage() -> None:
    overage = 137
    bundle = "x" * (_BUNDLE_HARD_LIMIT + overage)
    with pytest.raises(ValueError) as excinfo:
        _check_bundle_size(bundle)
    msg = str(excinfo.value)
    # Message names the actual bundle size, the hard limit, and the
    # byte overage so the operator can see how far past the limit
    # the assembled request is.
    assert str(_BUNDLE_HARD_LIMIT + overage) in msg
    assert str(_BUNDLE_HARD_LIMIT) in msg
    assert str(overage) in msg
    assert "narrower question" in msg


def test_over_hard_limit_reports_per_section_breakdown_when_supplied() -> None:
    bundle = "x" * (_BUNDLE_HARD_LIMIT + 1)
    sizes = {"step_log": 90_000, "case_header": 500, "observables": 40_000}
    with pytest.raises(ValueError) as excinfo:
        _check_bundle_size(bundle, sizes)
    msg = str(excinfo.value)
    # Every named section shows up with its char count so the operator
    # can point at the offending sub-report and narrow the question.
    for name, count in sizes.items():
        assert f"{name}={count}" in msg
    # Breakdown is ordered by descending size (largest offender first).
    step_log_pos = msg.index("step_log=90000")
    observables_pos = msg.index("observables=40000")
    case_header_pos = msg.index("case_header=500")
    assert step_log_pos < observables_pos < case_header_pos


def test_over_hard_limit_omits_breakdown_when_no_sizes_given() -> None:
    with pytest.raises(ValueError) as excinfo:
        _check_bundle_size("x" * (_BUNDLE_HARD_LIMIT + 1))
    assert "per-section chars" not in str(excinfo.value)


def test_injectable_hard_limit_for_narrower_tests() -> None:
    # The helper accepts a hard_limit override so future callers can
    # tighten the refusal threshold without touching the module
    # constant; assert the override actually drives the decision.
    _check_bundle_size("x" * 100, hard_limit=200)
    with pytest.raises(ValueError):
        _check_bundle_size("x" * 300, hard_limit=200)


# ---------------------------------------------------------------------------
# _truncate_output
# ---------------------------------------------------------------------------

def test_short_output_passes_through_unchanged() -> None:
    content = "# Report\nEverything fits.\n"
    assert _truncate_output(content) == content


def test_output_at_cap_passes_through_unchanged() -> None:
    # Cap is inclusive: a string of exactly _OUTPUT_CHAR_CAP is NOT
    # truncated. Truncation fires only on `>`.
    content = "a" * _OUTPUT_CHAR_CAP
    result = _truncate_output(content)
    assert result == content
    assert not result.endswith(_OUTPUT_TRUNCATION_MARKER)


def test_output_over_cap_is_truncated_and_marked() -> None:
    content = "a" * (_OUTPUT_CHAR_CAP + 5_000)
    result = _truncate_output(content)
    # Length is bounded: cap chars of body plus the fixed marker.
    assert len(result) == _OUTPUT_CHAR_CAP + len(_OUTPUT_TRUNCATION_MARKER)
    # Body carries the prefix of the original content.
    assert result.startswith("a" * _OUTPUT_CHAR_CAP)
    # Marker is exact so downstream string-match consumers can detect
    # truncation without regex.
    assert result.endswith(_OUTPUT_TRUNCATION_MARKER)


def test_truncation_marker_is_the_documented_string() -> None:
    # Pin the marker literal: downstream PDF / SSE consumers depend
    # on this exact string to badge a truncated report.
    assert _OUTPUT_TRUNCATION_MARKER == (
        "\n\n[...output truncated at 64000 chars; contact operator...]"
    )


def test_truncation_uses_injectable_cap() -> None:
    # The cap argument overrides the module constant so callers can
    # test the boundary without allocating 64k characters.
    result = _truncate_output("abcdef", cap=3)
    assert result == "abc" + _OUTPUT_TRUNCATION_MARKER


def test_output_cap_is_the_documented_value() -> None:
    # Pin the numeric contract: 64 000 chars, matching the marker text.
    assert _OUTPUT_CHAR_CAP == 64_000
