"""Tests for the text-first verdict analyzer in the VF Yanımda PDF.

The analyzer reads the agent's full answer text and returns a corrected
verdict label (PASS / FAIL / REVIEW / INFO / INCONCLUSIVE) when the
production verdict_mapper would mis-attribute a compliance verdict to
``DIRECT_FINDING``. Exhaustive coverage of every priority rung in the
decision tree:

  1. Empty / "N/A" answer            -> INCONCLUSIVE
  2. INFO marker anywhere (head/body) -> INFO (external doc required)
  3. HEAD has REVIEW marker          -> REVIEW
  4. HEAD has both PASS + FAIL       -> earliest position wins
  5. HEAD has only PASS              -> PASS
  6. HEAD has only FAIL              -> FAIL
  7. BODY has REVIEW marker          -> REVIEW
  8. BODY has both PASS + FAIL       -> REVIEW (mixed)
  9. BODY has only PASS              -> PASS
  10. BODY has only FAIL             -> FAIL
  11. No markers anywhere            -> fallback label

Plus the word-boundary protection: ``COMPLIANT`` substring inside
``NON_COMPLIANT`` / ``NON-COMPLIANT`` / ``NOT COMPLIANT`` must NOT
fire the PASS marker.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _load_analyzer():
    """Load the analyzer from scripts/ without making it a package."""
    script_path = Path("scripts/vr_masvs_report_yanimda.py").resolve()
    spec = importlib.util.spec_from_file_location(
        "vr_masvs_report_yanimda_test_module", script_path,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["vr_masvs_report_yanimda_test_module"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def analyzer():
    return _load_analyzer()


# ----------------------------------------------------------------------
# Rung 1 — empty / "N/A" → INCONCLUSIVE
# ----------------------------------------------------------------------


def test_empty_answer_is_inconclusive(analyzer) -> None:
    label, reason = analyzer._analyze_verdict_from_text(
        {"answer": ""}, fallback_label="MAPPER_FALLBACK",
    )
    assert label == "INCONCLUSIVE"
    assert reason == "no_answer_text"


def test_whitespace_only_answer_is_inconclusive(analyzer) -> None:
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer": "   \n\t  "}, fallback_label="X",
    )
    assert label == "INCONCLUSIVE"


def test_literal_na_is_inconclusive(analyzer) -> None:
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer": "N/A"}, fallback_label="X",
    )
    assert label == "INCONCLUSIVE"


# ----------------------------------------------------------------------
# Rung 2 — INFO (external doc required) takes priority over PASS/FAIL
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "phrase",
    [
        "ARCHITECTURE_DOCUMENT_REQUIRED",
        "REQUIRES SBOM",
        "NO DATA CLASSIFICATION MATRIX",
        "PRIVACY POLICY ARTIFACT",
        "DOCUMENTATION REQUIRED",
        "OUT OF SCOPE FOR CODE AUDIT",
        "REQUIRES OPERATOR INPUT",
        "PASSWORD POLICY DOCUMENT",
    ],
)
def test_info_phrase_in_head_wins(analyzer, phrase) -> None:
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer": f"MSTG-ARCH-3 Verdict: {phrase} per Vodafone TR"},
        fallback_label="FAIL",
    )
    assert label == "INFO"


def test_info_phrase_anywhere_dominates_fail(analyzer) -> None:
    """INFO check scans the FULL text, not just the head."""
    text = "VIOLATION CONFIRMED — but resolution REQUIRES ARCHITECTURE DOCUMENT"
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer": text}, fallback_label="FAIL",
    )
    assert label == "INFO"


# ----------------------------------------------------------------------
# Rung 3 — REVIEW marker in head
# ----------------------------------------------------------------------


def test_partial_compliance_head_is_review(analyzer) -> None:
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer": "MSTG-CRYPTO-3 PARTIAL NON-COMPLIANCE: app uses AES/CBC."},
        fallback_label="FAIL",
    )
    assert label == "REVIEW"


def test_with_hardening_notes_is_review(analyzer) -> None:
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer": "ASSESSMENT: SATISFIED WITH HARDENING NOTES on rate-limit."},
        fallback_label="X",
    )
    assert label == "REVIEW"


# ----------------------------------------------------------------------
# Rung 4 — head has both PASS + FAIL → earliest position wins
# ----------------------------------------------------------------------


def test_head_fail_earlier_than_pass_wins_fail(analyzer) -> None:
    text = "VIOLATION: WebView config insecure (PASSED MDR audit but NOT mobile)"
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer": text}, fallback_label="X",
    )
    assert label == "FAIL"


def test_head_pass_earlier_than_fail_wins_pass(analyzer) -> None:
    text = "PASSED — no symmetric key reuse. Old version had a FAIL but is fixed."
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer": text}, fallback_label="X",
    )
    assert label == "PASS"


# ----------------------------------------------------------------------
# Rung 5/6 — head has only one marker
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "phrase",
    [
        "PASSED. All security-relevant random values use SecureRandom.",
        "STRONG CONFIDENCE — PASS. App conforms to MASVS control.",
        "COMPLIANCE VERIFIED. No credential-replay violation detected.",
        "SUBSTANTIALLY MEETS the control requirement.",
        "NO EXTERNALLY REACHABLE deserialization vulnerability found.",
        "AUDIT COMPLETE: NO MASVS-PRIVACY-1 violations found.",
        "PATCH PRESENT — Authorization rules ARE enforced server-side.",
        "DO NOT PERFORM SENSITIVE state-changing operations without auth.",
        "VERDICT: COMPLIANT with MSTG-CODE-2.",
    ],
)
def test_head_pass_phrases_map_to_pass(analyzer, phrase) -> None:
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer": phrase}, fallback_label="FAIL",
    )
    assert label == "PASS", f"phrase {phrase!r} should map to PASS"


@pytest.mark.parametrize(
    "phrase",
    [
        "VIOLATION CONFIRMED: hardcoded AES key reuse across channels.",
        "DIRECT_FINDING: WebView violates MSTG-PLATFORM-6.",
        "FAILS. logout does NOT call server endpoint to invalidate session.",
        "NON-COMPLIANCE on JavascriptInterface bridge exposure.",
        "VIOLATION (FAIL): Native methods exposed to JS.",
        "CONTROL NOT MET: session cookies persist after logout.",
        "AUDIT VERDICT: FAIL.",
        "CRITICAL GAP: WebView allows arbitrary JS execution.",
    ],
)
def test_head_fail_phrases_map_to_fail(analyzer, phrase) -> None:
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer": phrase}, fallback_label="PASS",
    )
    assert label == "FAIL", f"phrase {phrase!r} should map to FAIL"


# ----------------------------------------------------------------------
# Word-boundary protection: COMPLIANT inside NON_COMPLIANT
# ----------------------------------------------------------------------


def test_non_compliant_not_matched_as_compliant(analyzer) -> None:
    """The substring COMPLIANT inside NON_COMPLIANT must not fire PASS."""
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer": "NON_COMPLIANT. The APK ships 9 native libraries with insecure linkage."},
        fallback_label="X",
    )
    assert label == "FAIL"


def test_non_dash_compliant_not_matched_as_compliant(analyzer) -> None:
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer": "NON-COMPLIANT — does not meet MSTG-CRYPTO-3."},
        fallback_label="X",
    )
    assert label == "FAIL"


def test_not_compliant_not_matched_as_compliant(analyzer) -> None:
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer": "Implementation is NOT COMPLIANT with the standard."},
        fallback_label="X",
    )
    assert label == "FAIL"


# ----------------------------------------------------------------------
def test_body_mixed_pass_and_fail_is_review(analyzer) -> None:
    """When BOTH PASS + FAIL markers live in the body (past the 400-char head),
    the verdict is REVIEW per rung 8."""
    head = (
        "Investigation summary: agent walked 3 call chains and inspected "
        "12 functions across the codebase. No verdict word appears in this "
        "first 400 character window so the analyzer has to fall through to "
        "body-level marker detection. Filler filler filler filler filler "
        "filler filler filler filler filler filler filler filler filler "
        "filler filler filler filler filler filler filler filler filler "
        "filler filler filler. "
    )
    body = (
        "Section A: COMPLIANCE VERIFIED for the auth flow. "
        "Section B: VIOLATION CONFIRMED — the token revocation path is missing."
    )
    assert len(head) >= 400, "head must be >= 400 chars to push markers into body"
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer": head + body}, fallback_label="X",
    )
    assert label == "REVIEW"


# ----------------------------------------------------------------------
# Rung 11 — no markers anywhere → fallback label
# ----------------------------------------------------------------------


def test_no_markers_returns_fallback(analyzer) -> None:
    text = (
        "Investigation summary: agent reviewed 12 functions, walked 4 call "
        "chains, no decisive evidence either way. Operator should look."
    )
    label, reason = analyzer._analyze_verdict_from_text(
        {"answer": text}, fallback_label="REVIEW",
    )
    assert label == "REVIEW"
    assert "fallback_mapper" in reason


# ----------------------------------------------------------------------
# answer_brief fallback when answer is missing
# ----------------------------------------------------------------------


def test_answer_brief_used_when_answer_missing(analyzer) -> None:
    label, _ = analyzer._analyze_verdict_from_text(
        {"answer_brief": "PASSED — no symmetric key reuse."},
        fallback_label="FAIL",
    )
    assert label == "PASS"


def test_full_answer_preferred_over_brief(analyzer) -> None:
    """When both fields present, ``answer`` wins (head priority)."""
    label, _ = analyzer._analyze_verdict_from_text(
        {
            "answer": "FAIL: control bypassed.",
            "answer_brief": "PASSED.",
        },
        fallback_label="X",
    )
    assert label == "FAIL"
