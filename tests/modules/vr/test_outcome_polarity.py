"""Coverage for ``_derive_outcome_polarity`` (VR investigation summary).

The synthesis banner and the investigations list badge both read
``primary_outcome_polarity`` off the summary envelope. Before this
helper landed, a no-finding audit_memo rendered identically to a
DirectFinding on both surfaces because the UI only saw
``outcome_kind`` and had no polarity signal. The helper reduces the
raw outcome_kind + payload pair to one of three user-visible states
under a fixed precedence: verifier verdict wins first, then the two
kind-level heuristics, then a catch-all inconclusive.

These tests pin every branch of that precedence so a future edit
that reorders the checks (e.g. running the direct_finding shortcut
before the verifier verdict) fails here before it ships.
"""
from __future__ import annotations

from aila.modules.vr.api_router import _derive_outcome_polarity


def test_direct_finding_without_verifier_collapses_to_finding() -> None:
    assert _derive_outcome_polarity("direct_finding", {}) == "finding"


def test_audit_memo_with_no_finding_verdict_collapses_to_no_finding() -> None:
    # The exact payload shape ``_build_vr_no_finding_payload`` writes
    # in ``services.investigation_finalizers`` -- verdict marker plus
    # the finalizer's rule / synthesized_by provenance fields.
    payload = {
        "verdict": "no_finding",
        "summary": "no exploitable path found across 3 branches",
        "branches": [],
        "synthesized_by": (
            "investigation_finalizers.synthesize_no_finding_outcomes"
        ),
        "synthesized_at": "2026-07-28T00:00:00Z",
        "rule": "every_investigation_has_outcome",
    }
    assert _derive_outcome_polarity("audit_memo", payload) == "no_finding"


def test_audit_memo_without_no_finding_verdict_collapses_to_inconclusive() -> None:
    # An audit_memo can also carry a plain narrative (agent notes,
    # partial assessments) with no ``verdict`` marker. That is not
    # a resolved outcome; it must not read as green in the UI.
    assert (
        _derive_outcome_polarity(
            "audit_memo",
            {"answer": "left as an exercise for the analyst"},
        )
        == "inconclusive"
    )


def test_verifier_confirmed_wins_over_audit_memo_kind() -> None:
    # The verifier ran, agreed there is a vulnerability, and stamped
    # ``verdict='confirmed'``. Even if the outcome was originally
    # filed under ``audit_memo`` the verifier's judgement must
    # promote it to a finding on the summary badge.
    payload = {
        "verdict": "no_finding",  # stale finalizer marker
        "verifier_report": {"verdict": "confirmed", "confidence": 0.92},
    }
    assert _derive_outcome_polarity("audit_memo", payload) == "finding"


def test_verifier_refuted_wins_over_direct_finding_kind() -> None:
    # The claim verifier reduced a DirectFinding to a refuted report
    # (false positive / patch already present). Polarity must flip to
    # ``no_finding`` regardless of the ``direct_finding`` kind so the
    # list badge stops calling it a landed vulnerability.
    payload = {
        "verifier_report": {"verdict": "refuted", "confidence": 0.81},
    }
    assert _derive_outcome_polarity("direct_finding", payload) == "no_finding"


def test_verifier_inconclusive_falls_through_to_kind_precedence() -> None:
    # An inconclusive verifier verdict does NOT short-circuit the
    # kind checks -- a direct_finding whose verifier could neither
    # confirm nor refute still reads as a finding on the badge.
    payload = {
        "verifier_report": {"verdict": "inconclusive", "confidence": 0.5},
    }
    assert _derive_outcome_polarity("direct_finding", payload) == "finding"


def test_assessment_report_without_verifier_is_inconclusive() -> None:
    # Neither a DirectFinding nor a no-finding audit_memo. Any of the
    # other 9 outcome kinds (assessment_report, variant_hunt_order,
    # patch_assessment_report, crash_triage_report, ...) fall through
    # to inconclusive.
    assert (
        _derive_outcome_polarity("assessment_report", {"answer": "TBD"})
        == "inconclusive"
    )


def test_variant_hunt_order_is_inconclusive() -> None:
    # A dispatched variant hunt order is a directive, not a resolved
    # verdict on the seed investigation itself.
    assert _derive_outcome_polarity("variant_hunt_order", {}) == "inconclusive"


def test_empty_outcome_kind_returns_none() -> None:
    # When the investigation has no primary outcome at all the helper
    # returns None so the UI can distinguish "nothing landed yet"
    # from a real inconclusive outcome. Callers additionally guard
    # with ``if primary is not None`` so this branch is defensive,
    # but it must be honoured either way.
    assert _derive_outcome_polarity("", {}) is None


def test_verifier_report_field_not_a_dict_is_ignored() -> None:
    # A malformed payload where ``verifier_report`` isn't a dict must
    # NOT crash the reducer; it falls through to kind precedence.
    payload = {"verifier_report": "confirmed"}
    assert _derive_outcome_polarity("direct_finding", payload) == "finding"
    assert (
        _derive_outcome_polarity("assessment_report", payload)
        == "inconclusive"
    )
