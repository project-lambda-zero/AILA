"""S-4 — :func:`child_outcome_to_verdict` mapping rule.

The four branches from PRD §S-4 plus the edge cases that matter for the
aggregator (R-1):

1. ``direct_finding`` with verifier confidence ≥ 0.6 → ``finding``.
2. ``refuted`` (verifier_report OR payload-level) → ``no_finding``.
3. Explicit ``not_applicable`` tag (boolean / applicability / tags
   list) → ``not_applicable``.
4. Everything else → ``inconclusive`` with ``reason`` carrying the
   underlying status verbatim.

Plus branch-priority invariants (``not_applicable`` wins over
``refuted``; ``refuted`` wins over ``direct_finding``), confidence
extraction fallback (no verifier_report → :class:`OutcomeConfidence`
enum mapped to float), and the no-primary-outcome case the aggregator
hits when a child timed out before emitting anything.
"""
from __future__ import annotations

from aila.modules.vr.contracts.masvs import MasvsControlVerdict, MasvsVerdict
from aila.modules.vr.contracts.outcome import (
    OutcomeConfidence,
    OutcomeKind,
    VROutcomeSummary,
)
from aila.modules.vr.masvs.catalog import MASVS_CONTROLS
from aila.modules.vr.masvs.models import MasvsControl, MasvsLevel
from aila.modules.vr.masvs.verdict_mapper import child_outcome_to_verdict


def _first_l1() -> MasvsControl:
    for c in MASVS_CONTROLS:
        if c.level == MasvsLevel.L1:
            return c
    raise AssertionError("catalog has no L1 controls; C-1b..C-1i regressed")


def _outcome(
    *,
    outcome_kind: OutcomeKind = OutcomeKind.DIRECT_FINDING,
    confidence: OutcomeConfidence = OutcomeConfidence.STRONG,
    payload: dict | None = None,
) -> VROutcomeSummary:
    return VROutcomeSummary(
        id="oc-1",
        investigation_id="inv-child-1",
        branch_id="br-1",
        outcome_kind=outcome_kind,
        payload=payload or {},
        confidence=confidence,
        evidence_refs=[],
    )


# --- Branch 1: direct_finding + confidence ≥ 0.6 → FINDING ------------------


def test_direct_finding_with_verifier_confidence_above_floor_maps_to_finding() -> None:
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.MEDIUM,
        payload={
            "verifier_report": {"verdict": "confirmed", "confidence": 0.82},
        },
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v == MasvsControlVerdict(
        control_id=control.id,
        verdict=MasvsVerdict.FINDING,
        confidence=0.82,
        child_investigation_id="inv-child-1",
        primary_outcome_id="oc-1",
        reason=None,
    )


def test_direct_finding_exactly_at_floor_is_finding() -> None:
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        payload={"verifier_report": {"verdict": "confirmed", "confidence": 0.6}},
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v.verdict == MasvsVerdict.FINDING
    assert v.confidence == 0.6


def test_direct_finding_below_floor_is_inconclusive_with_reason() -> None:
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.CAVEATED,
        payload={"verifier_report": {"verdict": "confirmed", "confidence": 0.42}},
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v.verdict == MasvsVerdict.INCONCLUSIVE
    assert v.confidence == 0.0
    assert v.reason is not None
    assert "direct_finding_low_confidence" in v.reason
    assert "0.42" in v.reason


def test_direct_finding_without_verifier_report_uses_enum_fallback() -> None:
    """No verifier_report — fall back to OutcomeConfidence enum mapping.

    STRONG → 0.85, which clears the 0.6 floor.
    """
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.STRONG,
        payload={},
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v.verdict == MasvsVerdict.FINDING
    assert v.confidence == 0.85


def test_direct_finding_with_unknown_enum_and_no_verifier_is_inconclusive() -> None:
    """UNKNOWN → 0.0; below the floor → inconclusive."""
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.UNKNOWN,
        payload={},
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v.verdict == MasvsVerdict.INCONCLUSIVE
    assert v.reason is not None
    assert "direct_finding_low_confidence" in v.reason


# --- Branch 2: refuted → NO_FINDING ----------------------------------------


def test_verifier_refuted_on_direct_finding_maps_to_no_finding() -> None:
    """Canonical post-synthesis path: verifier ran and refuted the claim."""
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.STRONG,
        payload={
            "verifier_report": {"verdict": "refuted", "confidence": 0.91},
        },
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v.verdict == MasvsVerdict.NO_FINDING
    assert v.confidence == 0.91
    assert v.reason is None


def test_payload_level_refuted_on_assessment_report_maps_to_no_finding() -> None:
    """The agent can write ``verdict: refuted`` directly on an assessment.

    Happens when the child walked every verification step and can
    affirmatively show the control is met, without going through the
    claim verifier.
    """
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.ASSESSMENT_REPORT,
        confidence=OutcomeConfidence.STRONG,
        payload={"verdict": "refuted"},
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v.verdict == MasvsVerdict.NO_FINDING


# --- Branch 3: explicit not_applicable tag → NOT_APPLICABLE ---------------


def test_not_applicable_boolean_field_maps_to_not_applicable() -> None:
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.ASSESSMENT_REPORT,
        confidence=OutcomeConfidence.STRONG,
        payload={"not_applicable": True},
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v.verdict == MasvsVerdict.NOT_APPLICABLE
    assert v.reason is None


def test_not_applicable_applicability_string_maps_to_not_applicable() -> None:
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.ASSESSMENT_REPORT,
        confidence=OutcomeConfidence.MEDIUM,
        payload={"applicability": "not_applicable"},
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v.verdict == MasvsVerdict.NOT_APPLICABLE


def test_not_applicable_in_tags_list_maps_to_not_applicable() -> None:
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.ASSESSMENT_REPORT,
        confidence=OutcomeConfidence.MEDIUM,
        payload={"tags": ["audit", "not_applicable", "native_libs_empty"]},
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v.verdict == MasvsVerdict.NOT_APPLICABLE


def test_not_applicable_wins_over_refuted() -> None:
    """Branch ordering invariant: not_applicable is checked first.

    When both signals are in the payload, the agent has told us the
    control doesn't apply to this APK — there is nothing to refute.
    """
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        payload={
            "not_applicable": True,
            "verifier_report": {"verdict": "refuted", "confidence": 0.9},
        },
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v.verdict == MasvsVerdict.NOT_APPLICABLE


def test_refuted_wins_over_direct_finding_confidence() -> None:
    """Branch ordering invariant: refuted is checked before the FINDING gate.

    A direct_finding outcome the verifier later refuted must map to
    NO_FINDING, regardless of the outcome's reported confidence.
    """
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.EXACT,
        payload={
            "verifier_report": {"verdict": "refuted", "confidence": 0.95},
        },
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v.verdict == MasvsVerdict.NO_FINDING


# --- Branch 4: default → INCONCLUSIVE with reason -------------------------


def test_no_primary_outcome_maps_to_inconclusive_with_explicit_reason() -> None:
    control = _first_l1()

    v = child_outcome_to_verdict(
        None, control, child_investigation_id="inv-child-1"
    )

    assert v == MasvsControlVerdict(
        control_id=control.id,
        verdict=MasvsVerdict.INCONCLUSIVE,
        confidence=0.0,
        child_investigation_id="inv-child-1",
        primary_outcome_id=None,
        reason="no_primary_outcome",
    )


def test_assessment_report_without_verdict_signal_is_inconclusive() -> None:
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.ASSESSMENT_REPORT,
        confidence=OutcomeConfidence.MEDIUM,
        payload={"summary": "ran out of time before reaching a verdict"},
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v.verdict == MasvsVerdict.INCONCLUSIVE
    assert v.reason is not None
    assert "assessment_report" in v.reason


def test_audit_memo_outcome_is_inconclusive_with_outcome_kind_in_reason() -> None:
    """Non-DIRECT_FINDING kinds carry through to inconclusive with the
    outcome_kind embedded in the reason so the operator can see why."""
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.AUDIT_MEMO,
        confidence=OutcomeConfidence.MEDIUM,
        payload={},
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v.verdict == MasvsVerdict.INCONCLUSIVE
    assert v.reason == "outcome_kind=audit_memo"


def test_verifier_inconclusive_on_direct_finding_maps_to_inconclusive() -> None:
    """The verifier explicitly classified the finding as inconclusive.

    Don't trust the direct_finding's reported confidence — the verifier
    overrides.
    """
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.STRONG,
        payload={
            "verifier_report": {"verdict": "inconclusive", "confidence": 0.5},
        },
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    assert v.verdict == MasvsVerdict.INCONCLUSIVE
    assert v.confidence == 0.0
    assert v.reason is not None
    assert "verifier_inconclusive" in v.reason


# --- Confidence extraction defensive cases -------------------------------


def test_verifier_report_with_non_numeric_confidence_falls_back_to_enum() -> None:
    """A malformed verifier_report.confidence must not crash the mapper."""
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.STRONG,
        payload={
            "verifier_report": {"verdict": "confirmed", "confidence": "high"},
        },
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    # Fell back to STRONG → 0.85, which clears the floor.
    assert v.verdict == MasvsVerdict.FINDING
    assert v.confidence == 0.85


def test_verifier_report_with_boolean_confidence_falls_back_to_enum() -> None:
    """``bool`` is a subclass of ``int``; reject it explicitly."""
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.CAVEATED,
        payload={
            "verifier_report": {"verdict": "confirmed", "confidence": True},
        },
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    # CAVEATED → 0.3, below the floor → inconclusive.
    assert v.verdict == MasvsVerdict.INCONCLUSIVE


def test_verifier_report_out_of_range_confidence_is_ignored() -> None:
    """Confidence outside [0.0, 1.0] is rejected; fall back to enum."""
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.UNKNOWN,
        payload={
            "verifier_report": {"verdict": "confirmed", "confidence": 1.5},
        },
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    # UNKNOWN → 0.0, below the floor → inconclusive.
    assert v.verdict == MasvsVerdict.INCONCLUSIVE


def test_verifier_report_non_dict_payload_is_ignored() -> None:
    """A string at ``payload['verifier_report']`` must not be unpacked."""
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.STRONG,
        payload={"verifier_report": "stringly-typed by mistake"},
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-1"
    )

    # Fell back to STRONG → 0.85.
    assert v.verdict == MasvsVerdict.FINDING
    assert v.confidence == 0.85


# --- Identity / reference fields ----------------------------------------


def test_verdict_carries_control_id_and_investigation_id_verbatim() -> None:
    """The mapper never invents identifiers — they pass through."""
    control = _first_l1()
    outcome = _outcome(
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.EXACT,
        payload={"verifier_report": {"verdict": "confirmed", "confidence": 0.95}},
    )

    v = child_outcome_to_verdict(
        outcome, control, child_investigation_id="inv-child-7"
    )

    assert v.control_id == control.id
    assert v.child_investigation_id == "inv-child-7"
    assert v.primary_outcome_id == outcome.id
