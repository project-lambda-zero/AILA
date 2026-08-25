"""VR outcome-polarity reducer -- single home for the finding /
no_finding / inconclusive classification.

Previously lived inside ``vr/api_router.py`` (``_derive_outcome_polarity``).
Extracted here so non-router paths (the follow-up discovery take-over
service, future outcome-summary consumers) can import the helper without
dragging in the FastAPI router module. ``api_router.py`` re-imports the
helper under its historical private alias so its behaviour + the polarity
test module keep working unchanged.

Derivation contract (mirror of ``frontend/components/OutcomePolarityBadge.tsx``):

1. ``payload['verifier_report']['verdict']``:

   * ``'confirmed'`` -> ``'finding'``
   * ``'refuted'``   -> ``'no_finding'``

   The verifier's judgement wins over the finalizer's initial call --
   an ``audit_memo`` whose verifier said ``confirmed`` is a finding on
   the badge, and a ``direct_finding`` whose verifier said ``refuted``
   is a no-finding on the badge. Any other verifier verdict (or a
   non-dict ``verifier_report``) falls through to the kind checks.

2. ``outcome_kind == 'direct_finding'`` -> ``'finding'``.
3. ``outcome_kind == 'audit_memo'`` combined with
   ``payload['verdict'] == 'no_finding'`` -> ``'no_finding'``
   (the shape written by ``_build_vr_no_finding_payload`` in
   ``services.investigation_finalizers``).
4. Everything else, including a plain narrative ``audit_memo`` without
   the ``no_finding`` verdict marker and every non-finding outcome
   kind (assessment_report, variant_hunt_order, patch_assessment_report,
   crash_triage_report, ...), collapses to ``'inconclusive'``.

Callers pass an empty ``outcome_kind`` when there is no primary outcome
at all; the helper returns ``None`` in that case so the UI can tell
"no outcome yet" apart from "an outcome landed but it's genuinely
inconclusive". Both list and single-investigation summary builders
additionally guard the call with ``if primary is not None`` so the
empty-kind branch is defensive.
"""
from __future__ import annotations

from typing import Literal

__all__ = [
    "derive_outcome_polarity",
    "derive_verifier_verdict",
    "investigation_outcome_axes",
]

_Polarity = Literal["finding", "no_finding", "inconclusive"]


def derive_outcome_polarity(
    outcome_kind: str,
    payload: dict,
) -> _Polarity | None:
    """Reduce a primary outcome to its user-visible polarity.

    See the module docstring for the fixed precedence contract.
    """
    if not outcome_kind:
        return None
    verifier_report = payload.get("verifier_report")
    if isinstance(verifier_report, dict):
        verifier_verdict = verifier_report.get("verdict")
        if verifier_verdict == "confirmed":
            return "finding"
        if verifier_verdict == "refuted":
            return "no_finding"
    if outcome_kind == "direct_finding":
        return "finding"
    if outcome_kind == "audit_memo" and payload.get("verdict") == "no_finding":
        return "no_finding"
    return "inconclusive"


def derive_verifier_verdict(payload: dict) -> str | None:
    """Return the raw verifier verdict string, or None when absent.

    Reads ``payload['verifier_report']['verdict']``; safe against a
    missing or non-dict ``verifier_report`` and against a non-string
    verdict field. Used to keep the denormalized ``verifier_verdict``
    filter column on ``VRInvestigationRecord`` in sync with the
    verifier report the claim verifier stamps on the canonical outcome.
    """
    report = payload.get("verifier_report")
    if isinstance(report, dict):
        v = report.get("verdict")
        if isinstance(v, str) and v:
            return v
    return None


def investigation_outcome_axes(
    outcome_kind: str, payload: dict,
) -> tuple[_Polarity | None, str | None]:
    """Return ``(primary_outcome_polarity, verifier_verdict)`` for
    the given canonical outcome kind + payload. Composed helper used
    by the investigation write hooks to update both denormalized
    filter columns in one shot.
    """
    return (
        derive_outcome_polarity(outcome_kind, payload),
        derive_verifier_verdict(payload),
    )
