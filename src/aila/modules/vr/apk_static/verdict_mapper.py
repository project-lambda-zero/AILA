"""Pure mapping rule: APK static child outcome -> ApkStaticControlVerdict.

Mirrors :mod:`aila.modules.vr.masvs.verdict_mapper` field-for-field.
Verdict semantics are identical across the two audit surfaces, so this
module reuses the MASVS helpers verbatim rather than duplicating the
payload-reading logic:

- confidence gate + enum-to-float bridge
  (``_ENUM_CONFIDENCE``, ``_FINDING_CONFIDENCE_FLOOR``)
- verifier-report parsing (``_extract_verifier_signal``)
- refuted / pass / not-applicable payload sniffers
  (``_payload_says_refuted``, ``_payload_says_pass``,
  ``_has_not_applicable_tag``)
- evidence-location extraction (``_extract_evidence_locations``)
- agent-summary window (``_extract_agent_summary``)
- synthesis panel_summary read (``_extract_synthesis_fields``)

The only new content here is the branch shape that emits an
:class:`~aila.modules.vr.contracts.apk_static.ApkStaticControlVerdict`
carrying an APK static check id instead of an OWASP MASVS control id.
Every verdict this mapper emits traces back to a real child investigation
outcome; no path invents a value.

The mapping rule (identical to MASVS):

- ``direct_finding`` with verifier confidence >= ``0.6`` ->
  :attr:`MasvsVerdict.FINDING`.
- ``refuted`` (canonical ``payload['verifier_report']['verdict']`` or a
  plain ``payload['verdict'] == 'refuted'`` on assessment_report
  outcomes) -> :attr:`MasvsVerdict.NO_FINDING`.
- Explicit ``not_applicable`` tag anywhere in the payload ->
  :attr:`MasvsVerdict.NOT_APPLICABLE`.
- Everything else (timeout, cost cap, low-confidence direct finding,
  unrecognized outcome kind) -> :attr:`MasvsVerdict.INCONCLUSIVE` with
  the underlying status carried through in
  :attr:`ApkStaticControlVerdict.reason`.
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.apk_static.models import ApkStaticCheck
from aila.modules.vr.contracts.apk_static import ApkStaticControlVerdict
from aila.modules.vr.contracts.masvs import MasvsVerdict
from aila.modules.vr.contracts.outcome import OutcomeKind, VROutcomeSummary
from aila.modules.vr.masvs.verdict_mapper import (
    _ENUM_CONFIDENCE,
    _FINDING_CONFIDENCE_FLOOR,
    _extract_agent_summary,
    _extract_evidence_locations,
    _extract_synthesis_fields,
    _extract_verifier_signal,
    _has_not_applicable_tag,
    _payload_says_pass,
    _payload_says_refuted,
)

__all__ = [
    "apk_static_child_outcome_to_verdict",
]


def apk_static_child_outcome_to_verdict(
    outcome: VROutcomeSummary | None,
    check: ApkStaticCheck,
    *,
    child_investigation_id: str,
) -> ApkStaticControlVerdict:
    """Project one child investigation's primary outcome to an APK verdict.

    :param outcome: The child investigation's primary
        :class:`VROutcomeSummary`. ``None`` when the child reached a
        terminal state without emitting a primary outcome (timeout, cost
        cap exhausted, abandoned mid-flight).
    :param check: The :class:`ApkStaticCheck` this child investigation
        was dispatched for. Provides
        :attr:`ApkStaticControlVerdict.control_id`.
    :param child_investigation_id: Identifier of the child investigation
        the verdict references. The collector already knows this from
        its iteration variable; the mapper never invents it.
    :returns: One :class:`ApkStaticControlVerdict` ready to embed into
        the :class:`ApkStaticAuditAggregate`.
    """
    if outcome is None:
        return ApkStaticControlVerdict(
            control_id=check.id,
            verdict=MasvsVerdict.INCONCLUSIVE,
            confidence=0.0,
            child_investigation_id=child_investigation_id,
            primary_outcome_id=None,
            reason="no_primary_outcome",
        )

    payload: dict[str, Any] = outcome.payload or {}
    evidence_locations, evidence_locations_total = _extract_evidence_locations(payload)
    verifier_verdict, verifier_conf = _extract_verifier_signal(payload)
    numeric_conf = (
        verifier_conf
        if verifier_conf is not None
        else _ENUM_CONFIDENCE.get(outcome.confidence, _FINDING_CONFIDENCE_FLOOR)
    )
    agent_summary = _extract_agent_summary(payload)
    scope, headline, key_points = _extract_synthesis_fields(payload)

    common: dict[str, Any] = {
        "control_id": check.id,
        "child_investigation_id": child_investigation_id,
        "primary_outcome_id": outcome.id,
        "evidence_locations": evidence_locations,
        "evidence_locations_total": evidence_locations_total,
        "agent_summary": agent_summary,
        "scope": scope,
        "headline": headline,
        "key_points": key_points,
    }

    # Branch 1 -- explicit not_applicable tag wins over every other
    # signal. The agent has told us the check does not apply to this
    # APK; there is nothing else to weigh. Confidence pins to 1.0 so
    # downstream consumers do not read a low numeric_conf as "we're
    # not sure this is N/A" -- the tag itself is the certainty signal.
    if _has_not_applicable_tag(payload):
        return ApkStaticControlVerdict(
            verdict=MasvsVerdict.NOT_APPLICABLE,
            confidence=1.0,
            reason=None,
            **common,
        )

    # Branch 2 -- refuted. Either the claim verifier emitted it on a
    # DIRECT_FINDING outcome (canonical post-synthesis path), or the
    # agent wrote it on an assessment_report outcome directly, or the
    # answer text carries an unambiguous PASS marker.
    if (
        verifier_verdict == "refuted"
        or _payload_says_refuted(payload)
        or _payload_says_pass(payload)
    ):
        return ApkStaticControlVerdict(
            verdict=MasvsVerdict.NO_FINDING,
            confidence=numeric_conf,
            reason=None,
            **common,
        )

    # Branch 3 -- direct_finding. Verifier-confirmed dominates the numeric
    # confidence gate; otherwise the float floor decides.
    if outcome.outcome_kind == OutcomeKind.DIRECT_FINDING:
        if verifier_verdict == "confirmed":
            return ApkStaticControlVerdict(
                verdict=MasvsVerdict.FINDING,
                confidence=numeric_conf,
                reason=None,
                **common,
            )
        if verifier_verdict == "inconclusive":
            return ApkStaticControlVerdict(
                verdict=MasvsVerdict.INCONCLUSIVE,
                confidence=0.0,
                reason=f"verifier_inconclusive_conf_{numeric_conf:.2f}",
                **common,
            )
        if numeric_conf >= _FINDING_CONFIDENCE_FLOOR:
            return ApkStaticControlVerdict(
                verdict=MasvsVerdict.FINDING,
                confidence=numeric_conf,
                reason=None,
                **common,
            )
        return ApkStaticControlVerdict(
            verdict=MasvsVerdict.INCONCLUSIVE,
            confidence=0.0,
            reason=f"direct_finding_low_confidence_{numeric_conf:.2f}",
            **common,
        )

    # Branch 4 -- fallthrough. Carry the underlying outcome_kind so the
    # operator can see why the child landed inconclusive (assessment
    # report without a verdict signal, audit memo, sub-investigation
    # spawn, etc.).
    return ApkStaticControlVerdict(
        verdict=MasvsVerdict.INCONCLUSIVE,
        confidence=0.0,
        reason=f"outcome_kind={outcome.outcome_kind.value}",
        **common,
    )
