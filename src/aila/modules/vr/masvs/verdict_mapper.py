"""Pure mapping rule: child investigation primary outcome → MASVS verdict (S-4).

The MASVS aggregator (R-1, :mod:`aila.modules.vr.reporting.masvs_report`)
walks every child investigation's primary outcome and turns it into one
:class:`MasvsControlVerdict` via :func:`child_outcome_to_verdict`. This
mapper is the *only* writer of verdicts in the MASVS pipeline — the
report renderer and the API payload carry the result verbatim, so any
operator-visible verdict traces back to a real child outcome. The
mapper never invents a value.

The agent-facing contract lives in the seed prompt at
:mod:`aila.modules.vr.masvs.seed` and is repeated here so prompt drift
is caught by tests:

- ``direct_finding`` with verifier confidence ≥ ``0.6`` →
  :attr:`MasvsVerdict.FINDING`.
- ``refuted`` (canonical: ``payload['verifier_report']['verdict']``;
  also accepted on plain ``assessment_report`` outcomes that write
  ``payload['verdict'] == 'refuted'`` directly) →
  :attr:`MasvsVerdict.NO_FINDING`.
- Explicit ``not_applicable`` tag in the payload (boolean field,
  ``applicability`` string, or an entry in a ``tags`` list) →
  :attr:`MasvsVerdict.NOT_APPLICABLE`.
- Everything else (timeout, cost cap, low-confidence direct finding,
  unrecognized outcome kind) → :attr:`MasvsVerdict.INCONCLUSIVE` with
  the underlying status carried through in
  :attr:`MasvsControlVerdict.reason`.

The not-applicable signal wins over every other branch because the
agent has explicitly told the auditor the underlying capability is
absent from this APK — there is nothing left to assess. Refuted then
wins over direct_finding because the verifier (or the agent's own
assessment) has explicitly contradicted the finding hypothesis.
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.contracts.masvs import MasvsControlVerdict, MasvsVerdict
from aila.modules.vr.contracts.outcome import (
    OutcomeConfidence,
    OutcomeKind,
    VROutcomeSummary,
)
from aila.modules.vr.masvs.models import MasvsControl

__all__ = [
    "child_outcome_to_verdict",
]


# Threshold above which a direct_finding's verifier confidence is treated
# as load-bearing for a MASVS ``finding`` verdict. PRD §S-4 fixes this
# at 0.6 — the same gate the auto-promotion path uses in
# :mod:`aila.modules.vr.agents.claim_verifier` (_AUTO_PROMOTE_MIN_CONFIDENCE).
_FINDING_CONFIDENCE_FLOOR: float = 0.6


# Bridge from the engine's coarse :class:`OutcomeConfidence` enum to the
# float scale ``verifier_report['confidence']`` already uses. The
# verifier emits a real float, so when it ran we read that directly;
# this table is the fallback for outcomes the verifier never touched
# (timed out before synthesis, audit memos, sub-investigations). The
# MEDIUM rung lands exactly on the FINDING floor so a MEDIUM-confidence
# direct_finding still crosses the gate when no verifier_report is
# present, matching the seed prompt's ≥0.6 cutoff.
_ENUM_CONFIDENCE: dict[OutcomeConfidence, float] = {
    OutcomeConfidence.EXACT: 1.0,
    OutcomeConfidence.STRONG: 0.85,
    OutcomeConfidence.MEDIUM: 0.6,
    OutcomeConfidence.CAVEATED: 0.3,
    OutcomeConfidence.UNKNOWN: 0.0,
}


def child_outcome_to_verdict(
    outcome: VROutcomeSummary | None,
    control: MasvsControl,
    *,
    child_investigation_id: str,
) -> MasvsControlVerdict:
    """Project one child investigation's primary outcome to a MASVS verdict.

    :param outcome: The child investigation's primary
        :class:`VROutcomeSummary`. ``None`` when the child reached a
        terminal state without emitting a primary outcome (timeout, cost
        cap exhausted, abandoned mid-flight).
    :param control: The :class:`MasvsControl` this child investigation
        was dispatched for. Provides
        :attr:`MasvsControlVerdict.control_id`.
    :param child_investigation_id: Identifier of the child investigation
        the verdict references. The aggregator already knows this from
        its iteration variable; the mapper never invents it.
    :returns: One :class:`MasvsControlVerdict` ready to embed into the
        :class:`MasvsAuditAggregate`.
    """
    if outcome is None:
        return MasvsControlVerdict(
            control_id=control.id,
            verdict=MasvsVerdict.INCONCLUSIVE,
            confidence=0.0,
            child_investigation_id=child_investigation_id,
            primary_outcome_id=None,
            reason="no_primary_outcome",
        )

    payload: dict[str, Any] = outcome.payload or {}
    verifier_verdict, verifier_conf = _extract_verifier_signal(payload)
    numeric_conf = (
        verifier_conf
        if verifier_conf is not None
        else _ENUM_CONFIDENCE.get(outcome.confidence, 0.0)
    )

    # Branch 1 — explicit not_applicable tag wins over every other
    # signal. The agent has told us the control does not apply to this
    # APK; there is nothing else to weigh.
    if _has_not_applicable_tag(payload):
        return MasvsControlVerdict(
            control_id=control.id,
            verdict=MasvsVerdict.NOT_APPLICABLE,
            confidence=numeric_conf,
            child_investigation_id=child_investigation_id,
            primary_outcome_id=outcome.id,
            reason=None,
        )

    # Branch 2 — refuted. Either the claim verifier emitted it on a
    # DIRECT_FINDING outcome (canonical post-synthesis path) or the
    # agent wrote it on an assessment_report outcome directly.
    if verifier_verdict == "refuted" or _payload_says_refuted(payload):
        return MasvsControlVerdict(
            control_id=control.id,
            verdict=MasvsVerdict.NO_FINDING,
            confidence=numeric_conf,
            child_investigation_id=child_investigation_id,
            primary_outcome_id=outcome.id,
            reason=None,
        )

    # Branch 3 — direct_finding above the confidence floor.
    if outcome.outcome_kind == OutcomeKind.DIRECT_FINDING:
        if verifier_verdict == "inconclusive":
            return MasvsControlVerdict(
                control_id=control.id,
                verdict=MasvsVerdict.INCONCLUSIVE,
                confidence=0.0,
                child_investigation_id=child_investigation_id,
                primary_outcome_id=outcome.id,
                reason=f"verifier_inconclusive_conf_{numeric_conf:.2f}",
            )
        if numeric_conf >= _FINDING_CONFIDENCE_FLOOR:
            return MasvsControlVerdict(
                control_id=control.id,
                verdict=MasvsVerdict.FINDING,
                confidence=numeric_conf,
                child_investigation_id=child_investigation_id,
                primary_outcome_id=outcome.id,
                reason=None,
            )
        return MasvsControlVerdict(
            control_id=control.id,
            verdict=MasvsVerdict.INCONCLUSIVE,
            confidence=0.0,
            child_investigation_id=child_investigation_id,
            primary_outcome_id=outcome.id,
            reason=f"direct_finding_low_confidence_{numeric_conf:.2f}",
        )

    # Branch 4 — fallthrough. Carry the underlying outcome_kind so the
    # operator can see why the child landed inconclusive (assessment
    # report without a verdict signal, audit memo, sub-investigation
    # spawn, etc.).
    return MasvsControlVerdict(
        control_id=control.id,
        verdict=MasvsVerdict.INCONCLUSIVE,
        confidence=0.0,
        child_investigation_id=child_investigation_id,
        primary_outcome_id=outcome.id,
        reason=f"outcome_kind={outcome.outcome_kind.value}",
    )


def _extract_verifier_signal(
    payload: dict[str, Any],
) -> tuple[str | None, float | None]:
    """Read ``payload['verifier_report']`` as the claim verifier writes it.

    Returns ``(verdict, confidence)`` where either may be ``None`` when
    the verifier didn't run or didn't emit that field. The verdict
    string is normalized to one of ``"confirmed"``, ``"refuted"``, or
    ``"inconclusive"`` (or ``None`` for absent / unrecognized values).
    The confidence is normalized to a float in ``[0.0, 1.0]`` or
    ``None`` for absent / out-of-range / non-numeric values.
    """
    raw = payload.get("verifier_report")
    if not isinstance(raw, dict):
        return None, None

    verdict: str | None = None
    verdict_raw = raw.get("verdict")
    if isinstance(verdict_raw, str):
        verdict_lower = verdict_raw.strip().lower()
        if verdict_lower in ("confirmed", "refuted", "inconclusive"):
            verdict = verdict_lower

    confidence: float | None = None
    conf_raw = raw.get("confidence")
    # ``bool`` is a subclass of ``int``; reject it explicitly so a stray
    # ``True`` doesn't read as ``1.0`` confidence.
    if isinstance(conf_raw, (int, float)) and not isinstance(conf_raw, bool):
        value = float(conf_raw)
        if 0.0 <= value <= 1.0:
            confidence = value

    return verdict, confidence


def _payload_says_refuted(payload: dict[str, Any]) -> bool:
    """Detect a payload-level ``verdict == 'refuted'`` signal.

    Used by the agent on ``assessment_report`` outcomes that encode
    refutation directly rather than going through the claim verifier.
    The verifier_report path is checked separately by
    :func:`_extract_verifier_signal` and takes precedence at the
    branch boundary.
    """
    verdict_raw = payload.get("verdict")
    return (
        isinstance(verdict_raw, str)
        and verdict_raw.strip().lower() == "refuted"
    )


def _has_not_applicable_tag(payload: dict[str, Any]) -> bool:
    """Detect the agent's ``not_applicable`` tag in any of three places.

    The seed prompt instructs the scout to "emit an explicit
    not_applicable tag" without nailing the field location. The agent
    may encode that as:

    - ``payload['not_applicable'] is True`` — boolean flag.
    - ``payload['applicability'] == 'not_applicable'`` — string field.
    - ``'not_applicable' in payload['tags']`` — tags list entry.

    The mapper accepts all three so a single prompt revision does not
    drop verdicts on the floor.
    """
    if payload.get("not_applicable") is True:
        return True

    applicability = payload.get("applicability")
    if (
        isinstance(applicability, str)
        and applicability.strip().lower() == "not_applicable"
    ):
        return True

    tags = payload.get("tags")
    if isinstance(tags, (list, tuple)):
        for tag in tags:
            if isinstance(tag, str) and tag.strip().lower() == "not_applicable":
                return True

    return False
