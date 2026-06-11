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

from aila.modules.vr.contracts.masvs import (
    MasvsControlVerdict,
    MasvsEvidenceLocation,
    MasvsVerdict,
)
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
#
# fix §219 — UNKNOWN is mapped to the FINDING floor (not 0.0) so the
# default behaviour for an unclassified confidence is "treat as finding
# pending operator review" rather than "silently demote to inconclusive".
# The :meth:`dict.get` default below also lands on the floor so a future
# OutcomeConfidence enum member added without updating this table fails
# safe in the same direction.
_ENUM_CONFIDENCE: dict[OutcomeConfidence, float] = {
    OutcomeConfidence.EXACT: 1.0,
    OutcomeConfidence.STRONG: 0.85,
    OutcomeConfidence.MEDIUM: 0.6,
    OutcomeConfidence.CAVEATED: 0.3,
    OutcomeConfidence.UNKNOWN: _FINDING_CONFIDENCE_FLOOR,
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
    evidence_locations, evidence_locations_total = _extract_evidence_locations(payload)
    verifier_verdict, verifier_conf = _extract_verifier_signal(payload)
    numeric_conf = (
        verifier_conf
        if verifier_conf is not None
        # fix §219 — unknown enum members fall through to the FINDING
        # floor (not 0.0) so adding a new OutcomeConfidence value defaults
        # to "treat as finding pending operator review".
        else _ENUM_CONFIDENCE.get(outcome.confidence, _FINDING_CONFIDENCE_FLOOR)
    )
    agent_summary = _extract_agent_summary(payload)

    # Branch 1 — explicit not_applicable tag wins over every other
    # signal. The agent has told us the control does not apply to this
    # APK; there is nothing else to weigh.
    if _has_not_applicable_tag(payload):
        # fix §220 — confidence is meaningless for a binary applicability
        # statement. Pin to 1.0 so downstream consumers don't read a
        # low numeric_conf as "we're not sure this is N/A" — the
        # not_applicable tag is itself the certainty signal.
        return MasvsControlVerdict(
            control_id=control.id,
            verdict=MasvsVerdict.NOT_APPLICABLE,
            confidence=1.0,
            child_investigation_id=child_investigation_id,
            primary_outcome_id=outcome.id,
            reason=None,
            evidence_locations=evidence_locations,
            evidence_locations_total=evidence_locations_total,
            agent_summary=agent_summary,
        )

    # Branch 2 — refuted. Either the claim verifier emitted it on a
    # DIRECT_FINDING outcome (canonical post-synthesis path) or the
    # agent wrote it on an assessment_report outcome directly.
    if verifier_verdict == "refuted" or _payload_says_refuted(payload) or _payload_says_pass(payload):
        return MasvsControlVerdict(
            control_id=control.id,
            verdict=MasvsVerdict.NO_FINDING,
            confidence=numeric_conf,
            child_investigation_id=child_investigation_id,
            primary_outcome_id=outcome.id,
            reason=None,
            evidence_locations=evidence_locations,
            evidence_locations_total=evidence_locations_total,
            agent_summary=agent_summary,
        )

    # Branch 3 — direct_finding. Verifier-confirmed dominates the numeric
    # confidence gate (fix §218); otherwise the float floor decides.
    if outcome.outcome_kind == OutcomeKind.DIRECT_FINDING:
        # fix §218 — verifier_verdict == 'confirmed' is the canonical
        # post-synthesis pass for a real finding. Treat it as FINDING
        # regardless of numeric_conf so a low-confidence-but-confirmed
        # claim is never demoted to inconclusive on the float gate.
        if verifier_verdict == "confirmed":
            return MasvsControlVerdict(
                control_id=control.id,
                verdict=MasvsVerdict.FINDING,
                confidence=numeric_conf,
                child_investigation_id=child_investigation_id,
                primary_outcome_id=outcome.id,
                reason=None,
                evidence_locations=evidence_locations,
                evidence_locations_total=evidence_locations_total,
                agent_summary=agent_summary,
            )
        if verifier_verdict == "inconclusive":
            return MasvsControlVerdict(
                control_id=control.id,
                verdict=MasvsVerdict.INCONCLUSIVE,
                confidence=0.0,
                child_investigation_id=child_investigation_id,
                primary_outcome_id=outcome.id,
                reason=f"verifier_inconclusive_conf_{numeric_conf:.2f}",
                evidence_locations=evidence_locations,
                evidence_locations_total=evidence_locations_total,
                agent_summary=agent_summary,
            )
        if numeric_conf >= _FINDING_CONFIDENCE_FLOOR:
            return MasvsControlVerdict(
                control_id=control.id,
                verdict=MasvsVerdict.FINDING,
                confidence=numeric_conf,
                child_investigation_id=child_investigation_id,
                primary_outcome_id=outcome.id,
                reason=None,
                evidence_locations=evidence_locations,
                evidence_locations_total=evidence_locations_total,
                agent_summary=agent_summary,
            )
        return MasvsControlVerdict(
            control_id=control.id,
            verdict=MasvsVerdict.INCONCLUSIVE,
            confidence=0.0,
            child_investigation_id=child_investigation_id,
            primary_outcome_id=outcome.id,
            reason=f"direct_finding_low_confidence_{numeric_conf:.2f}",
            evidence_locations=evidence_locations,
            evidence_locations_total=evidence_locations_total,
            agent_summary=agent_summary,
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
        evidence_locations=evidence_locations,
        evidence_locations_total=evidence_locations_total,
        agent_summary=agent_summary,
    )


def _extract_agent_summary(payload: dict[str, Any], cap_chars: int = 3500) -> str | None:
    """Pull the agent's natural-language conclusion from the outcome
    payload's ``answer`` field. Truncates to ``cap_chars`` so the PDF
    per-control subsection stays bounded.

    Returns ``None`` when:
      - the payload has no ``answer`` field at all (audit_memo synth,
        verifier-only outcomes, malformed payloads)
      - the ``answer`` is blank after stripping

    Truncation: tries to cut at a paragraph or sentence boundary near
    the cap so the report doesn't read as truncated mid-word. Falls
    back to a hard char cut + ellipsis when no boundary is close.
    """
    raw = payload.get("answer")
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    if len(text) <= cap_chars:
        return text
    window = text[:cap_chars]
    # Prefer paragraph boundary, fall back to sentence, fall back to char.
    for sep in ("\n\n", "\n", ". ", " "):
        idx = window.rfind(sep)
        if idx >= cap_chars * 0.6:  # only accept a boundary in the last 40% of the window
            return text[: idx + len(sep)].rstrip() + " …"
    return window.rstrip() + " …"


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



# Natural-language indicators that the agent concluded the control is
# COMPLIANT / PASSING / no vulnerability found — even when they
# (incorrectly) labelled the outcome with kind=direct_finding. Agents
# routinely use direct_finding as their default submit-kind regardless
# of whether they actually found a vulnerability, so the audit_memo
# system + the verifier signal alone don't catch every "we audited and
# the app is fine" outcome. The mapper falls back to parsing the
# ``payload['answer']`` text for these unambiguous PASS markers and
# treats those as NO_FINDING.
#
# Order matters: longer phrases first so partial substrings of longer
# matches don't trigger early. All checks are case-insensitive.
_PASS_PHRASES: tuple[str, ...] = (
    "no masvs violations found",
    "no compliance gap",
    "no compliance gaps",
    "no violations found",
    "no vulnerabilities found",
    "no finding identified",
    "audit complete: no",
    "audit verdict: pass",
    "audit verdict: compliant",
    "audit result: pass",
    "audit result: compliant",
    "verdict: compliant",
    "verdict: pass",
    "fully compliant",
    "is compliant with",
    "complies with masvs",
    "complies with mstg",
)

# Anti-pattern: even when one of the above is present, if the payload
# also explicitly says FAIL / CRITICAL / GAP, the agent meant a real
# finding (often mixed results — partial compliance with gaps). Don't
# flip the verdict to NO_FINDING in that case.
_FAIL_PHRASES: tuple[str, ...] = (
    "audit verdict: fail",
    "audit result: fail",
    "partial compliance",
    "critical gap",
    "compliance gap detected",
    "verdict: fail",
    "finding: yes",
    "violation detected",
    "vulnerable to",
)


def _payload_says_pass(payload: dict[str, Any]) -> bool:
    """Detect a natural-language PASS / compliant outcome.

    Agents submit outcome_kind=direct_finding for both real
    vulnerabilities AND audits that conclude the control is compliant.
    Without a payload-text override, the mapper trusts outcome_kind
    literally and renders 'audit found app is compliant' as a FAIL
    badge — operator-observed and rejected. This helper scans the
    ``answer`` field (the agent's free-text conclusion) for unambiguous
    PASS markers and returns True only when at least one PASS phrase
    is present AND no FAIL phrase is present.
    """
    answer_raw = payload.get("answer")
    if not isinstance(answer_raw, str):
        return False
    text = answer_raw.lower()
    if any(phrase in text for phrase in _FAIL_PHRASES):
        return False
    return any(phrase in text for phrase in _PASS_PHRASES)

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


# Hard cap on entries copied to a verdict — keeps the PDF table bounded
# and matches the spirit of the per-investigation pdf_report's
# ``affected_components[:8]`` slice for audit-mcp resolution. The
# verdict-level cap is larger because the MASVS PDF only renders the
# location strings (no source-body fetch), so a complex audit's full
# component chain is worth preserving up to the contract's
# ``max_length=64`` field bound.
_EVIDENCE_LOCATION_CAP: int = 32


def _extract_evidence_locations(
    payload: dict[str, Any],
) -> tuple[list[MasvsEvidenceLocation], int]:
    """Read ``payload['affected_components']`` defensively.

    Per ``vr/agents/prompts/system_audit.md``, every DIRECT_FINDING
    submit carries an ``affected_components: [{file, function}, ...]``
    list — the canonical evidence shape the per-investigation
    ``pdf_report`` also consumes. The MASVS verdict mapper surfaces
    these as :class:`MasvsEvidenceLocation` entries on the returned
    verdict so the PDF renderer can print "what the auditor cited"
    under each control without re-walking the outcome row.

    Defensive parsing:

    - Non-list payload → empty list.
    - Entries that are not dicts → skipped.
    - Dicts missing a non-empty ``file`` or ``function`` → skipped.
    - Whitespace trimmed; the contract's ``min_length=1`` would
      reject a trimmed-empty value otherwise.
    - Capped at :data:`_EVIDENCE_LOCATION_CAP` entries so a malformed
      payload listing thousands of components cannot bloat the PDF.

    The mapper never fabricates locations — when the payload omits
    the field or every entry is malformed, an empty list is the
    correct, honest output.
    """
    # fix §217 — return (capped_list, true_total) so the verdict carries
    # the pre-cap count for "N of M shown" rendering. The list is
    # bounded by :data:`_EVIDENCE_LOCATION_CAP`; the int counts every
    # validly-formed entry the agent emitted before truncation.
    raw = payload.get("affected_components")
    if not isinstance(raw, list):
        return [], 0
    locations: list[MasvsEvidenceLocation] = []
    total = 0
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        file_value = entry.get("file")
        function_value = entry.get("function")
        if not isinstance(file_value, str) or not isinstance(function_value, str):
            continue
        file_text = file_value.strip()
        function_text = function_value.strip()
        if not file_text or not function_text:
            continue
        total += 1
        if len(locations) < _EVIDENCE_LOCATION_CAP:
            locations.append(
                MasvsEvidenceLocation(file=file_text, function=function_text),
            )
    return locations, total
