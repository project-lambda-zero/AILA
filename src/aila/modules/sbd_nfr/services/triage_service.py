"""Pre-triage context derivation for the SbD NFR module.

Pure functions — no DB imports, no side effects, no imports from aila.storage.

Design references: TRIAGE-01, TRIAGE-02, TRIAGE-03, TRIAGE-04.

Pre-triage context pipeline:
    1. After session completion, scope answers are extracted (SCOPE-02, SCOPE-03).
    2. build_triage_context() derives a TriageContext from those answers and
       the session's computed risk_tier (written by scoring_service).
    3. The TriageContext dict is stored as JSON on every SbdNfrSessionSystemRecord
       linked to the session (one per registered system).
    4. Downstream finding prioritisation calls adjust_finding_severity() using
       the stored severity_multiplier to adjust raw CVSS scores before display.

Threat model mitigations:
    T-154-08: pre_triage_context_json is written only inside complete_session
              (a controlled status transition) and is never exposed as a write
              endpoint.  Callers receive it read-only via GET endpoint.
    T-154-09: GET /systems/{system_id}/triage-context requires require_auth.
    T-154-10: severity_multiplier is derived from the session owner's own scope
              answers — no elevation of other systems' findings is possible.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "TriageContext",
    "build_triage_context",
    "adjust_finding_severity",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Scope-03 answer values that indicate internet-facing exposure.
_INTERNET_FACING_VALUES: frozenset[str] = frozenset({"internet_facing", "public"})

# Scope-02 answer values that indicate high-sensitivity data.
# These trigger severity_multiplier 1.5 when combined with internet-facing.
_HIGH_SENSITIVITY_VALUES: frozenset[str] = frozenset({"pii", "phi", "financial", "sensitive"})

# Scope-02 answer values that indicate low-sensitivity data.
# These trigger severity_multiplier 0.8 when exposure is internal.
_LOW_SENSITIVITY_VALUES: frozenset[str] = frozenset({"public", "internal", "internal_only", "non_sensitive"})

# Mapping from canonical risk tier strings to business_impact_tier labels.
_RISK_TIER_TO_IMPACT: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

# ---------------------------------------------------------------------------
# Immutable DTO
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TriageContext:
    """Pre-triage risk context derived from scope answers.

    Stored as JSON on SbdNfrSessionSystemRecord.pre_triage_context_json.
    Consumed by finding prioritisation (TRIAGE-03, TRIAGE-04).

    Attributes:
        data_sensitivity:    Raw SCOPE-02 answer value, or "unknown" when absent.
        internet_exposure:   Raw SCOPE-03 answer value, or "unknown" when absent.
        business_impact_tier: Lowercased equivalent of risk_tier, or "unknown".
        risk_tier:           "CRITICAL"|"HIGH"|"MEDIUM"|"LOW" — passed through
                             from scoring_service.derive_risk_tier().
        severity_multiplier: Float adjustment factor for CVSS score adjustment.
                             1.5 for internet-facing high-sensitivity systems,
                             0.8 for internal low-sensitivity systems,
                             1.0 otherwise.
    """

    data_sensitivity: str
    internet_exposure: str
    business_impact_tier: str
    risk_tier: str
    severity_multiplier: float

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable dict for storage in pre_triage_context_json."""
        return {
            "data_sensitivity": self.data_sensitivity,
            "internet_exposure": self.internet_exposure,
            "business_impact_tier": self.business_impact_tier,
            "risk_tier": self.risk_tier,
            "severity_multiplier": self.severity_multiplier,
        }


# ---------------------------------------------------------------------------
# Pure engine functions
# ---------------------------------------------------------------------------


def build_triage_context(scope_answers: dict[str, str], risk_tier: str) -> TriageContext:
    """Build a TriageContext from scope question answers and the computed risk tier.

    Args:
        scope_answers: Mapping of question_id → answer_value for SCOPE-* questions.
            Expected keys: "SCOPE-02" (data sensitivity), "SCOPE-03" (exposure).
            Missing keys default to "unknown".
        risk_tier: The risk tier computed by scoring_service.derive_risk_tier().
            One of "CRITICAL"|"HIGH"|"MEDIUM"|"LOW".  Unexpected values produce
            business_impact_tier "unknown" (safe default).

    Returns:
        Immutable TriageContext with all fields populated.

    Severity multiplier logic (TRIAGE-03, TRIAGE-04):
        1.5: internet-facing (SCOPE-03 in {"internet_facing", "public"}) AND
             high-sensitivity data (SCOPE-02 in {"pii", "phi", "financial", "sensitive"})
        0.8: internal (SCOPE-03 NOT in internet-facing set) AND
             low-sensitivity data (SCOPE-02 in {"public", "internal", "internal_only", "non_sensitive"})
        1.0: all other combinations (including missing answers)
    """
    data_sensitivity = scope_answers.get("SCOPE-02", "unknown")
    internet_exposure = scope_answers.get("SCOPE-03", "unknown")

    business_impact_tier = _RISK_TIER_TO_IMPACT.get(risk_tier, "unknown")

    # Normalise for comparison — answers from the DB are stored as-is (lowercase).
    normalised_sensitivity = data_sensitivity.strip().lower()
    normalised_exposure = internet_exposure.strip().lower()

    is_internet_facing = normalised_exposure in _INTERNET_FACING_VALUES
    is_high_sensitivity = normalised_sensitivity in _HIGH_SENSITIVITY_VALUES
    is_low_sensitivity = normalised_sensitivity in _LOW_SENSITIVITY_VALUES

    if is_internet_facing and is_high_sensitivity:
        severity_multiplier = 1.5
    elif (not is_internet_facing) and is_low_sensitivity:
        severity_multiplier = 0.8
    else:
        severity_multiplier = 1.0

    return TriageContext(
        data_sensitivity=data_sensitivity,
        internet_exposure=internet_exposure,
        business_impact_tier=business_impact_tier,
        risk_tier=risk_tier,
        severity_multiplier=severity_multiplier,
    )


def adjust_finding_severity(base_score: float, triage_context: TriageContext) -> float:
    """Apply the triage severity multiplier to a raw CVSS-style finding score.

    Args:
        base_score:      Raw finding score in [0.0, 10.0] (CVSS range).
        triage_context:  TriageContext for the system under assessment.

    Returns:
        Adjusted score = base_score * severity_multiplier, capped at 10.0 (CVSS max).
        Rounded to 2 decimal places.

    Design note: The 10.0 cap is intentional — CVSS scores cannot exceed 10.
    Rounding ensures stable comparisons and clean display values.
    """
    result = base_score * triage_context.severity_multiplier
    result = min(result, 10.0)
    return round(result, 2)
