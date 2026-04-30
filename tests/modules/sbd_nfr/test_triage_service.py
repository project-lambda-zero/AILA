"""Unit tests for the SbD NFR triage service.

Tests cover:
- build_triage_context: all four tier/exposure combinations, empty scope answers
- adjust_finding_severity: cap at 10.0, multiplier application
- TriageContext JSON-serialisability

Design references: TRIAGE-01, TRIAGE-02, TRIAGE-03, TRIAGE-04.
"""

from __future__ import annotations

import json

import pytest

from aila.modules.sbd_nfr.services.triage_service import (
    TriageContext,
    adjust_finding_severity,
    build_triage_context,
)


# ---------------------------------------------------------------------------
# build_triage_context tests
# ---------------------------------------------------------------------------


class TestBuildTriageContextInternetFacingPII:
    """Internet-facing + PII/PHI/financial → severity_multiplier 1.5, risk_tier CRITICAL."""

    def test_internet_facing_pii_multiplier_1_5(self) -> None:
        """SCOPE-03=internet_facing + SCOPE-02=pii → multiplier 1.5."""
        scope_answers = {"SCOPE-02": "pii", "SCOPE-03": "internet_facing"}
        ctx = build_triage_context(scope_answers, "CRITICAL")
        assert ctx.severity_multiplier == 1.5

    def test_internet_facing_pii_risk_tier(self) -> None:
        """SCOPE-03=internet_facing + SCOPE-02=pii → risk_tier CRITICAL."""
        scope_answers = {"SCOPE-02": "pii", "SCOPE-03": "internet_facing"}
        ctx = build_triage_context(scope_answers, "CRITICAL")
        assert ctx.risk_tier == "CRITICAL"

    def test_internet_facing_pii_business_impact_tier(self) -> None:
        """CRITICAL risk_tier → business_impact_tier 'critical'."""
        scope_answers = {"SCOPE-02": "pii", "SCOPE-03": "internet_facing"}
        ctx = build_triage_context(scope_answers, "CRITICAL")
        assert ctx.business_impact_tier == "critical"

    def test_internet_facing_pii_raw_fields(self) -> None:
        """data_sensitivity and internet_exposure reflect raw scope answers."""
        scope_answers = {"SCOPE-02": "pii", "SCOPE-03": "internet_facing"}
        ctx = build_triage_context(scope_answers, "CRITICAL")
        assert ctx.data_sensitivity == "pii"
        assert ctx.internet_exposure == "internet_facing"

    def test_internet_facing_phi_multiplier_1_5(self) -> None:
        """PHI is also a high-sensitivity value → multiplier 1.5."""
        scope_answers = {"SCOPE-02": "phi", "SCOPE-03": "internet_facing"}
        ctx = build_triage_context(scope_answers, "CRITICAL")
        assert ctx.severity_multiplier == 1.5

    def test_public_exposure_financial_multiplier_1_5(self) -> None:
        """SCOPE-03=public is also internet-facing → multiplier 1.5 with financial data."""
        scope_answers = {"SCOPE-02": "financial", "SCOPE-03": "public"}
        ctx = build_triage_context(scope_answers, "CRITICAL")
        assert ctx.severity_multiplier == 1.5


class TestBuildTriageContextInternalPublic:
    """Internal + public/internal data → severity_multiplier 0.8, risk_tier LOW."""

    def test_internal_public_multiplier_0_8(self) -> None:
        """Internal + public data → multiplier 0.8."""
        scope_answers = {"SCOPE-02": "public", "SCOPE-03": "internal"}
        ctx = build_triage_context(scope_answers, "LOW")
        assert ctx.severity_multiplier == 0.8

    def test_internal_public_risk_tier_low(self) -> None:
        """LOW risk_tier → business_impact_tier 'low'."""
        scope_answers = {"SCOPE-02": "public", "SCOPE-03": "internal"}
        ctx = build_triage_context(scope_answers, "LOW")
        assert ctx.risk_tier == "LOW"
        assert ctx.business_impact_tier == "low"

    def test_internal_only_data_multiplier_0_8(self) -> None:
        """internal_only data classification is also low-sensitivity."""
        scope_answers = {"SCOPE-02": "internal_only", "SCOPE-03": "internal"}
        ctx = build_triage_context(scope_answers, "LOW")
        assert ctx.severity_multiplier == 0.8

    def test_non_sensitive_data_multiplier_0_8(self) -> None:
        """non_sensitive data classification with internal → multiplier 0.8."""
        scope_answers = {"SCOPE-02": "non_sensitive", "SCOPE-03": "internal"}
        ctx = build_triage_context(scope_answers, "LOW")
        assert ctx.severity_multiplier == 0.8


class TestBuildTriageContextInternetFacingConfidential:
    """Internet-facing + confidential (not high-sensitivity) → multiplier 1.0, risk_tier HIGH."""

    def test_internet_facing_confidential_multiplier_1_0(self) -> None:
        """Confidential data is not PII/PHI/financial → falls through to 1.0."""
        scope_answers = {"SCOPE-02": "confidential", "SCOPE-03": "internet_facing"}
        ctx = build_triage_context(scope_answers, "HIGH")
        assert ctx.severity_multiplier == 1.0

    def test_internet_facing_confidential_risk_tier(self) -> None:
        """HIGH risk_tier → business_impact_tier 'high'."""
        scope_answers = {"SCOPE-02": "confidential", "SCOPE-03": "internet_facing"}
        ctx = build_triage_context(scope_answers, "HIGH")
        assert ctx.risk_tier == "HIGH"
        assert ctx.business_impact_tier == "high"


class TestBuildTriageContextEmptyScopeAnswers:
    """Empty scope answers with unknown risk_tier → business_impact_tier 'unknown', severity_multiplier 1.0."""

    def test_empty_scope_answers_business_impact_tier(self) -> None:
        """No scope answers + unrecognised risk_tier → business_impact_tier 'unknown'."""
        ctx = build_triage_context({}, "UNKNOWN")
        assert ctx.business_impact_tier == "unknown"

    def test_empty_scope_answers_multiplier(self) -> None:
        """No scope answers → severity_multiplier defaults to 1.0 (no exposure/sensitivity data)."""
        ctx = build_triage_context({}, "UNKNOWN")
        assert ctx.severity_multiplier == 1.0

    def test_empty_scope_answers_unknown_fields(self) -> None:
        """Missing SCOPE-02 and SCOPE-03 → raw fields default to 'unknown'."""
        ctx = build_triage_context({}, "UNKNOWN")
        assert ctx.data_sensitivity == "unknown"
        assert ctx.internet_exposure == "unknown"

    def test_unknown_risk_tier_business_impact(self) -> None:
        """An unexpected risk_tier string → business_impact_tier 'unknown'."""
        ctx = build_triage_context({}, "UNDEFINED_TIER")
        assert ctx.business_impact_tier == "unknown"


# ---------------------------------------------------------------------------
# adjust_finding_severity tests
# ---------------------------------------------------------------------------


class TestAdjustFindingSeverityCapped:
    """Score * multiplier > 10.0 is capped at 10.0."""

    def test_score_8_0_multiplier_1_5_capped(self) -> None:
        """8.0 * 1.5 = 12.0 → capped to 10.0."""
        scope_answers = {"SCOPE-02": "pii", "SCOPE-03": "internet_facing"}
        ctx = build_triage_context(scope_answers, "CRITICAL")
        result = adjust_finding_severity(8.0, ctx)
        assert result == 10.0

    def test_exact_cap_boundary(self) -> None:
        """10.0 * 1.5 → capped at 10.0."""
        scope_answers = {"SCOPE-02": "pii", "SCOPE-03": "internet_facing"}
        ctx = build_triage_context(scope_answers, "CRITICAL")
        result = adjust_finding_severity(10.0, ctx)
        assert result == 10.0


class TestAdjustFindingSeverityMultiplied:
    """Scores within range are multiplied and returned correctly."""

    def test_score_5_0_multiplier_1_5(self) -> None:
        """5.0 * 1.5 = 7.5."""
        scope_answers = {"SCOPE-02": "pii", "SCOPE-03": "internet_facing"}
        ctx = build_triage_context(scope_answers, "CRITICAL")
        result = adjust_finding_severity(5.0, ctx)
        assert result == 7.5

    def test_score_5_0_multiplier_0_8(self) -> None:
        """5.0 * 0.8 = 4.0."""
        scope_answers = {"SCOPE-02": "public", "SCOPE-03": "internal"}
        ctx = build_triage_context(scope_answers, "LOW")
        result = adjust_finding_severity(5.0, ctx)
        assert result == 4.0

    def test_score_0_0_any_multiplier(self) -> None:
        """0.0 * anything = 0.0."""
        scope_answers = {"SCOPE-02": "pii", "SCOPE-03": "internet_facing"}
        ctx = build_triage_context(scope_answers, "CRITICAL")
        result = adjust_finding_severity(0.0, ctx)
        assert result == 0.0

    def test_score_rounded_to_two_decimals(self) -> None:
        """Result is rounded to 2 decimal places."""
        scope_answers = {}
        ctx = build_triage_context(scope_answers, "MEDIUM")
        # multiplier 1.0 → no rounding needed but test the return type
        result = adjust_finding_severity(3.333, ctx)
        assert result == round(3.333 * 1.0, 2)


# ---------------------------------------------------------------------------
# TriageContext JSON-serialisability
# ---------------------------------------------------------------------------


class TestTriageContextSerialisation:
    """TriageContext.to_dict() must produce a JSON-serialisable dict."""

    def test_json_serialisable(self) -> None:
        """json.dumps on to_dict() succeeds without error."""
        scope_answers = {"SCOPE-02": "pii", "SCOPE-03": "internet_facing"}
        ctx = build_triage_context(scope_answers, "CRITICAL")
        serialised = json.dumps(ctx.to_dict())
        assert isinstance(serialised, str)

    def test_to_dict_keys(self) -> None:
        """to_dict() contains the required canonical keys."""
        scope_answers = {"SCOPE-02": "pii", "SCOPE-03": "internet_facing"}
        ctx = build_triage_context(scope_answers, "CRITICAL")
        d = ctx.to_dict()
        assert set(d.keys()) == {
            "data_sensitivity",
            "internet_exposure",
            "business_impact_tier",
            "risk_tier",
            "severity_multiplier",
        }

    def test_roundtrip_from_json(self) -> None:
        """Values survive a JSON serialise/deserialise round-trip."""
        scope_answers = {"SCOPE-02": "phi", "SCOPE-03": "public"}
        ctx = build_triage_context(scope_answers, "CRITICAL")
        d = ctx.to_dict()
        restored = json.loads(json.dumps(d))
        assert restored["data_sensitivity"] == ctx.data_sensitivity
        assert restored["internet_exposure"] == ctx.internet_exposure
        assert restored["severity_multiplier"] == ctx.severity_multiplier
        assert restored["risk_tier"] == ctx.risk_tier
        assert restored["business_impact_tier"] == ctx.business_impact_tier
