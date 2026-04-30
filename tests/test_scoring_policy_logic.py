"""Comprehensive unit tests for scoring policy pure functions.

Tests: calculate_score_breakdown, build_scoring_evidence, build_report_sections,
apply_overrides, and all helper functions in policy.py.
"""
from __future__ import annotations

import pytest

from aila.modules.vulnerability.agents.scoring.config import (
    ControlGapWeights,
    CVSSBands,
    EPSSOverridePolicy,
    ExploitabilityWeights,
    InternalDowngradePolicy,
    NoFixOverridePolicy,
    ScoringOverrides,
    ScoringPolicyConfig,
    ScoringWeights,
)
from aila.modules.vulnerability.agents.scoring.models import ScoreBreakdown, ScoringCandidate
from aila.modules.vulnerability.agents.scoring.policy import (
    apply_overrides,
    build_advisory_provenance,
    build_intel_provenance,
    build_rationale,
    build_report_sections,
    build_scoring_evidence,
    bump_category,
    calculate_score_breakdown,
    category_from_score,
    control_gap_points,
    exploitability_points,
    format_scoring_mode_note,
    normalize_percentile,
    normalize_scoring_mode,
    raise_minimum,
    severity_profile,
)
from aila.modules.vulnerability.contracts import ScoringModeCounts, ScoringRunSummary, SignalAssessment


# ---------------------------------------------------------------------------
# Fixtures: reusable policy config and candidate builders
# ---------------------------------------------------------------------------

def _make_policy(**overrides) -> ScoringPolicyConfig:
    """Build a realistic ScoringPolicyConfig with sane defaults."""
    defaults = dict(
        policy_id="test-policy",
        category_order=["Planned", "Moderate", "High", "Immediate"],
        category_sla={
            "Planned": "90 days",
            "Moderate": "30 days",
            "High": "14 days",
            "Immediate": "48 hours",
        },
        category_thresholds={
            "Moderate": 25,
            "High": 50,
            "Immediate": 75,
        },
        exposure_points={
            "internet_facing": 15,
            "partner_exposed": 10,
            "internal_flat_network": 5,
            "internal_segmented": 2,
            "isolated": 0,
            "unknown": 5,
        },
        weights=ScoringWeights(
            epss_max_points=20,
            kev_listed_points=15,
            severity_points={
                "critical": 20,
                "high": 15,
                "medium": 10,
                "low": 5,
                "unknown": 0,
            },
            cvss_bands=CVSSBands(critical_min=9.0, high_min=7.0, medium_min=4.0, low_min=0.1),
            exploitability=ExploitabilityWeights(
                attack_vector_network=5,
                attack_vector_adjacent=3,
                privileges_none=5,
                privileges_low=3,
                user_interaction_none=3,
                poc_available=4,
                max_points=15,
            ),
            control_gap=ControlGapWeights(
                patch_available=3,
                missing_mitigating_control=4,
                missing_detection=3,
            ),
        ),
        overrides=ScoringOverrides(
            kev_minimum_category="High",
            epss_escalation=EPSSOverridePolicy(
                percentile_threshold=95.0,
                required_exposure="internet_facing",
                required_privileges=["NONE", "LOW"],
                default_minimum_category="High",
                network_severity_levels=["critical", "high"],
                network_minimum_category="Immediate",
            ),
            no_fix_escalation=NoFixOverridePolicy(
                required_exposure="internet_facing",
                required_attack_vector="network",
                required_severity_level="critical",
                require_no_mitigating_control=True,
                category_delta=1,
            ),
            internal_downgrade=InternalDowngradePolicy(
                allowed_exposures=["internal_segmented", "isolated"],
                required_attack_vector="local",
                required_privileges="high",
                exclude_kev_listed=True,
                category_delta=-1,
            ),
        ),
    )
    defaults.update(overrides)
    return ScoringPolicyConfig(**defaults)


def _make_candidate(**overrides) -> ScoringCandidate:
    """Build a ScoringCandidate with realistic defaults."""
    defaults = dict(
        system_id=1,
        system_name="web-server",
        host="web01.example.com",
        distribution="ubuntu",
        package_name="openssl",
        installed_version="3.0.1",
        cve_id="CVE-2024-12345",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
        fixed_version="3.0.2",
        host_description="Ubuntu 22.04 web server",
        cve_description="Buffer overflow in OpenSSL.",
        base_severity="HIGH",
        cvss_score=8.1,
        attack_vector="NETWORK",
        privileges_required="NONE",
        user_interaction="NONE",
        epss_score=0.45,
        epss_percentile=0.92,
        kev_listed=False,
        evidence_sources=["nvd", "osv"],
        advisory_ids=["GHSA-1234"],
        advisory_source_modes=["live"],
        advisory_last_synced_at=[],
        intel_source_mode="live",
        intel_last_synced_at=None,
    )
    defaults.update(overrides)
    return ScoringCandidate(**defaults)


def _make_signal_assessment(**overrides) -> SignalAssessment:
    """Build a SignalAssessment with realistic defaults."""
    defaults = dict(
        exposure="internet_facing",
        mitigating_control_present=False,
        detection_present=False,
        poc_available=True,
        cve_detail_commentary="Critical buffer overflow.",
        environment_commentary="Internet-facing server.",
        operator_guidance="Patch immediately.",
    )
    defaults.update(overrides)
    return SignalAssessment(**defaults)


@pytest.fixture
def policy():
    return _make_policy()


@pytest.fixture
def candidate():
    return _make_candidate()


@pytest.fixture
def signal_assessment():
    return _make_signal_assessment()


# ---------------------------------------------------------------------------
# normalize_percentile
# ---------------------------------------------------------------------------

class TestNormalizePercentile:
    def test_percentile_in_0_to_1_range(self):
        assert normalize_percentile(0.85, None) == 85.0

    def test_percentile_already_0_to_100(self):
        assert normalize_percentile(85.0, None) == 85.0

    def test_percentile_zero(self):
        assert normalize_percentile(0.0, None) == 0.0

    def test_percentile_one_boundary(self):
        assert normalize_percentile(1.0, None) == 100.0

    def test_percentile_just_above_one(self):
        # Value > 1 is already in 0-100 range
        assert normalize_percentile(1.01, None) == 1.01

    def test_percentile_none_falls_back_to_epss_score(self):
        assert normalize_percentile(None, 0.30) == 30.0

    def test_both_none_returns_zero(self):
        assert normalize_percentile(None, None) == 0.0

    def test_percentile_takes_priority_over_score(self):
        result = normalize_percentile(0.75, 0.10)
        assert result == 75.0


# ---------------------------------------------------------------------------
# severity_profile
# ---------------------------------------------------------------------------

class TestSeverityProfile:
    def test_critical_cvss(self, policy):
        level, points = severity_profile(9.8, None, policy)
        assert level == "critical"
        assert points == 20

    def test_high_cvss(self, policy):
        level, points = severity_profile(7.5, None, policy)
        assert level == "high"
        assert points == 15

    def test_medium_cvss(self, policy):
        level, points = severity_profile(5.0, None, policy)
        assert level == "medium"
        assert points == 10

    def test_low_cvss(self, policy):
        level, points = severity_profile(2.0, None, policy)
        assert level == "low"
        assert points == 5

    def test_below_low_min(self, policy):
        # cvss_score 0.0 is below low_min (0.1), falls through to base_severity
        level, points = severity_profile(0.0, "MEDIUM", policy)
        assert level == "medium"
        assert points == 10

    def test_cvss_exactly_at_critical_boundary(self, policy):
        level, points = severity_profile(9.0, None, policy)
        assert level == "critical"

    def test_cvss_exactly_at_high_boundary(self, policy):
        level, points = severity_profile(7.0, None, policy)
        assert level == "high"

    def test_cvss_just_below_high(self, policy):
        level, points = severity_profile(6.99, None, policy)
        assert level == "medium"

    def test_base_severity_fallback_when_no_cvss(self, policy):
        level, points = severity_profile(None, "CRITICAL", policy)
        assert level == "critical"
        assert points == 20

    def test_base_severity_low(self, policy):
        level, points = severity_profile(None, "low", policy)
        assert level == "low"
        assert points == 5

    def test_unknown_when_both_none(self, policy):
        level, points = severity_profile(None, None, policy)
        assert level == "unknown"
        assert points == 0

    def test_unknown_for_nonsense_severity(self, policy):
        level, points = severity_profile(None, "bananas", policy)
        assert level == "unknown"
        assert points == 0

    def test_cvss_overrides_base_severity(self, policy):
        # cvss_score says critical, base_severity says low -- cvss wins
        level, _ = severity_profile(9.5, "LOW", policy)
        assert level == "critical"


# ---------------------------------------------------------------------------
# exploitability_points
# ---------------------------------------------------------------------------

class TestExploitabilityPoints:
    def test_network_none_none_with_poc(self, policy):
        pts = exploitability_points("NETWORK", "NONE", "NONE", True, policy)
        # 5 (network) + 5 (none priv) + 3 (no interaction) + 4 (poc) = 17 -> capped to 15
        assert pts == 15

    def test_network_none_none_no_poc(self, policy):
        pts = exploitability_points("NETWORK", "NONE", "NONE", False, policy)
        # 5 + 5 + 3 + 0 = 13
        assert pts == 13

    def test_adjacent_low_required_no_poc(self, policy):
        pts = exploitability_points("ADJACENT", "LOW", "REQUIRED", False, policy)
        # 3 (adjacent) + 3 (low) + 0 (required) + 0 = 6
        assert pts == 6

    def test_local_vector_contributes_nothing(self, policy):
        pts = exploitability_points("LOCAL", "HIGH", "REQUIRED", False, policy)
        assert pts == 0

    def test_none_values_contribute_nothing(self, policy):
        pts = exploitability_points(None, None, None, False, policy)
        assert pts == 0

    def test_empty_strings(self, policy):
        pts = exploitability_points("", "", "", False, policy)
        assert pts == 0

    def test_poc_alone(self, policy):
        pts = exploitability_points("LOCAL", "HIGH", "REQUIRED", True, policy)
        assert pts == 4

    def test_max_cap_applied(self, policy):
        # Even with all flags set the cap must hold
        pts = exploitability_points("NETWORK", "NONE", "NONE", True, policy)
        assert pts <= policy.weights.exploitability.max_points


# ---------------------------------------------------------------------------
# control_gap_points
# ---------------------------------------------------------------------------

class TestControlGapPoints:
    def test_all_gaps(self, policy):
        pts = control_gap_points(True, False, False, policy)
        # 3 (patch) + 4 (no mitigating) + 3 (no detection) = 10
        assert pts == 10

    def test_no_gaps(self, policy):
        pts = control_gap_points(False, True, True, policy)
        assert pts == 0

    def test_patch_only(self, policy):
        pts = control_gap_points(True, True, True, policy)
        assert pts == 3

    def test_missing_detection_only(self, policy):
        pts = control_gap_points(False, True, False, policy)
        assert pts == 3

    def test_missing_mitigating_only(self, policy):
        pts = control_gap_points(False, False, True, policy)
        assert pts == 4


# ---------------------------------------------------------------------------
# category_from_score
# ---------------------------------------------------------------------------

class TestCategoryFromScore:
    def test_zero_score(self, policy):
        assert category_from_score(0, policy) == "Planned"

    def test_below_moderate(self, policy):
        assert category_from_score(24, policy) == "Planned"

    def test_at_moderate(self, policy):
        assert category_from_score(25, policy) == "Moderate"

    def test_at_high(self, policy):
        assert category_from_score(50, policy) == "High"

    def test_at_immediate(self, policy):
        assert category_from_score(75, policy) == "Immediate"

    def test_score_100(self, policy):
        assert category_from_score(100, policy) == "Immediate"

    def test_between_moderate_and_high(self, policy):
        assert category_from_score(49, policy) == "Moderate"


# ---------------------------------------------------------------------------
# raise_minimum
# ---------------------------------------------------------------------------

class TestRaiseMinimum:
    def test_raises_when_minimum_higher(self, policy):
        result = raise_minimum("Planned", "High", policy.category_rank)
        assert result == "High"

    def test_keeps_current_when_already_higher(self, policy):
        result = raise_minimum("Immediate", "High", policy.category_rank)
        assert result == "Immediate"

    def test_same_rank_keeps_current(self, policy):
        result = raise_minimum("High", "High", policy.category_rank)
        assert result == "High"


# ---------------------------------------------------------------------------
# bump_category
# ---------------------------------------------------------------------------

class TestBumpCategory:
    def test_bump_up(self, policy):
        result = bump_category("Moderate", 1, policy.category_order, policy.category_rank)
        assert result == "High"

    def test_bump_down(self, policy):
        result = bump_category("High", -1, policy.category_order, policy.category_rank)
        assert result == "Moderate"

    def test_bump_up_clamped(self, policy):
        result = bump_category("Immediate", 1, policy.category_order, policy.category_rank)
        assert result == "Immediate"

    def test_bump_down_clamped(self, policy):
        result = bump_category("Planned", -1, policy.category_order, policy.category_rank)
        assert result == "Planned"

    def test_bump_zero(self, policy):
        result = bump_category("Moderate", 0, policy.category_order, policy.category_rank)
        assert result == "Moderate"

    def test_large_positive_delta(self, policy):
        result = bump_category("Planned", 99, policy.category_order, policy.category_rank)
        assert result == "Immediate"


# ---------------------------------------------------------------------------
# apply_overrides
# ---------------------------------------------------------------------------

class TestApplyOverrides:
    def test_no_overrides_triggered(self, policy):
        candidate = _make_candidate(
            kev_listed=False,
            attack_vector="LOCAL",
            privileges_required="HIGH",
            fixed_version="3.0.2",
        )
        final, overrides, hard_min = apply_overrides(
            base_category="Moderate",
            candidate=candidate,
            exposure="internal_flat_network",
            severity_level="medium",
            epss_percentile_100=50.0,
            mitigating_control_present=True,
            policy=policy,
        )
        assert final == "Moderate"
        assert overrides == []
        assert hard_min == "Planned"

    def test_kev_raises_minimum(self, policy):
        candidate = _make_candidate(kev_listed=True, attack_vector="LOCAL", privileges_required="HIGH")
        final, overrides, hard_min = apply_overrides(
            base_category="Planned",
            candidate=candidate,
            exposure="internal_flat_network",
            severity_level="medium",
            epss_percentile_100=10.0,
            mitigating_control_present=True,
            policy=policy,
        )
        assert final == "High"
        assert hard_min == "High"
        assert len(overrides) == 1
        assert "KEV listed" in overrides[0]

    def test_kev_does_not_lower_existing_higher_category(self, policy):
        candidate = _make_candidate(kev_listed=True, attack_vector="LOCAL", privileges_required="HIGH")
        final, overrides, _ = apply_overrides(
            base_category="Immediate",
            candidate=candidate,
            exposure="internal_flat_network",
            severity_level="high",
            epss_percentile_100=10.0,
            mitigating_control_present=True,
            policy=policy,
        )
        assert final == "Immediate"

    def test_epss_escalation_default(self, policy):
        candidate = _make_candidate(
            kev_listed=False,
            epss_percentile=0.97,
            attack_vector="LOCAL",
            privileges_required="NONE",
            fixed_version="3.0.2",
        )
        final, overrides, hard_min = apply_overrides(
            base_category="Planned",
            candidate=candidate,
            exposure="internet_facing",
            severity_level="medium",
            epss_percentile_100=97.0,
            mitigating_control_present=False,
            policy=policy,
        )
        assert final == "High"
        assert hard_min == "High"
        assert any("EPSS percentile" in o for o in overrides)

    def test_epss_escalation_network_critical_gets_immediate(self, policy):
        candidate = _make_candidate(
            kev_listed=False,
            attack_vector="NETWORK",
            privileges_required="NONE",
            fixed_version="3.0.2",
        )
        final, overrides, hard_min = apply_overrides(
            base_category="Planned",
            candidate=candidate,
            exposure="internet_facing",
            severity_level="critical",
            epss_percentile_100=97.0,
            mitigating_control_present=False,
            policy=policy,
        )
        assert final == "Immediate"
        assert hard_min == "Immediate"

    def test_epss_escalation_not_triggered_below_threshold(self, policy):
        candidate = _make_candidate(
            kev_listed=False,
            attack_vector="NETWORK",
            privileges_required="NONE",
            fixed_version="3.0.2",
        )
        final, overrides, _ = apply_overrides(
            base_category="Moderate",
            candidate=candidate,
            exposure="internet_facing",
            severity_level="critical",
            epss_percentile_100=90.0,  # below threshold of 95
            mitigating_control_present=False,
            policy=policy,
        )
        assert not any("EPSS" in o for o in overrides)

    def test_epss_escalation_not_triggered_wrong_exposure(self, policy):
        candidate = _make_candidate(
            kev_listed=False,
            attack_vector="NETWORK",
            privileges_required="NONE",
            fixed_version="3.0.2",
        )
        final, overrides, _ = apply_overrides(
            base_category="Moderate",
            candidate=candidate,
            exposure="internal_segmented",
            severity_level="critical",
            epss_percentile_100=97.0,
            mitigating_control_present=False,
            policy=policy,
        )
        assert not any("EPSS" in o for o in overrides)

    def test_epss_escalation_not_triggered_wrong_privileges(self, policy):
        candidate = _make_candidate(
            kev_listed=False,
            attack_vector="NETWORK",
            privileges_required="HIGH",
            fixed_version="3.0.2",
        )
        final, overrides, _ = apply_overrides(
            base_category="Moderate",
            candidate=candidate,
            exposure="internet_facing",
            severity_level="critical",
            epss_percentile_100=97.0,
            mitigating_control_present=False,
            policy=policy,
        )
        assert not any("EPSS" in o for o in overrides)

    def test_no_fix_escalation(self, policy):
        candidate = _make_candidate(
            kev_listed=False,
            fixed_version=None,
            attack_vector="NETWORK",
            privileges_required="HIGH",
        )
        final, overrides, _ = apply_overrides(
            base_category="High",
            candidate=candidate,
            exposure="internet_facing",
            severity_level="critical",
            epss_percentile_100=50.0,
            mitigating_control_present=False,
            policy=policy,
        )
        assert final == "Immediate"
        assert any("No fix" in o for o in overrides)

    def test_no_fix_escalation_blocked_by_mitigating_control(self, policy):
        candidate = _make_candidate(
            kev_listed=False,
            fixed_version=None,
            attack_vector="NETWORK",
            privileges_required="HIGH",
        )
        final, overrides, _ = apply_overrides(
            base_category="High",
            candidate=candidate,
            exposure="internet_facing",
            severity_level="critical",
            epss_percentile_100=50.0,
            mitigating_control_present=True,
            policy=policy,
        )
        assert not any("No fix" in o for o in overrides)
        assert final == "High"

    def test_no_fix_not_triggered_wrong_severity(self, policy):
        candidate = _make_candidate(
            kev_listed=False,
            fixed_version=None,
            attack_vector="NETWORK",
            privileges_required="NONE",
        )
        final, overrides, _ = apply_overrides(
            base_category="Moderate",
            candidate=candidate,
            exposure="internet_facing",
            severity_level="high",  # requires critical
            epss_percentile_100=50.0,
            mitigating_control_present=False,
            policy=policy,
        )
        assert not any("No fix" in o for o in overrides)

    def test_internal_downgrade(self, policy):
        candidate = _make_candidate(
            kev_listed=False,
            attack_vector="LOCAL",
            privileges_required="HIGH",
            fixed_version="3.0.2",
        )
        final, overrides, _ = apply_overrides(
            base_category="High",
            candidate=candidate,
            exposure="internal_segmented",
            severity_level="medium",
            epss_percentile_100=10.0,
            mitigating_control_present=True,
            policy=policy,
        )
        assert final == "Moderate"
        assert any("Internal" in o or "downgrade" in o for o in overrides)

    def test_internal_downgrade_blocked_by_kev(self, policy):
        candidate = _make_candidate(
            kev_listed=True,
            attack_vector="LOCAL",
            privileges_required="HIGH",
            fixed_version="3.0.2",
        )
        final, overrides, _ = apply_overrides(
            base_category="High",
            candidate=candidate,
            exposure="internal_segmented",
            severity_level="medium",
            epss_percentile_100=10.0,
            mitigating_control_present=True,
            policy=policy,
        )
        # KEV override raises to High, internal downgrade is excluded for KEV
        assert not any("downgrade" in o for o in overrides)

    def test_internal_downgrade_isolated(self, policy):
        candidate = _make_candidate(
            kev_listed=False,
            attack_vector="LOCAL",
            privileges_required="HIGH",
            fixed_version="3.0.2",
        )
        final, overrides, _ = apply_overrides(
            base_category="Moderate",
            candidate=candidate,
            exposure="isolated",
            severity_level="medium",
            epss_percentile_100=10.0,
            mitigating_control_present=True,
            policy=policy,
        )
        assert final == "Planned"
        assert any("downgrade" in o for o in overrides)

    def test_multiple_overrides_stack(self, policy):
        """KEV + EPSS escalation on an internet-facing, none-priv, high severity."""
        candidate = _make_candidate(
            kev_listed=True,
            attack_vector="NETWORK",
            privileges_required="NONE",
            fixed_version="3.0.2",
        )
        final, overrides, hard_min = apply_overrides(
            base_category="Planned",
            candidate=candidate,
            exposure="internet_facing",
            severity_level="high",
            epss_percentile_100=97.0,
            mitigating_control_present=False,
            policy=policy,
        )
        # KEV raises to High, EPSS network+high raises to Immediate
        assert final == "Immediate"
        assert len(overrides) >= 2


# ---------------------------------------------------------------------------
# calculate_score_breakdown (integration of all helpers)
# ---------------------------------------------------------------------------

class TestCalculateScoreBreakdown:
    def test_basic_high_severity_internet_facing(self, policy, candidate, signal_assessment):
        breakdown = calculate_score_breakdown(candidate, signal_assessment, policy)
        assert isinstance(breakdown, ScoreBreakdown)
        assert breakdown.exposure == "internet_facing"
        assert breakdown.severity_level == "high"
        assert breakdown.patch_available is True
        assert breakdown.poc_available is True
        assert breakdown.weighted_score <= 100
        assert breakdown.weighted_score > 0
        assert breakdown.final_category in policy.category_order

    def test_zero_epss_zero_cvss(self, policy):
        candidate = _make_candidate(
            cvss_score=None,
            base_severity=None,
            epss_score=None,
            epss_percentile=None,
            kev_listed=False,
            attack_vector=None,
            privileges_required=None,
            user_interaction=None,
            fixed_version=None,
        )
        signal = _make_signal_assessment(
            exposure="unknown",
            poc_available=False,
            mitigating_control_present=True,
            detection_present=True,
        )
        breakdown = calculate_score_breakdown(candidate, signal, policy)
        assert breakdown.epss_component == 0
        assert breakdown.kev_component == 0
        assert breakdown.severity_level == "unknown"
        assert breakdown.severity_component == 0
        assert breakdown.exploitability_component == 0
        # exposure_points for "unknown" = 5
        assert breakdown.exposure_component == 5
        # No patch, no missing controls -> 0 control gap
        assert breakdown.control_gap_component == 0

    def test_kev_listed_raises_category(self, policy):
        candidate = _make_candidate(
            kev_listed=True,
            cvss_score=5.0,
            epss_percentile=0.30,
            attack_vector="LOCAL",
            privileges_required="HIGH",
            user_interaction="REQUIRED",
        )
        signal = _make_signal_assessment(
            exposure="internal_segmented",
            poc_available=False,
            mitigating_control_present=True,
            detection_present=True,
        )
        breakdown = calculate_score_breakdown(candidate, signal, policy)
        assert breakdown.kev_component == 15
        assert "KEV listed" in breakdown.overrides[0]
        # KEV ensures minimum of High
        assert policy.category_rank[breakdown.final_category] >= policy.category_rank["High"]

    def test_score_capped_at_100(self, policy):
        """Even with all high signals, weighted_score must not exceed 100."""
        candidate = _make_candidate(
            kev_listed=True,
            cvss_score=10.0,
            epss_percentile=0.99,
            attack_vector="NETWORK",
            privileges_required="NONE",
            user_interaction="NONE",
        )
        signal = _make_signal_assessment(
            exposure="internet_facing",
            poc_available=True,
            mitigating_control_present=False,
            detection_present=False,
        )
        breakdown = calculate_score_breakdown(candidate, signal, policy)
        assert breakdown.weighted_score <= 100

    def test_component_sum_matches_weighted_score(self, policy, candidate, signal_assessment):
        breakdown = calculate_score_breakdown(candidate, signal_assessment, policy)
        raw_sum = (
            breakdown.epss_component
            + breakdown.kev_component
            + breakdown.exposure_component
            + breakdown.exploitability_component
            + breakdown.severity_component
            + breakdown.control_gap_component
        )
        assert breakdown.weighted_score == min(100, raw_sum)

    def test_epss_percentile_100_rounded(self, policy):
        candidate = _make_candidate(epss_percentile=0.123456789)
        signal = _make_signal_assessment()
        breakdown = calculate_score_breakdown(candidate, signal, policy)
        # normalize_percentile(0.123456789) => 12.3456789
        assert breakdown.epss_percentile_100 == round(12.3456789, 2)

    def test_patch_available_false_when_no_fixed_version(self, policy):
        candidate = _make_candidate(fixed_version=None)
        signal = _make_signal_assessment()
        breakdown = calculate_score_breakdown(candidate, signal, policy)
        assert breakdown.patch_available is False

    def test_isolated_low_severity_gets_planned(self, policy):
        candidate = _make_candidate(
            cvss_score=2.0,
            base_severity="LOW",
            epss_percentile=0.05,
            kev_listed=False,
            attack_vector="LOCAL",
            privileges_required="HIGH",
            user_interaction="REQUIRED",
            fixed_version=None,
        )
        signal = _make_signal_assessment(
            exposure="isolated",
            poc_available=False,
            mitigating_control_present=True,
            detection_present=True,
        )
        breakdown = calculate_score_breakdown(candidate, signal, policy)
        # Very low score should land in Planned
        assert breakdown.final_category == "Planned"


# ---------------------------------------------------------------------------
# build_scoring_evidence
# ---------------------------------------------------------------------------

class TestBuildScoringEvidence:
    def _make_breakdown(self):
        return ScoreBreakdown(
            exposure="internet_facing",
            severity_level="high",
            patch_available=True,
            mitigating_control_present=False,
            detection_present=False,
            poc_available=True,
            epss_component=18,
            kev_component=0,
            exposure_component=15,
            exploitability_component=13,
            severity_component=15,
            control_gap_component=10,
            weighted_score=71,
            base_category="High",
            final_category="High",
            hard_minimum_category="Planned",
            overrides=[],
            epss_percentile_100=92.0,
        )

    def test_builds_valid_evidence(self):
        candidate = _make_candidate()
        breakdown = self._make_breakdown()
        evidence = build_scoring_evidence(
            candidate,
            breakdown,
            agent_review_enabled=True,
            signal_analysis_source="model",
            signal_assessment_error=None,
            cve_commentary="Buffer overflow in OpenSSL.",
            environment_commentary="Internet-facing web server.",
            operator_guidance="Patch immediately.",
        )
        assert evidence.exposure == "internet_facing"
        assert evidence.severity_level == "high"
        assert evidence.weighted_score == 71
        assert evidence.final_category == "High"
        assert evidence.scoring_mode == "model"
        assert evidence.signal_analysis_confidence == "reviewed"
        assert evidence.cve_commentary == "Buffer overflow in OpenSSL."

    def test_cache_source_sets_cached_review_confidence(self):
        candidate = _make_candidate()
        breakdown = self._make_breakdown()
        evidence = build_scoring_evidence(
            candidate,
            breakdown,
            agent_review_enabled=True,
            signal_analysis_source="cache",
            signal_assessment_error=None,
            cve_commentary="",
            environment_commentary="",
            operator_guidance="",
        )
        assert evidence.scoring_mode == "cache"
        assert evidence.signal_analysis_confidence == "cached_review"

    def test_fallback_source_normalized_to_model(self):
        candidate = _make_candidate()
        breakdown = self._make_breakdown()
        evidence = build_scoring_evidence(
            candidate,
            breakdown,
            agent_review_enabled=True,
            signal_analysis_source="fallback",
            signal_assessment_error=None,
            cve_commentary="",
            environment_commentary="",
            operator_guidance="",
        )
        assert evidence.scoring_mode == "model"

    def test_advisory_fields_passed_through(self):
        candidate = _make_candidate(
            advisory_ids=["GHSA-1234", "DSA-5678"],
            advisory_severities=["HIGH", "CRITICAL"],
            advisory_types=["vulnerability"],
            alternate_fixed_versions=["3.0.3", "3.1.0"],
            vendor_statuses=["affected"],
            vendor_urgencies=["high"],
        )
        breakdown = self._make_breakdown()
        evidence = build_scoring_evidence(
            candidate,
            breakdown,
            agent_review_enabled=True,
            signal_analysis_source="model",
            signal_assessment_error=None,
            cve_commentary="",
            environment_commentary="",
            operator_guidance="",
        )
        assert evidence.advisory_ids == ["GHSA-1234", "DSA-5678"]
        assert evidence.advisory_severities == ["HIGH", "CRITICAL"]
        assert evidence.alternate_fixed_versions == ["3.0.3", "3.1.0"]

    def test_signal_assessment_error_passes_through(self):
        candidate = _make_candidate()
        breakdown = self._make_breakdown()
        evidence = build_scoring_evidence(
            candidate,
            breakdown,
            agent_review_enabled=True,
            signal_analysis_source="model",
            signal_assessment_error="LLM timeout",
            cve_commentary="",
            environment_commentary="",
            operator_guidance="",
        )
        assert evidence.signal_analysis_error == "LLM timeout"


# ---------------------------------------------------------------------------
# normalize_scoring_mode
# ---------------------------------------------------------------------------

class TestNormalizeScoringMode:
    def test_model(self):
        assert normalize_scoring_mode("model") == "model"

    def test_cache(self):
        assert normalize_scoring_mode("cache") == "cache"

    def test_fallback(self):
        assert normalize_scoring_mode("fallback") == "fallback"

    def test_mixed_coerced_to_model(self):
        assert normalize_scoring_mode("mixed") == "model"

    def test_none(self):
        assert normalize_scoring_mode(None) == ""

    def test_unknown_string(self):
        assert normalize_scoring_mode("banana") == ""

    def test_case_insensitive(self):
        assert normalize_scoring_mode("MODEL") == "model"
        assert normalize_scoring_mode("Cache") == "cache"

    def test_whitespace_stripped(self):
        assert normalize_scoring_mode("  model  ") == "model"


# ---------------------------------------------------------------------------
# format_scoring_mode_note
# ---------------------------------------------------------------------------

class TestFormatScoringModeNote:
    def test_no_findings(self):
        meta = ScoringRunSummary(
            scoring_mode="model",
            scoring_counts=ScoringModeCounts(model=0, cache=0),
        )
        result = format_scoring_mode_note(meta)
        assert result == "Scoring mode: no findings required review."

    def test_all_model(self):
        meta = ScoringRunSummary(
            scoring_mode="model",
            scoring_counts=ScoringModeCounts(model=5, cache=0),
        )
        result = format_scoring_mode_note(meta)
        assert "fresh model review" in result
        assert "5 fresh" in result

    def test_all_cache(self):
        meta = ScoringRunSummary(
            scoring_mode="cache",
            scoring_counts=ScoringModeCounts(model=0, cache=10),
        )
        result = format_scoring_mode_note(meta)
        assert "cached model review" in result
        assert "10 cached" in result

    def test_mixed_mode(self):
        meta = ScoringRunSummary(
            scoring_mode="mixed",
            scoring_counts=ScoringModeCounts(model=3, cache=7),
        )
        result = format_scoring_mode_note(meta)
        assert "mixed" in result
        assert "3 fresh" in result
        assert "7 cached" in result


# ---------------------------------------------------------------------------
# build_rationale
# ---------------------------------------------------------------------------

class TestBuildRationale:
    def test_all_sections_present(self):
        result = build_rationale(
            "CVSS 9.8, KEV listed.",
            "Critical remote code execution.",
            "Apply patch immediately.",
            "No major uncertainty.",
        )
        assert "Facts: CVSS 9.8" in result
        assert "Assessment: Critical" in result
        assert "Recommended action: Apply patch" in result
        assert "Uncertainty: No major" in result

    def test_empty_section_skipped(self):
        result = build_rationale(
            "Some facts.",
            "",
            "Do something.",
            "Some doubt.",
        )
        # "Assessment: " ends with ": " so it should be filtered out
        assert "Assessment:" not in result

    def test_all_empty_sections(self):
        result = build_rationale("", "", "", "")
        assert result == ""


# ---------------------------------------------------------------------------
# build_advisory_provenance
# ---------------------------------------------------------------------------

class TestBuildAdvisoryProvenance:
    def test_empty_modes(self):
        result = build_advisory_provenance([], [])
        assert result == "Advisory provenance was not recorded."

    def test_all_live(self):
        result = build_advisory_provenance(["live", "live"], [])
        assert "fetched live" in result

    def test_all_cache_with_sync_date(self):
        result = build_advisory_provenance(["cache"], ["2024-01-15T10:00:00Z"])
        assert "cached OSV data last synced at 2024-01-15T10:00:00Z" in result

    def test_all_cache_no_sync_date(self):
        result = build_advisory_provenance(["cache"], [])
        assert result == "Advisory provenance: cached OSV data."

    def test_mixed(self):
        result = build_advisory_provenance(["live", "cache"], ["2024-01-15T10:00:00Z"])
        assert "mixed" in result
        assert "2024-01-15T10:00:00Z" in result

    def test_mixed_no_sync_date(self):
        result = build_advisory_provenance(["live", "cache"], [])
        assert "mixed" in result

    def test_blank_entries_filtered(self):
        result = build_advisory_provenance(["", None, "live"], [])
        assert "fetched live" in result


# ---------------------------------------------------------------------------
# build_intel_provenance
# ---------------------------------------------------------------------------

class TestBuildIntelProvenance:
    def test_live(self):
        result = build_intel_provenance("live", None)
        assert "fetched live" in result

    def test_cache_with_date(self):
        result = build_intel_provenance("cache", "2024-02-01T00:00:00Z")
        assert "cached CVE intelligence last synced" in result

    def test_cache_no_date(self):
        result = build_intel_provenance("cache", None)
        assert result == "Intel provenance: cached CVE intelligence."

    def test_fallback(self):
        result = build_intel_provenance("fallback", None)
        assert "fallback" in result

    def test_none(self):
        result = build_intel_provenance(None, None)
        assert result == "Intel provenance was not recorded."

    def test_unknown_string(self):
        result = build_intel_provenance("potato", None)
        assert result == "Intel provenance was not recorded."


# ---------------------------------------------------------------------------
# build_report_sections
# ---------------------------------------------------------------------------

class TestBuildReportSections:
    def test_full_report_sections(self, policy):
        candidate = _make_candidate(
            base_severity="HIGH",
            cvss_score=8.1,
            kev_listed=True,
            attack_vector="NETWORK",
            privileges_required="NONE",
            user_interaction="NONE",
            fixed_version="3.0.2",
            fixed_version_note="Upstream advisory recommends 3.0.2+.",
            alternate_fixed_versions=["3.0.3"],
            vendor_urgencies=["high"],
            vendor_fix_states=["fix_available"],
            vendor_support_channels=["upstream-security"],
            vendor_statuses=["affected"],
            vendor_status_notes=["Backport expected."],
            evidence_sources=["nvd", "osv"],
            advisory_ids=["GHSA-1234"],
            advisory_source_modes=["live"],
            advisory_last_synced_at=[],
            intel_source_mode="live",
            intel_last_synced_at=None,
            host_description="Ubuntu 22.04 web server",
        )
        breakdown = ScoreBreakdown(
            exposure="internet_facing",
            severity_level="high",
            patch_available=True,
            mitigating_control_present=False,
            detection_present=False,
            poc_available=True,
            epss_component=18,
            kev_component=15,
            exposure_component=15,
            exploitability_component=13,
            severity_component=15,
            control_gap_component=10,
            weighted_score=86,
            base_category="Immediate",
            final_category="Immediate",
            hard_minimum_category="High",
            overrides=["KEV listed: minimum category raised to High."],
            epss_percentile_100=92.0,
        )
        facts, inference, recommended, uncertainty = build_report_sections(
            candidate,
            breakdown,
            cve_commentary="OpenSSL buffer overflow, remotely exploitable.",
            environment_commentary="Hosts are directly internet-facing.",
            operator_guidance="Apply patch 3.0.2 immediately.",
            signal_analysis_source="model",
            signal_assessment_error=None,
            policy=policy,
        )
        # Facts checks
        assert "Base severity is HIGH" in facts
        assert "CVSS is 8.1" in facts
        assert "KEV listed." in facts
        assert "EPSS percentile is 92.00" in facts
        assert "Attack vector is network" in facts
        assert "Privileges required are none" in facts
        assert "User interaction is none" in facts
        assert "internet facing" in facts
        assert "Vendor fix version is 3.0.2" in facts
        assert "Alternate fix versions" in facts
        assert "urgency high" in facts
        assert "fix state fix available" in facts
        assert "Backport expected." in facts
        assert "nvd" in facts
        assert "GHSA-1234" in facts

        # Inference
        assert "OpenSSL buffer overflow" in inference
        assert "Final priority is Immediate" in inference
        assert "KEV listed" in inference  # from overrides
        assert "SLA is 48 hours" in inference

        # Recommended action
        assert recommended == "Apply patch 3.0.2 immediately."

        # Uncertainty -- no error, model source, patch exists, host description present
        assert "No major uncertainty" in uncertainty

    def test_no_fixed_version(self, policy):
        candidate = _make_candidate(
            fixed_version=None,
            advisory_current_versions=["3.0.1", "3.0.0"],
            host_description="",
        )
        breakdown = ScoreBreakdown(
            exposure="unknown",
            severity_level="medium",
            patch_available=False,
            mitigating_control_present=True,
            detection_present=True,
            poc_available=False,
            epss_component=5,
            kev_component=0,
            exposure_component=5,
            exploitability_component=0,
            severity_component=10,
            control_gap_component=0,
            weighted_score=20,
            base_category="Planned",
            final_category="Planned",
            hard_minimum_category="Planned",
            overrides=[],
            epss_percentile_100=0.0,
        )
        facts, inference, _, uncertainty = build_report_sections(
            candidate,
            breakdown,
            cve_commentary="Minor issue.",
            environment_commentary="Internal.",
            operator_guidance="Monitor only.",
            signal_analysis_source="model",
            signal_assessment_error=None,
            policy=policy,
        )
        assert "No fixed version" in facts
        assert "Current repo versions still marked vulnerable" in facts
        assert "3.0.1" in facts
        assert "No policy override changed" in inference
        assert "No published fix" in uncertainty
        assert "Host context is limited" in uncertainty

    def test_cached_source_uncertainty(self, policy):
        candidate = _make_candidate()
        breakdown = ScoreBreakdown(
            exposure="internet_facing",
            severity_level="high",
            patch_available=True,
            mitigating_control_present=False,
            detection_present=False,
            poc_available=True,
            epss_component=10,
            kev_component=0,
            exposure_component=15,
            exploitability_component=13,
            severity_component=15,
            control_gap_component=10,
            weighted_score=63,
            base_category="High",
            final_category="High",
            hard_minimum_category="Planned",
            overrides=[],
            epss_percentile_100=50.0,
        )
        _, _, _, uncertainty = build_report_sections(
            candidate,
            breakdown,
            cve_commentary="",
            environment_commentary="",
            operator_guidance="",
            signal_analysis_source="cache",
            signal_assessment_error=None,
            policy=policy,
        )
        assert "cached model assessment" in uncertainty

    def test_signal_assessment_error_in_uncertainty(self, policy):
        candidate = _make_candidate()
        breakdown = ScoreBreakdown(
            exposure="internet_facing",
            severity_level="high",
            patch_available=True,
            mitigating_control_present=False,
            detection_present=False,
            poc_available=True,
            epss_component=10,
            kev_component=0,
            exposure_component=15,
            exploitability_component=13,
            severity_component=15,
            control_gap_component=10,
            weighted_score=63,
            base_category="High",
            final_category="High",
            hard_minimum_category="Planned",
            overrides=[],
            epss_percentile_100=50.0,
        )
        _, _, _, uncertainty = build_report_sections(
            candidate,
            breakdown,
            cve_commentary="",
            environment_commentary="",
            operator_guidance="",
            signal_analysis_source="model",
            signal_assessment_error="LLM parse error",
            policy=policy,
        )
        assert "LLM parse error" in uncertainty

    def test_unknown_exposure_text(self, policy):
        candidate = _make_candidate()
        breakdown = ScoreBreakdown(
            exposure="unknown",
            severity_level="medium",
            patch_available=True,
            mitigating_control_present=True,
            detection_present=True,
            poc_available=False,
            epss_component=5,
            kev_component=0,
            exposure_component=5,
            exploitability_component=0,
            severity_component=10,
            control_gap_component=3,
            weighted_score=23,
            base_category="Planned",
            final_category="Planned",
            hard_minimum_category="Planned",
            overrides=[],
            epss_percentile_100=5.0,
        )
        facts, _, _, _ = build_report_sections(
            candidate,
            breakdown,
            cve_commentary="",
            environment_commentary="",
            operator_guidance="",
            signal_analysis_source="model",
            signal_assessment_error=None,
            policy=policy,
        )
        assert "Host exposure was not established" in facts

    def test_not_kev_listed_text(self, policy):
        candidate = _make_candidate(kev_listed=False)
        breakdown = ScoreBreakdown(
            exposure="internet_facing",
            severity_level="high",
            patch_available=True,
            mitigating_control_present=False,
            detection_present=False,
            poc_available=False,
            epss_component=10,
            kev_component=0,
            exposure_component=15,
            exploitability_component=8,
            severity_component=15,
            control_gap_component=10,
            weighted_score=58,
            base_category="High",
            final_category="High",
            hard_minimum_category="Planned",
            overrides=[],
            epss_percentile_100=50.0,
        )
        facts, _, _, _ = build_report_sections(
            candidate,
            breakdown,
            cve_commentary="",
            environment_commentary="",
            operator_guidance="",
            signal_analysis_source="model",
            signal_assessment_error=None,
            policy=policy,
        )
        assert "Not listed in KEV" in facts

    def test_no_base_severity_or_cvss(self, policy):
        candidate = _make_candidate(base_severity=None, cvss_score=None)
        breakdown = ScoreBreakdown(
            exposure="internet_facing",
            severity_level="unknown",
            patch_available=True,
            mitigating_control_present=False,
            detection_present=False,
            poc_available=False,
            epss_component=0,
            kev_component=0,
            exposure_component=15,
            exploitability_component=0,
            severity_component=0,
            control_gap_component=10,
            weighted_score=25,
            base_category="Moderate",
            final_category="Moderate",
            hard_minimum_category="Planned",
            overrides=[],
            epss_percentile_100=0.0,
        )
        facts, _, _, _ = build_report_sections(
            candidate,
            breakdown,
            cve_commentary="",
            environment_commentary="",
            operator_guidance="",
            signal_analysis_source="model",
            signal_assessment_error=None,
            policy=policy,
        )
        # Neither "Base severity" nor "CVSS is" should appear
        assert "Base severity" not in facts
        assert "CVSS is" not in facts


# ---------------------------------------------------------------------------
# Edge cases: missing fields in candidates
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_candidate_with_all_none_optional_fields(self, policy):
        candidate = _make_candidate(
            fixed_version=None,
            host_description="",
            cve_description="",
            base_severity=None,
            cvss_score=None,
            attack_vector=None,
            privileges_required=None,
            user_interaction=None,
            epss_score=None,
            epss_percentile=None,
            kev_listed=False,
            evidence_sources=[],
            advisory_ids=[],
        )
        signal = _make_signal_assessment(
            exposure="unknown",
            poc_available=False,
            mitigating_control_present=True,
            detection_present=True,
        )
        breakdown = calculate_score_breakdown(candidate, signal, policy)
        assert breakdown.epss_component == 0
        assert breakdown.kev_component == 0
        assert breakdown.exploitability_component == 0
        assert breakdown.severity_level == "unknown"
        assert breakdown.severity_component == 0
        assert breakdown.patch_available is False
        assert breakdown.final_category in policy.category_order

    def test_epss_percentile_exactly_1(self, policy):
        """EPSS percentile of 1.0 should normalize to 100."""
        candidate = _make_candidate(epss_percentile=1.0, epss_score=0.5)
        signal = _make_signal_assessment()
        breakdown = calculate_score_breakdown(candidate, signal, policy)
        # 100.0 / 100 * 20 = 20
        assert breakdown.epss_component == 20

    def test_epss_percentile_zero(self, policy):
        candidate = _make_candidate(epss_percentile=0.0, epss_score=0.0)
        signal = _make_signal_assessment()
        breakdown = calculate_score_breakdown(candidate, signal, policy)
        assert breakdown.epss_component == 0

    def test_negative_epss_clamped_to_zero(self, policy):
        """Negative percentile should be clamped to 0."""
        candidate = _make_candidate(epss_percentile=-5.0, epss_score=None)
        signal = _make_signal_assessment()
        breakdown = calculate_score_breakdown(candidate, signal, policy)
        assert breakdown.epss_component == 0

    def test_very_high_epss_clamped_to_max_points(self, policy):
        """Percentile above 100 should be clamped."""
        candidate = _make_candidate(epss_percentile=150.0, epss_score=None)
        signal = _make_signal_assessment()
        breakdown = calculate_score_breakdown(candidate, signal, policy)
        assert breakdown.epss_component == 20  # max points
