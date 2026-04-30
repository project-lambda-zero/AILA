"""Unit tests for scoring policy pure functions.

All tests are in-memory only — no DB, no network, no mocking of scoring functions.
"""
from __future__ import annotations

import pytest

from aila.modules.vulnerability.agents.scoring.config import ScoringPolicyConfig
from aila.modules.vulnerability.agents.scoring.models import (
    ScoreBreakdown,
    ScoringCandidate,
)
from aila.modules.vulnerability.contracts import SignalAssessment
from aila.modules.vulnerability.agents.scoring.policy import (
    apply_overrides,
    bump_category,
    calculate_score_breakdown,
    category_from_score,
    control_gap_points,
    exploitability_points,
    normalize_percentile,
    raise_minimum,
    severity_profile,
)

# ---------------------------------------------------------------------------
# Inline default policy — mirrors scoring_policy.default.json exactly.
# No file I/O in tests.
# ---------------------------------------------------------------------------

POLICY_DATA = {
    "policy_id": "default",
    "category_order": ["Planned", "Moderate", "High", "Immediate"],
    "category_sla": {
        "Immediate": "same day / 24-72h depending on asset class",
        "High": "this sprint",
        "Moderate": "scheduled remediation",
        "Planned": "backlog with review date",
    },
    "base_scoring_notes": [],
    "exposure_points": {
        "unknown": 0,
        "internet_facing": 15,
        "partner_exposed": 10,
        "internal_flat_network": 8,
        "internal_segmented": 4,
        "isolated": 0,
    },
    "category_thresholds": {
        "Moderate": 30,
        "High": 50,
        "Immediate": 75,
    },
    "weights": {
        "epss_max_points": 35,
        "kev_listed_points": 30,
        "severity_points": {
            "critical": 5,
            "high": 4,
            "medium": 2,
            "low": 1,
            "unknown": 0,
        },
        "cvss_bands": {
            "critical_min": 9.0,
            "high_min": 7.0,
            "medium_min": 4.0,
            "low_min": 0.1,
        },
        "exploitability": {
            "attack_vector_network": 4,
            "attack_vector_adjacent": 2,
            "privileges_none": 3,
            "privileges_low": 1,
            "user_interaction_none": 2,
            "poc_available": 1,
            "max_points": 10,
        },
        "control_gap": {
            "patch_available": 2,
            "missing_mitigating_control": 2,
            "missing_detection": 1,
        },
    },
    "overrides": {
        "kev_minimum_category": "Immediate",
        "epss_escalation": {
            "percentile_threshold": 99.0,
            "required_exposure": "internet_facing",
            "required_privileges": ["none", "low"],
            "default_minimum_category": "High",
            "network_severity_levels": ["high", "critical"],
            "network_minimum_category": "Immediate",
        },
        "no_fix_escalation": {
            "required_exposure": "internet_facing",
            "required_attack_vector": "network",
            "required_severity_level": "critical",
            "require_no_mitigating_control": True,
            "category_delta": 1,
        },
        "internal_downgrade": {
            "allowed_exposures": ["internal_segmented", "isolated"],
            "required_attack_vector": "local",
            "required_privileges": "high",
            "exclude_kev_listed": True,
            "category_delta": -1,
        },
    },
}

POLICY = ScoringPolicyConfig.model_validate(POLICY_DATA)

CATEGORY_ORDER = POLICY.category_order
CATEGORY_RANK = POLICY.category_rank


# ---------------------------------------------------------------------------
# Minimal factories
# ---------------------------------------------------------------------------


def _candidate(**overrides) -> ScoringCandidate:
    defaults = dict(
        system_id=1,
        system_name="srv",
        host="host.example.com",
        distribution="ubuntu",
        package_name="libssl",
        installed_version="3.0.1",
        cve_id="CVE-2024-0001",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
    )
    defaults.update(overrides)
    return ScoringCandidate(**defaults)


def _signal(**overrides) -> SignalAssessment:
    defaults = dict(
        exposure="unknown",
        mitigating_control_present=False,
        detection_present=False,
        poc_available=False,
        cve_detail_commentary="",
        environment_commentary="",
        operator_guidance="",
    )
    defaults.update(overrides)
    return SignalAssessment(**defaults)


# ---------------------------------------------------------------------------
# normalize_percentile
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "percentile, epss_score, expected",
    [
        (0.95, None, 95.0),   # 0-1 range scaled to 0-100
        (99.5, None, 99.5),   # already >1, pass-through
        (None, 0.87, 87.0),   # falls back to epss_score * 100
        (None, None, 0.0),    # both absent
        (0.0, None, 0.0),     # zero percentile
        (1.0, None, 100.0),   # boundary: exactly 1 → scaled to 100
        (1.01, None, 1.01),   # just above 1 → pass-through (> 1 not <= 1)
    ],
)
def test_normalize_percentile(percentile, epss_score, expected):
    result = normalize_percentile(percentile, epss_score)
    assert result == pytest.approx(expected, abs=1e-6)


# ---------------------------------------------------------------------------
# severity_profile
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cvss_score, base_severity, expected_level, expected_points",
    [
        (9.5, None, "critical", 5),
        (9.0, None, "critical", 5),     # exact critical_min boundary
        (8.9, None, "high", 4),
        (7.0, None, "high", 4),         # exact high_min boundary
        (6.9, None, "medium", 2),
        (4.0, None, "medium", 2),       # exact medium_min boundary
        (3.9, None, "low", 1),
        (0.1, None, "low", 1),          # exact low_min boundary
        (0.09, None, "unknown", 0),     # just below low_min → unknown
        (None, "CRITICAL", "critical", 5),   # string fallback, case-insensitive
        (None, "HIGH", "high", 4),
        (None, "Medium", "medium", 2),
        (None, "low", "low", 1),
        (None, "unknown_severity", "unknown", 0),  # unrecognized string
        (None, None, "unknown", 0),
    ],
)
def test_severity_profile(cvss_score, base_severity, expected_level, expected_points):
    level, points = severity_profile(cvss_score, base_severity, POLICY)
    assert level == expected_level
    assert points == expected_points


# ---------------------------------------------------------------------------
# category_from_score
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score, expected_category",
    [
        (0, "Planned"),
        (29, "Planned"),
        (30, "Moderate"),    # exact Moderate threshold
        (49, "Moderate"),
        (50, "High"),        # exact High threshold
        (74, "High"),
        (75, "Immediate"),   # exact Immediate threshold
        (100, "Immediate"),
    ],
)
def test_category_from_score(score, expected_category):
    assert category_from_score(score, POLICY) == expected_category


# ---------------------------------------------------------------------------
# exploitability_points
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "attack_vector, privileges_required, user_interaction, poc_available, expected",
    [
        ("network", "none", "none", False, 9),    # 4+3+2
        ("network", "none", "none", True, 10),    # 4+3+2+1 = 10 (capped at max)
        ("adjacent", "low", "none", False, 5),    # 2+1+2
        (None, None, None, False, 0),             # all missing
        ("NETWORK", "NONE", "NONE", False, 9),    # case-insensitive
        ("network", "low", "required", False, 5), # 4+1+0
        ("adjacent", "none", "none", True, 8),    # 2+3+2+1
        ("local", "none", "none", False, 5),      # 0+3+2 (local not in network/adjacent)
    ],
)
def test_exploitability_points(attack_vector, privileges_required, user_interaction, poc_available, expected):
    result = exploitability_points(attack_vector, privileges_required, user_interaction, poc_available, POLICY)
    assert result == expected


# ---------------------------------------------------------------------------
# control_gap_points
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "patch_available, mitigating_control_present, detection_present, expected",
    [
        (True, False, False, 5),    # 2+2+1
        (False, True, True, 0),     # 0+0+0
        (True, True, True, 2),      # 2+0+0
        (False, False, False, 3),   # 0+2+1
        (True, False, True, 4),     # 2+2+0
        (False, True, False, 1),    # 0+0+1
    ],
)
def test_control_gap_points(patch_available, mitigating_control_present, detection_present, expected):
    result = control_gap_points(patch_available, mitigating_control_present, detection_present, POLICY)
    assert result == expected


# ---------------------------------------------------------------------------
# raise_minimum
# ---------------------------------------------------------------------------


def test_raise_minimum_raises_when_below():
    result = raise_minimum("Planned", "High", CATEGORY_RANK)
    assert result == "High"


def test_raise_minimum_no_change_when_already_above():
    result = raise_minimum("High", "Moderate", CATEGORY_RANK)
    assert result == "High"


def test_raise_minimum_no_change_when_equal():
    result = raise_minimum("High", "High", CATEGORY_RANK)
    assert result == "High"


def test_raise_minimum_planned_to_immediate():
    result = raise_minimum("Planned", "Immediate", CATEGORY_RANK)
    assert result == "Immediate"


# ---------------------------------------------------------------------------
# bump_category
# ---------------------------------------------------------------------------


def test_bump_category_up_one():
    result = bump_category("Moderate", 1, CATEGORY_ORDER, CATEGORY_RANK)
    assert result == "High"


def test_bump_category_clamped_at_top():
    result = bump_category("Immediate", 1, CATEGORY_ORDER, CATEGORY_RANK)
    assert result == "Immediate"


def test_bump_category_clamped_at_bottom():
    result = bump_category("Planned", -1, CATEGORY_ORDER, CATEGORY_RANK)
    assert result == "Planned"


def test_bump_category_down_one():
    result = bump_category("High", -1, CATEGORY_ORDER, CATEGORY_RANK)
    assert result == "Moderate"


# ---------------------------------------------------------------------------
# apply_overrides: KEV
# ---------------------------------------------------------------------------


def test_apply_overrides_kev_raises_to_immediate():
    candidate = _candidate(kev_listed=True)
    final_category, overrides, hard_minimum = apply_overrides(
        base_category="Planned",
        candidate=candidate,
        exposure="unknown",
        severity_level="low",
        epss_percentile_100=0.0,
        mitigating_control_present=False,
        policy=POLICY,
    )
    assert final_category == "Immediate"
    assert hard_minimum == "Immediate"
    assert any("KEV" in o for o in overrides)


def test_apply_overrides_kev_listed_override_message():
    candidate = _candidate(kev_listed=True)
    _, overrides, _ = apply_overrides(
        base_category="Planned",
        candidate=candidate,
        exposure="unknown",
        severity_level="medium",
        epss_percentile_100=0.0,
        mitigating_control_present=False,
        policy=POLICY,
    )
    assert any("Immediate" in o for o in overrides)


def test_apply_overrides_no_kev_no_change():
    candidate = _candidate(kev_listed=False)
    final_category, overrides, hard_minimum = apply_overrides(
        base_category="Moderate",
        candidate=candidate,
        exposure="unknown",
        severity_level="medium",
        epss_percentile_100=0.0,
        mitigating_control_present=False,
        policy=POLICY,
    )
    assert final_category == "Moderate"
    assert hard_minimum == "Planned"
    assert not any("KEV" in o for o in overrides)


# ---------------------------------------------------------------------------
# apply_overrides: EPSS escalation
# ---------------------------------------------------------------------------


def test_apply_overrides_epss_network_critical_raises_to_immediate():
    candidate = _candidate(attack_vector="network", privileges_required="none")
    final_category, overrides, _ = apply_overrides(
        base_category="Moderate",
        candidate=candidate,
        exposure="internet_facing",
        severity_level="high",
        epss_percentile_100=99.5,
        mitigating_control_present=False,
        policy=POLICY,
    )
    assert final_category == "Immediate"
    assert any("EPSS" in o for o in overrides)


def test_apply_overrides_epss_non_network_high_severity_raises_to_default_minimum():
    # severity="low" does not qualify for network_minimum → uses default_minimum "High"
    candidate = _candidate(attack_vector="network", privileges_required="none")
    final_category, overrides, _ = apply_overrides(
        base_category="Planned",
        candidate=candidate,
        exposure="internet_facing",
        severity_level="low",
        epss_percentile_100=99.5,
        mitigating_control_present=False,
        policy=POLICY,
    )
    assert final_category == "High"
    assert any("EPSS" in o for o in overrides)


def test_apply_overrides_epss_below_threshold_no_override():
    candidate = _candidate(attack_vector="network", privileges_required="none")
    final_category, overrides, _ = apply_overrides(
        base_category="Moderate",
        candidate=candidate,
        exposure="internet_facing",
        severity_level="high",
        epss_percentile_100=98.0,   # below threshold of 99.0
        mitigating_control_present=False,
        policy=POLICY,
    )
    assert final_category == "Moderate"
    assert not any("EPSS" in o for o in overrides)


def test_apply_overrides_epss_wrong_exposure_no_override():
    candidate = _candidate(attack_vector="network", privileges_required="none")
    final_category, overrides, _ = apply_overrides(
        base_category="Moderate",
        candidate=candidate,
        exposure="internal_segmented",   # not internet_facing
        severity_level="high",
        epss_percentile_100=99.5,
        mitigating_control_present=False,
        policy=POLICY,
    )
    assert not any("EPSS" in o for o in overrides)


# ---------------------------------------------------------------------------
# apply_overrides: no_fix_escalation
# ---------------------------------------------------------------------------


def test_apply_overrides_no_fix_escalation_fires():
    candidate = _candidate(
        fixed_version=None,
        attack_vector="network",
        privileges_required="none",
    )
    final_category, overrides, _ = apply_overrides(
        base_category="High",
        candidate=candidate,
        exposure="internet_facing",
        severity_level="critical",
        epss_percentile_100=0.0,
        mitigating_control_present=False,
        policy=POLICY,
    )
    assert final_category == "Immediate"   # bumped by 1
    assert any("No fix" in o for o in overrides)


def test_apply_overrides_no_fix_not_fired_when_fix_available():
    candidate = _candidate(
        fixed_version="1.0.2",
        attack_vector="network",
        privileges_required="none",
    )
    final_category, overrides, _ = apply_overrides(
        base_category="High",
        candidate=candidate,
        exposure="internet_facing",
        severity_level="critical",
        epss_percentile_100=0.0,
        mitigating_control_present=False,
        policy=POLICY,
    )
    assert final_category == "High"   # no bump
    assert not any("No fix" in o for o in overrides)


def test_apply_overrides_no_fix_not_fired_wrong_exposure():
    candidate = _candidate(fixed_version=None, attack_vector="network")
    final_category, overrides, _ = apply_overrides(
        base_category="High",
        candidate=candidate,
        exposure="internal_segmented",   # wrong exposure
        severity_level="critical",
        epss_percentile_100=0.0,
        mitigating_control_present=False,
        policy=POLICY,
    )
    assert not any("No fix" in o for o in overrides)


def test_apply_overrides_no_fix_not_fired_with_mitigating_control():
    candidate = _candidate(fixed_version=None, attack_vector="network")
    final_category, overrides, _ = apply_overrides(
        base_category="High",
        candidate=candidate,
        exposure="internet_facing",
        severity_level="critical",
        epss_percentile_100=0.0,
        mitigating_control_present=True,  # control present blocks escalation
        policy=POLICY,
    )
    assert not any("No fix" in o for o in overrides)


# ---------------------------------------------------------------------------
# apply_overrides: internal_downgrade
# ---------------------------------------------------------------------------


def test_apply_overrides_internal_downgrade_fires():
    candidate = _candidate(
        kev_listed=False,
        attack_vector="local",
        privileges_required="high",
    )
    final_category, overrides, _ = apply_overrides(
        base_category="High",
        candidate=candidate,
        exposure="internal_segmented",
        severity_level="medium",
        epss_percentile_100=0.0,
        mitigating_control_present=False,
        policy=POLICY,
    )
    assert final_category == "Moderate"  # bumped by -1
    assert any("Internal" in o for o in overrides)


def test_apply_overrides_internal_downgrade_excluded_when_kev():
    candidate = _candidate(
        kev_listed=True,
        attack_vector="local",
        privileges_required="high",
    )
    _, overrides, _ = apply_overrides(
        base_category="High",
        candidate=candidate,
        exposure="internal_segmented",
        severity_level="medium",
        epss_percentile_100=0.0,
        mitigating_control_present=False,
        policy=POLICY,
    )
    # KEV listed → exclude_kev_listed=True → no internal downgrade
    assert not any("Internal" in o for o in overrides)


def test_apply_overrides_internal_downgrade_not_fired_wrong_exposure():
    candidate = _candidate(kev_listed=False, attack_vector="local", privileges_required="high")
    final_category, overrides, _ = apply_overrides(
        base_category="High",
        candidate=candidate,
        exposure="internet_facing",  # not in allowed_exposures
        severity_level="medium",
        epss_percentile_100=0.0,
        mitigating_control_present=False,
        policy=POLICY,
    )
    assert not any("Internal" in o for o in overrides)


def test_apply_overrides_internal_downgrade_isolated():
    candidate = _candidate(kev_listed=False, attack_vector="local", privileges_required="high")
    final_category, overrides, _ = apply_overrides(
        base_category="Moderate",
        candidate=candidate,
        exposure="isolated",  # also in allowed_exposures
        severity_level="low",
        epss_percentile_100=0.0,
        mitigating_control_present=False,
        policy=POLICY,
    )
    assert final_category == "Planned"
    assert any("Internal" in o for o in overrides)


# ---------------------------------------------------------------------------
# calculate_score_breakdown — integration tests
# ---------------------------------------------------------------------------


def test_calculate_score_breakdown_high_risk():
    """Internet-facing, network, no privs, KEV=True, critical CVSS → Immediate.

    KEV override raises final_category to Immediate regardless of weighted_score.
    weighted_score reflects raw point total (no EPSS → ~63), overrides lift the category.
    """
    candidate = _candidate(
        kev_listed=True,
        cvss_score=9.5,
        attack_vector="network",
        privileges_required="none",
        user_interaction="none",
    )
    signal = _signal(
        exposure="internet_facing",
        poc_available=True,
    )
    bd = calculate_score_breakdown(candidate, signal, POLICY)
    assert bd.final_category == "Immediate"
    # KEV override fires; weighted_score may be below 75 because EPSS=0.
    assert bd.kev_component == 30
    assert bd.weighted_score >= 30  # at minimum KEV+severity+exploitability


def test_calculate_score_breakdown_low_risk():
    """Isolated, local, high privs, required interaction, no KEV, low CVSS → Planned/Moderate."""
    candidate = _candidate(
        kev_listed=False,
        cvss_score=3.0,
        attack_vector="local",
        privileges_required="high",
        user_interaction="required",
    )
    signal = _signal(
        exposure="isolated",
        mitigating_control_present=True,
        detection_present=True,
        poc_available=False,
    )
    bd = calculate_score_breakdown(candidate, signal, POLICY)
    assert bd.final_category in ("Planned", "Moderate")
    assert bd.weighted_score <= 40


def test_calculate_score_breakdown_score_capped_at_100():
    """All high-value components combined → weighted_score == 100 (capped)."""
    candidate = _candidate(
        kev_listed=True,           # +30
        cvss_score=9.5,            # severity critical → +5
        attack_vector="network",   # +4
        privileges_required="none",# +3
        user_interaction="none",   # +2
        epss_percentile=0.99,      # → 99.0 → epss_component ~ 35
        fixed_version="1.0",       # patch_available → +2 control gap
    )
    signal = _signal(
        exposure="internet_facing",  # +15
        poc_available=True,          # +1 (capped at max_points=10 for exploitability)
        mitigating_control_present=False,  # +2 control gap
        detection_present=False,           # +1 control gap
    )
    bd = calculate_score_breakdown(candidate, signal, POLICY)
    assert bd.weighted_score == 100


def test_calculate_score_breakdown_returns_score_breakdown_instance():
    candidate = _candidate()
    signal = _signal()
    bd = calculate_score_breakdown(candidate, signal, POLICY)
    assert isinstance(bd, ScoreBreakdown)


def test_calculate_score_breakdown_patch_available_from_fixed_version():
    candidate = _candidate(fixed_version="2.0.0")
    signal = _signal()
    bd = calculate_score_breakdown(candidate, signal, POLICY)
    assert bd.patch_available is True


def test_calculate_score_breakdown_no_fix():
    candidate = _candidate(fixed_version=None)
    signal = _signal()
    bd = calculate_score_breakdown(candidate, signal, POLICY)
    assert bd.patch_available is False


def test_calculate_score_breakdown_epss_percentile_stored_rounded():
    candidate = _candidate(epss_percentile=0.9567)
    signal = _signal()
    bd = calculate_score_breakdown(candidate, signal, POLICY)
    # epss_percentile_100 = 95.67 → rounded to 2 decimal places
    assert bd.epss_percentile_100 == pytest.approx(95.67, abs=0.01)
