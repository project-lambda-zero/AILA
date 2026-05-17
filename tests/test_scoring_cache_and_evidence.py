"""Tests for OPT-02/OPT-03/OPT-04: category_rank caching and direct field access in build_scoring_evidence."""
from __future__ import annotations

POLICY_DATA = {
    "policy_id": "default",
    "category_order": ["Planned", "Moderate", "High", "Immediate"],
    "category_sla": {"Planned": "90d", "Moderate": "30d", "High": "7d", "Immediate": "24h"},
    "category_thresholds": {"Moderate": 20, "High": 50, "Immediate": 75},
    "exposure_points": {"internet_facing": 20},
    "weights": {
        "epss_max_points": 20,
        "kev_listed_points": 30,
        "severity_points": {"critical": 25, "high": 18, "medium": 10, "low": 5, "unknown": 0},
        "cvss_bands": {},
        "exploitability": {
            "attack_vector_network": 8,
            "attack_vector_adjacent": 4,
            "privileges_none": 5,
            "privileges_low": 2,
            "user_interaction_none": 3,
            "poc_available": 10,
            "max_points": 20,
        },
        "control_gap": {
            "patch_available": 5,
            "missing_mitigating_control": 8,
            "missing_detection": 5,
        },
    },
    "overrides": {
        "kev_minimum_category": "High",
        "epss_escalation": {
            "percentile_threshold": 90,
            "required_exposure": "internet_facing",
            "required_privileges": ["none"],
            "default_minimum_category": "High",
            "network_severity_levels": ["critical", "high"],
            "network_minimum_category": "Immediate",
        },
        "no_fix_escalation": {
            "required_exposure": "internet_facing",
            "required_attack_vector": "network",
            "required_severity_level": "critical",
        },
        "internal_downgrade": {
            "allowed_exposures": ["internal_segmented", "isolated"],
            "required_attack_vector": "local",
            "required_privileges": "high",
        },
    },
}


def test_category_rank_returns_same_dict_object():
    """category_rank must return the same dict object on repeated access (cached)."""
    from aila.modules.vulnerability.agents.scoring.config import ScoringPolicyConfig

    policy = ScoringPolicyConfig.model_validate(POLICY_DATA)
    r1 = policy.category_rank
    r2 = policy.category_rank
    assert r1 is r2, "category_rank must return the same dict object on repeat calls"


def test_category_rank_correct_values():
    from aila.modules.vulnerability.agents.scoring.config import ScoringPolicyConfig

    policy = ScoringPolicyConfig.model_validate(POLICY_DATA)
    assert policy.category_rank == {"Planned": 0, "Moderate": 1, "High": 2, "Immediate": 3}


def test_build_scoring_evidence_no_model_dump():
    """build_scoring_evidence must work and produce ScoringEvidence without using model_dump."""
    from aila.modules.vulnerability.agents.scoring.models import ScoreBreakdown, ScoringCandidate
    from aila.modules.vulnerability.agents.scoring.policy import build_scoring_evidence
    from aila.modules.vulnerability.contracts import ScoringEvidence

    c = ScoringCandidate(
        system_id=1,
        system_name="server",
        host="host.example.com",
        distribution="ubuntu",
        package_name="libssl",
        installed_version="3.0.1",
        cve_id="CVE-2024-0001",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
    )
    b = ScoreBreakdown(
        exposure="unknown",
        severity_level="high",
        patch_available=True,
        mitigating_control_present=False,
        detection_present=False,
        poc_available=False,
        epss_component=5,
        kev_component=0,
        exposure_component=10,
        exploitability_component=8,
        severity_component=15,
        control_gap_component=3,
        weighted_score=41,
        base_category="High",
        final_category="High",
        hard_minimum_category="Planned",
    )
    evidence = build_scoring_evidence(
        c,
        b,
        agent_review_enabled=True,
        signal_analysis_source="model",
        signal_assessment_error=None,
        cve_commentary="test commentary",
        environment_commentary="env commentary",
        operator_guidance="apply patch",
    )
    assert isinstance(evidence, ScoringEvidence)
    assert evidence.final_category == "High"
    assert evidence.weighted_score == 41
    assert evidence.patch_available is True
    assert evidence.exposure == "unknown"


def test_build_scoring_evidence_field_values_propagated():
    """All candidate and breakdown fields must flow through to ScoringEvidence correctly."""
    from aila.modules.vulnerability.agents.scoring.models import ScoreBreakdown, ScoringCandidate
    from aila.modules.vulnerability.agents.scoring.policy import build_scoring_evidence

    c = ScoringCandidate(
        system_id=2,
        system_name="web01",
        host="web01.lan",
        distribution="debian",
        package_name="curl",
        installed_version="7.68.0",
        cve_id="CVE-2024-0002",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-0002",
        advisory_source_modes=["live"],
        advisory_last_synced_at=["2024-01-01T00:00:00Z"],
        evidence_sources=["osv"],
        advisory_ids=["DSA-1234"],
        advisory_severities=["high"],
        advisory_types=["security"],
        vendor_statuses=["affected"],
        vendor_status_notes=["critical note"],
        vendor_urgencies=["high"],
        vendor_fix_states=["pending"],
        vendor_support_channels=["security"],
        intel_source_mode="cache",
        intel_last_synced_at="2024-01-01T00:00:00Z",
        fixed_version_source="advisory",
        fixed_version_note=None,
        alternate_fixed_versions=["7.68.1"],
        advisory_current_versions=["7.68.0-1"],
    )
    b = ScoreBreakdown(
        exposure="internet_facing",
        severity_level="critical",
        patch_available=True,
        mitigating_control_present=False,
        detection_present=True,
        poc_available=True,
        epss_component=15,
        kev_component=30,
        exposure_component=20,
        exploitability_component=20,
        severity_component=25,
        control_gap_component=5,
        weighted_score=100,
        base_category="Immediate",
        final_category="Immediate",
        hard_minimum_category="High",
        overrides=["KEV listed: minimum category raised to High."],
        epss_percentile_100=92.5,
    )
    evidence = build_scoring_evidence(
        c,
        b,
        agent_review_enabled=False,
        signal_analysis_source="cache",
        signal_assessment_error=None,
        cve_commentary="remote code execution",
        environment_commentary="internet-facing server",
        operator_guidance="patch immediately",
    )
    assert evidence.exposure == "internet_facing"
    assert evidence.overrides == ["KEV listed: minimum category raised to High."]
    assert evidence.epss_percentile_100 == 92.5
    assert evidence.evidence_sources == ["osv"]
    assert evidence.advisory_ids == ["DSA-1234"]
    assert evidence.advisory_source_modes == ["live"]
    assert evidence.intel_source_mode == "cache"
    assert evidence.signal_analysis_confidence == "cached_review"
    assert evidence.signal_analysis_source == "cache"
