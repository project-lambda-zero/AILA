"""Tests for OPT-01: ScoringCandidate and ScoreBreakdown as dataclasses."""
from __future__ import annotations


def test_scoring_candidate_list_fields_are_independent():
    """Each ScoringCandidate instance must have independent list defaults."""
    from aila.modules.vulnerability.agents.scoring.models import ScoringCandidate

    a = ScoringCandidate(
        system_id=1, system_name="s", host="h", distribution="d",
        package_name="p", installed_version="1.0", cve_id="CVE-1", nvd_url="u",
    )
    b = ScoringCandidate(
        system_id=2, system_name="s2", host="h2", distribution="d2",
        package_name="p2", installed_version="2.0", cve_id="CVE-2", nvd_url="u2",
    )
    a.intel_notes.append("note")
    assert b.intel_notes == [], "List defaults must not be shared between instances"


def test_score_breakdown_list_fields_independent():
    """Each ScoreBreakdown must have independent list defaults."""
    from aila.modules.vulnerability.agents.scoring.models import ScoreBreakdown

    kwargs = dict(
        exposure="unknown", severity_level="high", patch_available=True,
        mitigating_control_present=False, detection_present=False, poc_available=False,
        epss_component=0, kev_component=0, exposure_component=0, exploitability_component=0,
        severity_component=0, control_gap_component=0, weighted_score=0,
        base_category="Planned", final_category="Planned", hard_minimum_category="Planned",
    )
    a = ScoreBreakdown(**kwargs)
    b = ScoreBreakdown(**kwargs)
    a.overrides.append("x")
    assert b.overrides == [], "List defaults must not be shared between instances"


