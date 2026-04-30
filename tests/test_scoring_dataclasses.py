"""Tests for OPT-01: ScoringCandidate and ScoreBreakdown as dataclasses."""
from __future__ import annotations

import dataclasses

import pydantic
import pytest


def test_scoring_candidate_is_dataclass():
    from aila.modules.vulnerability.agents.scoring.models import ScoringCandidate

    assert dataclasses.is_dataclass(ScoringCandidate), "ScoringCandidate must be a dataclass"


def test_score_breakdown_is_dataclass():
    from aila.modules.vulnerability.agents.scoring.models import ScoreBreakdown

    assert dataclasses.is_dataclass(ScoreBreakdown), "ScoreBreakdown must be a dataclass"


def test_signal_assessment_stays_pydantic():
    from aila.modules.vulnerability.contracts import SignalAssessment

    assert issubclass(SignalAssessment, pydantic.BaseModel), "SignalAssessment must remain a Pydantic BaseModel"


def test_scoring_candidate_defaults():
    from aila.modules.vulnerability.agents.scoring.models import ScoringCandidate

    c = ScoringCandidate(
        system_id=1,
        system_name="srv",
        host="host.example.com",
        distribution="ubuntu",
        package_name="libssl",
        installed_version="3.0.1",
        cve_id="CVE-2024-0001",
        nvd_url="https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
    )
    assert c.kev_listed is False
    assert c.intel_notes == []
    assert c.evidence_sources == []
    assert c.advisory_ids == []
    assert c.fixed_version_source == "advisory"
    assert c.fixed_version is None
    assert c.host_description == ""


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


def test_score_breakdown_defaults():
    from aila.modules.vulnerability.agents.scoring.models import ScoreBreakdown

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
    assert b.overrides == []
    assert b.epss_percentile_100 == 0.0


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


def test_no_pydantic_on_scoring_candidate():
    """ScoringCandidate should NOT be a Pydantic model."""
    from aila.modules.vulnerability.agents.scoring.models import ScoringCandidate

    assert not issubclass(ScoringCandidate, pydantic.BaseModel), "ScoringCandidate must not be Pydantic"


def test_no_pydantic_on_score_breakdown():
    """ScoreBreakdown should NOT be a Pydantic model."""
    from aila.modules.vulnerability.agents.scoring.models import ScoreBreakdown

    assert not issubclass(ScoreBreakdown, pydantic.BaseModel), "ScoreBreakdown must not be Pydantic"


def test_scoring_candidate_all_exported():
    import aila.modules.vulnerability.agents.scoring.models as m

    for name in ("ScoringCandidate", "ScoreBreakdown"):
        assert name in m.__all__, f"{name} must be in __all__"


def test_signal_assessment_exported_from_contracts():
    import aila.modules.vulnerability.contracts as c

    assert "SignalAssessment" in c.__all__, "SignalAssessment must be in contracts.__all__"
