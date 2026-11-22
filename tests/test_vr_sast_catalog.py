from __future__ import annotations

from aila.modules.vr.sast import (
    SAST_DETECTION_SKILLS,
    SAST_SKILLS,
    SAST_UPSTREAM_COMMIT,
    SastPhase,
    SastSeedBuilder,
    load_sast_skill,
)


def test_catalog_contains_the_complete_pinned_upstream_workflow() -> None:
    assert len(SAST_SKILLS) == 16
    assert len(SAST_DETECTION_SKILLS) == 14
    assert sum(skill.phase is SastPhase.ANALYSIS for skill in SAST_SKILLS) == 1
    assert sum(skill.phase is SastPhase.REPORT for skill in SAST_SKILLS) == 1
    assert "sast-hardcodedsecrets" in {skill.id for skill in SAST_DETECTION_SKILLS}
    for skill in SAST_SKILLS:
        body = load_sast_skill(skill)
        assert f"name: {skill.id}" in body
        prompt = SastSeedBuilder.build(skill)
        assert body in prompt
        assert SAST_UPSTREAM_COMMIT in prompt
        assert "VR persists your final outcome" in prompt
