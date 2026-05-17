"""Unit tests for the 7 extra disclosure tracks (v0.3 closeout).

Each track is verified for:
  - track_id + kind + display_name + program_url sanity
  - required_artifacts + accepted_poc_tiers
  - render() returns Markdown body containing the finding signature
  - validate() rejects mismatched poc_tier
"""
from __future__ import annotations

import pytest

from aila.modules.vr.contracts.disclosure import (
    ArtifactTier,
    DisclosureKind,
)
from aila.modules.vr.disclosure import available_tracks, get_track

_SAMPLE_PAYLOAD = {
    "id": "f-1",
    "title": "JIT type confusion in V8",
    "crash_type": "type-confusion",
    "vulnerable_function": "JSCallReducer::ReduceJSCall",
    "root_cause": "Missing alias check on InferMaps allows JIT to materialise a wrong-typed object.",
    "poc_code": "var a = ...; for (let i = 0; i < 100; i++) jit(a);",
    "summary": "JIT type-confuses on aliased map-inference input",
    "affected_component": "V8 8.x — 11.x",
    "impact": "Renderer RCE via JIT-produced type confusion.",
    "mitigation_suggestion": "Reinstate alias check before InferMaps.",
    "expected_vs_actual": "Expected: alias check rejects. Actual: JIT proceeds.",
    "reliability_notes": "Deterministic when warm-up shapes match.",
    "attribution": "researcher@example.com",
    "talk_abstract": "How I found CVE-2026-XXXXX",
    "talk_outline": "1. Background\n2. Discovery\n3. Demo\n4. Mitigation",
    "talk_relevance": "First public V8 sandbox escape since X",
}


_NEW_TRACKS = [
    ("msrc",            DisclosureKind.BOUNTY),
    ("mozilla_bb",      DisclosureKind.BOUNTY),
    ("apple_security",  DisclosureKind.BOUNTY),
    ("github_bb",       DisclosureKind.BOUNTY),
    ("zdi",             DisclosureKind.BROKER),
    ("cert_cc",         DisclosureKind.COORDINATION),
    ("conference_cfp",  DisclosureKind.ACADEMIC),
]


class TestExtraTracksRegistered:
    def test_all_seven_in_registry(self) -> None:
        registry = available_tracks()
        for track_id, _ in _NEW_TRACKS:
            assert track_id in registry, f"{track_id} not registered"

    def test_total_track_count_is_fourteen(self) -> None:
        # 4 original (chrome_vrp / blog_post / vendor_direct / cna_github_gsa)
        # + 7 v0.3 extras + 3 v0.5 kernel = 14
        assert len(available_tracks()) == 14

    @pytest.mark.parametrize("track_id,expected_kind", _NEW_TRACKS)
    def test_kind_matches(self, track_id: str, expected_kind: DisclosureKind) -> None:
        track = get_track(track_id)
        assert track is not None
        assert track.kind == expected_kind


class TestExtraTracksRender:
    @pytest.mark.parametrize("track_id,_", _NEW_TRACKS)
    def test_render_includes_finding_signature(
        self, track_id: str, _: DisclosureKind,
    ) -> None:
        track = get_track(track_id)
        assert track is not None
        # Pick the highest poc_tier the track accepts
        poc_tier = track.accepted_poc_tiers[0]
        body = track.render(
            finding_payload=_SAMPLE_PAYLOAD,
            poc_tier=poc_tier,
            severity_rating="9.8 critical",
            embargo_days=None,
        )
        assert isinstance(body, str)
        assert len(body) > 100
        # Every rendered body should include either the function name OR title
        assert (
            "JSCallReducer::ReduceJSCall" in body
            or "JIT type confusion in V8" in body
            or "type-confusion" in body
        ), f"{track_id} render() body missing finding signature: {body[:200]}"

    @pytest.mark.parametrize("track_id,_", _NEW_TRACKS)
    def test_render_includes_severity_when_provided(
        self, track_id: str, _: DisclosureKind,
    ) -> None:
        if track_id == "conference_cfp":
            pytest.skip("conference_cfp is a talk-proposal template; no severity row")
        track = get_track(track_id)
        assert track is not None
        poc_tier = track.accepted_poc_tiers[0]
        body = track.render(
            finding_payload=_SAMPLE_PAYLOAD,
            poc_tier=poc_tier,
            severity_rating="9.8 critical",
            embargo_days=None,
        )
        # Common-header puts severity inline; cna_github_gsa puts CVSS in a
        # dedicated field. Either presentation is OK.
        assert "9.8" in body or "critical" in body.lower()


class TestExtraTracksValidate:
    @pytest.mark.parametrize("track_id,_", _NEW_TRACKS)
    def test_rejects_wrong_poc_tier(
        self, track_id: str, _: DisclosureKind,
    ) -> None:
        track = get_track(track_id)
        assert track is not None
        all_tiers = {ArtifactTier.WORKING_POC, ArtifactTier.SANITIZED_POC, ArtifactTier.NO_POC}
        rejected_tier = next(
            iter(all_tiers - set(track.accepted_poc_tiers)),
            None,
        )
        if rejected_tier is None:
            pytest.skip(f"{track_id} accepts all poc tiers")
        errors = track.validate(
            poc_tier=rejected_tier,
            finding_payload=_SAMPLE_PAYLOAD,
        )
        assert errors, f"{track_id} should reject poc_tier={rejected_tier.value}"
        assert any("does not accept" in e for e in errors)

    @pytest.mark.parametrize("track_id,_", _NEW_TRACKS)
    def test_accepts_with_full_payload_and_top_tier(
        self, track_id: str, _: DisclosureKind,
    ) -> None:
        track = get_track(track_id)
        assert track is not None
        poc_tier = track.accepted_poc_tiers[0]
        # Sample payload populates all common required_artifacts
        errors = track.validate(
            poc_tier=poc_tier,
            finding_payload=_SAMPLE_PAYLOAD,
        )
        # talk_outline / talk_relevance for conference_cfp aren't in required;
        # missing CVE/fix tracking fields for cna_github_gsa aren't either
        # for this set. Errors should be empty.
        assert errors == [], (
            f"{track_id} unexpected validation errors: {errors}"
        )


class TestSpecificTrackBehaviour:
    def test_zdi_requires_working_poc_only(self) -> None:
        zdi = get_track("zdi")
        assert zdi is not None
        assert zdi.accepted_poc_tiers == (ArtifactTier.WORKING_POC,)
        body = zdi.render(
            finding_payload=_SAMPLE_PAYLOAD,
            poc_tier=ArtifactTier.WORKING_POC,
            severity_rating="critical",
            embargo_days=None,
        )
        # ZDI render must mention exclusivity (operator-visible warning)
        assert "exclusiv" in body.lower()

    def test_apple_security_requires_working_poc_only(self) -> None:
        apple = get_track("apple_security")
        assert apple is not None
        assert apple.accepted_poc_tiers == (ArtifactTier.WORKING_POC,)

    def test_conference_cfp_renders_talk_proposal(self) -> None:
        cfp = get_track("conference_cfp")
        assert cfp is not None
        body = cfp.render(
            finding_payload=_SAMPLE_PAYLOAD,
            poc_tier=ArtifactTier.SANITIZED_POC,
            severity_rating=None,
            embargo_days=None,
        )
        assert "Talk proposal" in body
        assert "Abstract" in body

    def test_cert_cc_default_embargo_45_days(self) -> None:
        cert = get_track("cert_cc")
        assert cert is not None
        assert cert.embargo_default_days == 45

    def test_zdi_default_embargo_120_days(self) -> None:
        zdi = get_track("zdi")
        assert zdi is not None
        assert zdi.embargo_default_days == 120

    def test_msrc_program_url_points_to_researcher_portal(self) -> None:
        msrc = get_track("msrc")
        assert msrc is not None
        assert msrc.program_url is not None
        assert "msrc.microsoft.com" in msrc.program_url

    def test_conference_cfp_no_program_url(self) -> None:
        cfp = get_track("conference_cfp")
        assert cfp is not None
        # Conference CFP isn't a bounty portal — operator picks their conf
        assert cfp.program_url is None
