"""Unit tests for v0.5 phase 3 — kernel disclosure tracks."""
from __future__ import annotations

import pytest

from aila.modules.vr.contracts.disclosure import (
    ArtifactTier,
    DisclosureKind,
)
from aila.modules.vr.disclosure import get_track

_KERNEL_TRACKS = [
    ("linux_distros",       DisclosureKind.COORDINATION),
    ("oss_security",        DisclosureKind.PUBLIC),
    ("kernel_org_security", DisclosureKind.VENDOR_DIRECT),
]

_SAMPLE_PAYLOAD = {
    "id": "f-kernel-1",
    "title": "UAF in netfilter nf_tables expression eval",
    "crash_type": "uaf_refcount",
    "vulnerable_function": "nf_tables_expr_destroy",
    "root_cause": (
        "Concurrent nft_chain_del + ongoing nft_do_chain holds a "
        "stale chain reference after RCU grace period."
    ),
    "poc_code": "// syzkaller reproducer\nint main() { /* ... */ }",
    "summary": "UAF in nf_tables expression destruction path",
    "affected_component": "net/netfilter/nf_tables_api.c",
    "affected_versions": "5.16 — 6.10",
    "fixed_version": "6.10.5",
    "patch_reference": "git.kernel.org/..../commit/abcdef0",
    "attribution": "researcher@example.com",
    "assigned_cve_id": "CVE-2026-99001",
    "mitigation_suggestion": "Add RCU read-side lock around expr destroy.",
}


class TestKernelTracksRegistered:
    @pytest.mark.parametrize("track_id,expected_kind", _KERNEL_TRACKS)
    def test_each_track_registered_with_kind(
        self, track_id: str, expected_kind: DisclosureKind,
    ) -> None:
        track = get_track(track_id)
        assert track is not None
        assert track.kind == expected_kind


class TestLinuxDistros:
    def test_embargo_default_is_14_days(self) -> None:
        track = get_track("linux_distros")
        assert track is not None
        assert track.embargo_default_days == 14

    def test_render_includes_distros_address(self) -> None:
        track = get_track("linux_distros")
        assert track is not None
        body = track.render(
            finding_payload=_SAMPLE_PAYLOAD,
            poc_tier=ArtifactTier.WORKING_POC,
            severity_rating="high",
            embargo_days=None,
        )
        assert "distros@vs.openwall.org" in body
        assert "Subject:" in body
        # Embargo prefix logic — 14 days → [next-day]; 7 days → [vs]
        assert "[next-day]" in body

    def test_render_with_short_embargo_uses_vs_prefix(self) -> None:
        track = get_track("linux_distros")
        assert track is not None
        body = track.render(
            finding_payload=_SAMPLE_PAYLOAD,
            poc_tier=ArtifactTier.WORKING_POC,
            severity_rating="high",
            embargo_days=5,
        )
        assert "[vs]" in body

    def test_rejects_no_poc_tier(self) -> None:
        track = get_track("linux_distros")
        assert track is not None
        errors = track.validate(
            poc_tier=ArtifactTier.NO_POC,
            finding_payload=_SAMPLE_PAYLOAD,
        )
        assert any("does not accept" in e for e in errors)


class TestOssSecurity:
    def test_embargo_default_is_zero(self) -> None:
        # Public list — post AFTER prior-track embargo lifts
        track = get_track("oss_security")
        assert track is not None
        assert track.embargo_default_days == 0

    def test_render_includes_cve_and_patch(self) -> None:
        track = get_track("oss_security")
        assert track is not None
        body = track.render(
            finding_payload=_SAMPLE_PAYLOAD,
            poc_tier=ArtifactTier.SANITIZED_POC,
            severity_rating="high",
            embargo_days=None,
        )
        assert "CVE-2026-99001" in body
        assert "git.kernel.org" in body
        assert "oss-security@lists.openwall.org" in body

    def test_does_not_accept_working_poc(self) -> None:
        track = get_track("oss_security")
        assert track is not None
        assert ArtifactTier.WORKING_POC not in track.accepted_poc_tiers


class TestKernelOrgSecurity:
    def test_embargo_default_is_7_days(self) -> None:
        track = get_track("kernel_org_security")
        assert track is not None
        assert track.embargo_default_days == 7

    def test_render_sends_to_security_at_kernel_org(self) -> None:
        track = get_track("kernel_org_security")
        assert track is not None
        body = track.render(
            finding_payload=_SAMPLE_PAYLOAD,
            poc_tier=ArtifactTier.WORKING_POC,
            severity_rating="high",
            embargo_days=None,
        )
        assert "security@kernel.org" in body
        assert "[SECURITY]" in body

    def test_requires_vulnerable_function(self) -> None:
        track = get_track("kernel_org_security")
        assert track is not None
        bad_payload = {**_SAMPLE_PAYLOAD, "vulnerable_function": ""}
        errors = track.validate(
            poc_tier=ArtifactTier.WORKING_POC,
            finding_payload=bad_payload,
        )
        assert any("vulnerable_function" in e for e in errors)


class TestKernelTrackPayloadAcceptance:
    @pytest.mark.parametrize("track_id,_", _KERNEL_TRACKS)
    def test_accepts_with_full_payload(
        self, track_id: str, _: DisclosureKind,
    ) -> None:
        track = get_track(track_id)
        assert track is not None
        # Pick highest acceptable tier for each
        tier = track.accepted_poc_tiers[0]
        errors = track.validate(
            poc_tier=tier, finding_payload=_SAMPLE_PAYLOAD,
        )
        assert errors == [], (
            f"{track_id} unexpected validation errors: {errors}"
        )
