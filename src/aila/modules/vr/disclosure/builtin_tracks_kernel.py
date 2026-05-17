"""Kernel-specific disclosure tracks (v0.5 GA-57).

Three tracks ship in v0.5 phase 3:

  linux_distros           — private list (vendor-sec@lists.openwall.org).
                            Embargo 14 days max per list policy.
                            PoC private; distros build patches under embargo.
  oss_security            — public mailing list (oss-security@lists.openwall.org).
                            Post AFTER embargo lifts. Sanitized PoC OK.
  kernel_org_security     — security@kernel.org direct. Embargo 7-30 days.
                            CVE pre-assigned via the kernel.org CNA.

Pattern matches v0.3's chrome_vrp / mozilla_bb structure — each is a
small subclass with a render() that emits the operator-pasteable body
in the format that program expects (mailing-list message, security@
email, GHSA YAML).
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.contracts.disclosure import (
    ArtifactTier,
    DisclosureKind,
)

from .base import DisclosureTrack
from .builtin_tracks import _common_header, _section

__all__ = [
    "ALL_KERNEL_TRACKS",
    "KernelOrgSecurityTrack",
    "LinuxDistrosTrack",
    "OssSecurityTrack",
]


class LinuxDistrosTrack(DisclosureTrack):
    track_id = "linux_distros"
    kind = DisclosureKind.COORDINATION
    display_name = "linux-distros (private)"
    program_url = "https://oss-security.openwall.org/wiki/mailing-lists/distros"
    required_artifacts = ("affected_component", "root_cause", "summary")
    accepted_poc_tiers = (
        ArtifactTier.WORKING_POC,
        ArtifactTier.SANITIZED_POC,
    )
    embargo_default_days = 14  # list policy hard cap
    severity_schema = "cvss"
    notes = (
        "Private mailing list for Linux distro security teams. Embargo "
        "is HARD-CAPPED at 14 days from first email by list policy — "
        "request an extension only with strong justification. PoC stays "
        "on-list; do not forward off-list."
    )

    @classmethod
    def render(
        cls,
        *,
        finding_payload: dict[str, Any],
        poc_tier: ArtifactTier,
        severity_rating: str | None,
        embargo_days: int | None,
    ) -> str:
        days = embargo_days or cls.embargo_default_days
        # linux-distros wants a specific subject prefix
        subj_prefix = "[vs] " if days <= 7 else "[next-day] "
        parts: list[str] = [
            f"Subject: {subj_prefix}{finding_payload.get('title') or 'kernel finding'}",
            "",
            "To: distros@vs.openwall.org",
            "",
            _common_header(finding_payload, severity_rating),
            _section("Affected component", str(finding_payload.get("affected_component") or "")),
            _section("Affected kernel versions", str(finding_payload.get("affected_versions") or "(operator to specify)")),
            _section("Summary", str(finding_payload.get("summary") or "")),
            _section("Root cause", str(finding_payload.get("root_cause") or "")),
            _section(
                "Reproducer",
                str(finding_payload.get("poc_code") or
                    "(working PoC attached separately)"),
            ),
            _section(
                "Patch / mitigation",
                str(finding_payload.get("mitigation_suggestion") or
                    "(suggested patch will follow)"),
            ),
            _section(
                "Disclosure timeline",
                (
                    f"Requesting {days}-day embargo per linux-distros policy "
                    "(max 14). Public disclosure on oss-security after."
                ),
            ),
            "",
            "Regards,",
            str(finding_payload.get("attribution") or "(researcher name)"),
        ]
        return "\n".join(parts)


class OssSecurityTrack(DisclosureTrack):
    track_id = "oss_security"
    kind = DisclosureKind.PUBLIC
    display_name = "oss-security (public)"
    program_url = "https://oss-security.openwall.org/wiki/mailing-lists/oss-security"
    required_artifacts = ("title", "summary", "affected_component")
    accepted_poc_tiers = (
        ArtifactTier.SANITIZED_POC,
        ArtifactTier.NO_POC,
    )
    embargo_default_days = 0  # post AFTER prior-track embargo lifts
    severity_schema = "cvss"
    notes = (
        "Public mailing list. POST AFTER the linux_distros / "
        "kernel_org_security embargo has lifted AND the patch has shipped. "
        "Sanitized PoC only; working PoC stays private on the prior track."
    )

    @classmethod
    def render(
        cls,
        *,
        finding_payload: dict[str, Any],
        poc_tier: ArtifactTier,
        severity_rating: str | None,
        embargo_days: int | None,
    ) -> str:
        cve = finding_payload.get("assigned_cve_id") or "(CVE pending)"
        parts: list[str] = [
            f"Subject: {finding_payload.get('title') or 'kernel finding'} [{cve}]",
            "",
            "To: oss-security@lists.openwall.org",
            "",
            _common_header(finding_payload, severity_rating),
            f"- **CVE**: {cve}",
            f"- **Patch commit**: {finding_payload.get('patch_reference') or '(commit hash here)'}",
            "",
            _section("Summary", str(finding_payload.get("summary") or "")),
            _section("Affected versions", str(finding_payload.get("affected_versions") or "")),
            _section("Fixed in", str(finding_payload.get("fixed_version") or "")),
            _section("Technical details", str(finding_payload.get("root_cause") or "")),
            _section(
                "Reproducer (sanitized)",
                str(finding_payload.get("sanitized_poc") or "(descriptive only — full PoC stays private)"),
            ),
            _section("Credit", str(finding_payload.get("attribution") or "")),
            "",
            "Regards,",
            str(finding_payload.get("attribution") or "(researcher name)"),
        ]
        return "\n".join(parts)


class KernelOrgSecurityTrack(DisclosureTrack):
    track_id = "kernel_org_security"
    kind = DisclosureKind.VENDOR_DIRECT
    display_name = "kernel.org security team"
    program_url = "https://www.kernel.org/doc/html/latest/process/security-bugs.html"
    required_artifacts = (
        "vulnerable_function",
        "root_cause",
        "affected_component",
    )
    accepted_poc_tiers = (
        ArtifactTier.WORKING_POC,
        ArtifactTier.SANITIZED_POC,
    )
    embargo_default_days = 7  # kernel.org default; up to 30 with justification
    severity_schema = "cvss"
    notes = (
        "Send to security@kernel.org. The kernel security team triages, "
        "writes the patch, and merges it under embargo. CVE pre-assigned "
        "via the kernel.org CNA. Default embargo 7 days from patch ready; "
        "request up to 30 days with justification."
    )

    @classmethod
    def render(
        cls,
        *,
        finding_payload: dict[str, Any],
        poc_tier: ArtifactTier,
        severity_rating: str | None,
        embargo_days: int | None,
    ) -> str:
        days = embargo_days or cls.embargo_default_days
        parts: list[str] = [
            f"Subject: [SECURITY] {finding_payload.get('title') or 'kernel finding'}",
            "",
            "To: security@kernel.org",
            "",
            _common_header(finding_payload, severity_rating),
            _section("Affected subsystem", str(finding_payload.get("affected_component") or "")),
            _section("Vulnerable function", str(finding_payload.get("vulnerable_function") or "")),
            _section("Root cause", str(finding_payload.get("root_cause") or "")),
            _section(
                "Reproducer",
                str(finding_payload.get("poc_code") or
                    "(working PoC attached; runs under syzkaller / qemu)"),
            ),
            _section(
                "Impact",
                str(finding_payload.get("impact") or
                    "(operator to characterise: privilege escalation / "
                    "info leak / container escape / DoS)"),
            ),
            _section(
                "Suggested fix",
                str(finding_payload.get("mitigation_suggestion") or
                    "(operator to propose patch or leave blank for team to author)"),
            ),
            _section(
                "Disclosure timeline",
                (
                    f"Requesting {days}-day embargo from patch-ready. "
                    "CVE pre-assignment requested. After embargo: post to "
                    "oss-security + personal blog writeup."
                ),
            ),
            "",
            "Regards,",
            str(finding_payload.get("attribution") or "(researcher name)"),
        ]
        return "\n".join(parts)


ALL_KERNEL_TRACKS: tuple[type[DisclosureTrack], ...] = (
    LinuxDistrosTrack,
    OssSecurityTrack,
    KernelOrgSecurityTrack,
)
