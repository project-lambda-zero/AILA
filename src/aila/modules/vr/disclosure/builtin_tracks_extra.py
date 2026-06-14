"""Additional built-in disclosure tracks (v0.3 closeout).

These 6 tracks complete the 10-track baseline the Disclosure Lifecycle
plan calls for. Each is a thin subclass with a per-track render() that
operators paste into the program's actual submission portal.
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
    "ALL_EXTRA_TRACKS",
    "AppleSecurityTrack",
    "CertCCTrack",
    "ConferenceCfpTrack",
    "GitHubBugBountyTrack",
    "MSRCTrack",
    "MozillaBBTrack",
    "ZDITrack",
]


class MSRCTrack(DisclosureTrack):
    track_id = "msrc"
    kind = DisclosureKind.BOUNTY
    display_name = "Microsoft Security Response Center"
    program_url = "https://msrc.microsoft.com/report"
    required_artifacts = ("vulnerable_function", "root_cause", "affected_component")
    accepted_poc_tiers = (ArtifactTier.WORKING_POC, ArtifactTier.SANITIZED_POC)
    embargo_default_days = 90
    severity_schema = "cvss"
    notes = (
        "Submit via MSRC Researcher Portal. CVE pre-assignment supported "
        "for confirmed vulnerabilities. PoC encouraged but Sanitised "
        "Proof-of-Concept acceptable for low-severity submissions."
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
        del poc_tier  # part of DisclosureTrack.render contract; unused here
        parts: list[str] = [
            _common_header(finding_payload, severity_rating),
            _section(
                "Affected product / version",
                str(finding_payload.get("affected_component") or ""),
            ),
            _section("Summary", str(finding_payload.get("summary") or "")),
            _section("Root cause", str(finding_payload.get("root_cause") or "")),
            _section(
                "Reproducer",
                str(finding_payload.get("poc_code")
                    or "Submitted separately via the secure-upload portal."),
            ),
            _section(
                "Impact",
                str(finding_payload.get("impact")
                    or "Remote code execution / privilege escalation / information disclosure"),
            ),
            _section(
                "Disclosure",
                (
                    f"Requesting {embargo_days or cls.embargo_default_days}-day "
                    "embargo per MSRC policy. CVE pre-assignment requested."
                ),
            ),
        ]
        return "\n".join(parts)


class MozillaBBTrack(DisclosureTrack):
    track_id = "mozilla_bb"
    kind = DisclosureKind.BOUNTY
    display_name = "Mozilla Bug Bounty"
    program_url = "https://www.mozilla.org/security/bug-bounty/"
    required_artifacts = ("vulnerable_function", "root_cause")
    accepted_poc_tiers = (ArtifactTier.WORKING_POC, ArtifactTier.SANITIZED_POC)
    embargo_default_days = 90
    severity_schema = "mozilla_severity"
    notes = (
        "Submit via Bugzilla with the 'sec-critical/sec-high/...' confidentiality "
        "flag. Operator self-rates severity per Mozilla's published rubric."
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
        del poc_tier  # part of DisclosureTrack.render contract; unused here
        parts: list[str] = [
            _common_header(finding_payload, severity_rating),
            _section("Summary", str(finding_payload.get("summary") or "")),
            _section("Steps to reproduce", str(finding_payload.get("poc_code") or "")),
            _section(
                "Actual vs expected behaviour",
                str(finding_payload.get("expected_vs_actual") or ""),
            ),
            _section("Root cause", str(finding_payload.get("root_cause") or "")),
            _section(
                "Disclosure",
                (
                    f"Mozilla standard embargo "
                    f"({embargo_days or cls.embargo_default_days} days from triage)."
                ),
            ),
        ]
        return "\n".join(parts)


class AppleSecurityTrack(DisclosureTrack):
    track_id = "apple_security"
    kind = DisclosureKind.BOUNTY
    display_name = "Apple Security Bounty"
    program_url = "https://security.apple.com/bounty/"
    required_artifacts = (
        "vulnerable_function",
        "root_cause",
        "affected_component",
    )
    accepted_poc_tiers = (ArtifactTier.WORKING_POC,)
    embargo_default_days = 90
    severity_schema = "apple_security"
    notes = (
        "Submit via Apple's bounty portal. Working PoC required + targeting "
        "info (device model, OS version). Apple's payout depends on bug class + "
        "exploitation reliability."
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
        del poc_tier  # part of DisclosureTrack.render contract; unused here
        parts: list[str] = [
            _common_header(finding_payload, severity_rating),
            _section(
                "Affected device / OS",
                str(finding_payload.get("affected_component")
                    or "(operator to fill: iOS / macOS / iPadOS / watchOS / visionOS + version range)"),
            ),
            _section("Bug class", str(finding_payload.get("crash_type") or "")),
            _section("Root cause", str(finding_payload.get("root_cause") or "")),
            _section(
                "Reproducer",
                str(finding_payload.get("poc_code")
                    or "(working PoC required — never strip primitives)"),
            ),
            _section(
                "Reliability",
                str(finding_payload.get("reliability_notes")
                    or "(operator to characterise: deterministic / probabilistic / "
                    "race-dependent / etc.)"),
            ),
            _section(
                "Disclosure",
                f"{embargo_days or cls.embargo_default_days}-day embargo from acknowledgement.",
            ),
        ]
        return "\n".join(parts)


class GitHubBugBountyTrack(DisclosureTrack):
    track_id = "github_bb"
    kind = DisclosureKind.BOUNTY
    display_name = "GitHub Bug Bounty (HackerOne)"
    program_url = "https://hackerone.com/github"
    required_artifacts = ("affected_component", "summary", "root_cause")
    accepted_poc_tiers = (
        ArtifactTier.WORKING_POC,
        ArtifactTier.SANITIZED_POC,
    )
    embargo_default_days = 90
    severity_schema = "cvss"
    notes = (
        "Submit via HackerOne. GitHub-owned products in scope (github.com, "
        "Actions, Codespaces, etc.). Third-party-OSS bugs go to "
        "cna_github_gsa instead."
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
        del poc_tier  # part of DisclosureTrack.render contract; unused here
        cvss = severity_rating or "(operator to compute)"
        parts: list[str] = [
            _common_header(finding_payload, severity_rating),
            _section("Affected asset", str(finding_payload.get("affected_component") or "")),
            f"- **CVSS**: {cvss}",
            "",
            _section("Summary", str(finding_payload.get("summary") or "")),
            _section("Steps to reproduce", str(finding_payload.get("poc_code") or "")),
            _section("Impact", str(finding_payload.get("impact") or "")),
            _section("Suggested fix", str(finding_payload.get("mitigation_suggestion") or "")),
            _section(
                "Disclosure",
                f"H1 policy {embargo_days or cls.embargo_default_days}-day embargo.",
            ),
        ]
        return "\n".join(parts)


class ZDITrack(DisclosureTrack):
    track_id = "zdi"
    kind = DisclosureKind.BROKER
    display_name = "Trend Micro Zero Day Initiative"
    program_url = "https://www.zerodayinitiative.com/advisories/upcoming/"
    required_artifacts = (
        "vulnerable_function",
        "root_cause",
        "affected_component",
    )
    accepted_poc_tiers = (ArtifactTier.WORKING_POC,)
    embargo_default_days = 120
    severity_schema = "cvss"
    notes = (
        "Submit via ZDI Researcher portal. ZDI takes exclusivity — the same "
        "finding CANNOT be reported to other programs or the vendor "
        "directly while ZDI evaluates. Embargo typically 120 days, sometimes "
        "extended to coordinated disclosure date."
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
        del poc_tier  # part of DisclosureTrack.render contract; unused here
        parts: list[str] = [
            _common_header(finding_payload, severity_rating),
            _section("Affected product", str(finding_payload.get("affected_component") or "")),
            _section("Bug class", str(finding_payload.get("crash_type") or "")),
            _section("Summary", str(finding_payload.get("summary") or "")),
            _section("Root cause", str(finding_payload.get("root_cause") or "")),
            _section("Reproducer", str(finding_payload.get("poc_code") or "")),
            _section(
                "Reliability + exploitation",
                str(finding_payload.get("reliability_notes")
                    or "(operator: bypass mitigations covered, target environment)"),
            ),
            _section(
                "Exclusivity",
                "Confirming this finding is exclusive to ZDI for the duration "
                "of evaluation. No other reports filed.",
            ),
            _section(
                "Disclosure",
                f"ZDI-coordinated; embargo {embargo_days or cls.embargo_default_days}+ days.",
            ),
        ]
        return "\n".join(parts)


class CertCCTrack(DisclosureTrack):
    track_id = "cert_cc"
    kind = DisclosureKind.COORDINATION
    display_name = "CERT/CC (VINCE)"
    program_url = "https://kb.cert.org/vince/"
    required_artifacts = ("summary", "affected_component")
    accepted_poc_tiers = (
        ArtifactTier.SANITIZED_POC,
        ArtifactTier.NO_POC,
    )
    embargo_default_days = 45
    severity_schema = "cvss"
    notes = (
        "Submit via VINCE. Use for multi-vendor coordination — CERT/CC "
        "contacts affected vendors on your behalf. PoC sent privately to "
        "vendors after they engage."
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
        del poc_tier  # part of DisclosureTrack.render contract; unused here
        parts: list[str] = [
            _common_header(finding_payload, severity_rating),
            _section(
                "Affected vendors / products",
                str(finding_payload.get("affected_component")
                    or "(operator to list all affected vendors for CERT/CC to contact)"),
            ),
            _section("Vulnerability summary", str(finding_payload.get("summary") or "")),
            _section("Technical details", str(finding_payload.get("root_cause") or "")),
            _section(
                "Coordination requested",
                "Requesting CERT/CC to contact the listed vendors and "
                "coordinate a joint disclosure date.",
            ),
            _section(
                "Disclosure",
                (
                    f"Standard {embargo_days or cls.embargo_default_days}-day CERT/CC "
                    "coordination window; extendable if vendors engage."
                ),
            ),
        ]
        return "\n".join(parts)


class ConferenceCfpTrack(DisclosureTrack):
    track_id = "conference_cfp"
    kind = DisclosureKind.ACADEMIC
    display_name = "Conference CFP / talk abstract"
    program_url = None
    required_artifacts = ("title", "summary")
    accepted_poc_tiers = (
        ArtifactTier.SANITIZED_POC,
        ArtifactTier.NO_POC,
    )
    embargo_default_days = 0
    severity_schema = "cvss"
    notes = (
        "Talk abstract for Black Hat / DEF CON / USENIX Security / IEEE S&P "
        "/ etc. Working PoC NEVER on stage — sanitized demonstration only. "
        "Requires patch shipped + (typically) ≥ 30 days post-disclosure."
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
        del poc_tier, severity_rating, embargo_days  # part of DisclosureTrack.render contract; unused here
        parts: list[str] = [
            f"# Talk proposal: {finding_payload.get('title') or 'untitled'}",
            "",
            _section(
                "Abstract (≤ 200 words)",
                str(finding_payload.get("talk_abstract")
                    or "(operator to draft: hook + technical insight + audience takeaway)"),
            ),
            _section(
                "Outline",
                str(finding_payload.get("talk_outline")
                    or "1. Background\n2. Discovery process\n3. Technical deep-dive\n"
                    "4. Sanitised demonstration\n5. Mitigation + ecosystem implications\n"
                    "6. Q&A"),
            ),
            _section(
                "Why now",
                str(finding_payload.get("talk_relevance")
                    or "(operator to justify novelty / industry impact / mitigation gap)"),
            ),
            _section(
                "Speaker bio",
                str(finding_payload.get("attribution") or "(researcher bio)"),
            ),
            _section(
                "Materials provided",
                "Slides + sanitised demo video. Working PoC withheld; will "
                "discuss exploitation technique conceptually.",
            ),
        ]
        return "\n".join(parts)


ALL_EXTRA_TRACKS: tuple[type[DisclosureTrack], ...] = (
    MSRCTrack,
    MozillaBBTrack,
    AppleSecurityTrack,
    GitHubBugBountyTrack,
    ZDITrack,
    CertCCTrack,
    ConferenceCfpTrack,
)
