"""Built-in disclosure tracks shipped in v0.3 v1.

Adding a new track:
  1. Subclass DisclosureTrack
  2. Override class attributes (track_id, kind, display_name, ...)
  3. Override render() — return Markdown the operator pastes / submits
  4. Add to BUILTIN_TRACKS at the bottom

The 4 tracks below cover the practical operator workflow today:
  chrome_vrp       — Chrome's bounty program
  blog_post        — public writeup (operator's own platform)
  vendor_direct    — generic security@ email template
  cna_github_gsa   — GitHub Security Advisory (own-repo or via CNA)

The plan calls for ~10 tracks (msrc / mozilla_bb / apple_security /
github_bb / zdi / cert_cc / conference_cfp); those land per-need.
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.contracts.disclosure import (
    ArtifactTier,
    DisclosureKind,
)

from .base import DisclosureTrack

__all__ = [
    "BUILTIN_TRACKS",
    "BlogPostTrack",
    "ChromeVRPTrack",
    "CnaGithubGsaTrack",
    "VendorDirectTrack",
]


def _section(title: str, body: str) -> str:
    body = body.strip()
    if not body:
        body = "_(not provided)_"
    return f"## {title}\n\n{body}\n"


def _common_header(
    finding_payload: dict[str, Any],
    severity_rating: str | None,
) -> str:
    title = finding_payload.get("title") or finding_payload.get("crash_type") or "VR finding"
    function_name = finding_payload.get("vulnerable_function") or "(unspecified)"
    crash_type = finding_payload.get("crash_type") or "(unspecified)"
    out: list[str] = [
        f"# {title}",
        "",
        f"- **Crash type**: `{crash_type}`",
        f"- **Vulnerable function**: `{function_name}`",
    ]
    if severity_rating:
        out.append(f"- **Severity**: {severity_rating}")
    return "\n".join(out) + "\n"


class ChromeVRPTrack(DisclosureTrack):
    track_id = "chrome_vrp"
    kind = DisclosureKind.BOUNTY
    display_name = "Chrome Vulnerability Reward Program"
    program_url = "https://bughunters.google.com/report"
    required_artifacts = ("vulnerable_function", "root_cause")
    accepted_poc_tiers = (ArtifactTier.WORKING_POC,)
    embargo_default_days = 90
    severity_schema = "chrome_vrp_custom"
    notes = (
        "Submit via the Chrome Issue Tracker. Working PoC is required — "
        "no-PoC submissions are rejected by triage. Operator self-rates "
        "severity per the Chrome VRP severity guidelines."
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
        parts: list[str] = [
            _common_header(finding_payload, severity_rating),
            _section("Summary", str(finding_payload.get("summary") or "")),
            _section("Reproducer", str(finding_payload.get("poc_code") or finding_payload.get("reproducer") or "")),
            _section("Root cause", str(finding_payload.get("root_cause") or "")),
            _section(
                "Expected vs actual behaviour",
                str(finding_payload.get("expected_vs_actual") or ""),
            ),
            _section(
                "Impact",
                str(finding_payload.get("impact") or "Memory corruption in browser process (renderer or browser)."),
            ),
            _section(
                "Mitigation suggestion",
                str(finding_payload.get("mitigation_suggestion") or ""),
            ),
            _section(
                "Disclosure",
                (
                    f"Requesting standard {embargo_days or cls.embargo_default_days}-day "
                    "embargo. PoC tier supplied: "
                    f"`{poc_tier.value}` (Chrome VRP requires working_poc; "
                    "do not strip until vendor confirms triage)."
                ),
            ),
        ]
        return "\n".join(parts)


class BlogPostTrack(DisclosureTrack):
    track_id = "blog_post"
    kind = DisclosureKind.PUBLIC
    display_name = "Public writeup (own platform)"
    program_url = None
    required_artifacts = ("title", "summary")
    accepted_poc_tiers = (ArtifactTier.SANITIZED_POC, ArtifactTier.NO_POC)
    embargo_default_days = 0  # publish after parallel-track embargo passes
    severity_schema = "cvss"
    notes = (
        "Public writeup as Markdown suitable for the operator's own blog. "
        "Working PoC NEVER published; sanitized or descriptive only. "
        "Cross-references to bounty awards / CVE ids land in the timeline "
        "section. Operator approves before publish."
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
        parts: list[str] = [
            _common_header(finding_payload, severity_rating),
            _section(
                "Background",
                str(finding_payload.get("background") or
                    "Add context: what subsystem, why interesting, prior art."),
            ),
            _section(
                "The bug",
                str(finding_payload.get("root_cause") or
                    "Describe the bug in operator's voice. Cite code / disassembly."),
            ),
            _section(
                "How it was found",
                str(finding_payload.get("discovery_narrative") or
                    "Tooling used (audit-mcp / IDA / fuzzing) and the chain of "
                    "reasoning. Link patterns extracted from this investigation."),
            ),
            _section(
                "Exploitation outline",
                str(finding_payload.get("exploitation_outline") or
                    "DESCRIPTIVE only — no working primitives. "
                    f"PoC tier on this writeup: `{poc_tier.value}`."),
            ),
            _section(
                "Mitigation",
                str(finding_payload.get("mitigation_summary") or
                    "Vendor patch description + version range fixed."),
            ),
            _section(
                "Timeline",
                str(finding_payload.get("timeline_markdown") or
                    "- Discovery: …\n- Reported to vendor: …\n- Triaged: …\n"
                    "- Patch shipped: …\n- Public disclosure: …"),
            ),
            _section(
                "Attribution",
                str(finding_payload.get("attribution") or "Researcher name + handle"),
            ),
        ]
        return "\n".join(parts)


class VendorDirectTrack(DisclosureTrack):
    track_id = "vendor_direct"
    kind = DisclosureKind.VENDOR_DIRECT
    display_name = "Generic security@ email"
    program_url = None
    required_artifacts = ("vulnerable_function", "root_cause")
    accepted_poc_tiers = (
        ArtifactTier.WORKING_POC,
        ArtifactTier.SANITIZED_POC,
        ArtifactTier.NO_POC,
    )
    embargo_default_days = 90
    severity_schema = "cvss"
    notes = (
        "Plain Markdown email body. Operator sends from their own mailbox "
        "to the vendor's security@ address. PGP encryption if vendor "
        "publishes a key."
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
        parts: list[str] = [
            f"Subject: Vulnerability report — {finding_payload.get('title') or 'security finding'}",
            "",
            "Hello,",
            "",
            "I am reporting a security vulnerability in your product. Details below.",
            "",
            _common_header(finding_payload, severity_rating),
            _section("Affected component", str(finding_payload.get("affected_component") or "")),
            _section("Description", str(finding_payload.get("summary") or finding_payload.get("root_cause") or "")),
            _section(
                "Reproducer",
                (
                    str(finding_payload.get("poc_code") or "")
                    if poc_tier != ArtifactTier.NO_POC
                    else "Available on request after acknowledgement."
                ),
            ),
            _section("Expected impact", str(finding_payload.get("impact") or "")),
            _section(
                "Disclosure timeline",
                (
                    f"Requesting {embargo_days or cls.embargo_default_days}-day "
                    "embargo from acknowledgement. After that I plan to publish a writeup."
                ),
            ),
            "",
            "Please confirm receipt within 7 days.",
            "",
            "Regards,",
            str(finding_payload.get("attribution") or "(researcher name)"),
        ]
        return "\n".join(parts)


class CnaGithubGsaTrack(DisclosureTrack):
    track_id = "cna_github_gsa"
    kind = DisclosureKind.CNA
    display_name = "GitHub Security Advisory (CNA)"
    program_url = "https://github.com/advisories"
    required_artifacts = ("affected_component", "root_cause", "fixed_version")
    accepted_poc_tiers = (
        ArtifactTier.SANITIZED_POC,
        ArtifactTier.NO_POC,
    )
    embargo_default_days = 30
    severity_schema = "cvss"
    notes = (
        "Draft GHSA YAML/Markdown for the maintainer to publish. Once "
        "published GitHub assigns a CVE id automatically. Working PoC "
        "stays private (separate vendor email)."
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
        del poc_tier  # base-class kwarg; CnaGithubGsaTrack omits it from output
        affected = finding_payload.get("affected_component") or "(unspecified)"
        fixed = finding_payload.get("fixed_version") or "(unreleased)"
        cvss = severity_rating or "7.5 (placeholder — operator to compute)"
        parts: list[str] = [
            f"# Security advisory: {finding_payload.get('title') or 'untitled'}",
            "",
            f"- **Package / component**: `{affected}`",
            f"- **Fixed in**: `{fixed}`",
            f"- **CVSS**: {cvss}",
            f"- **CWE**: {finding_payload.get('cwe') or '(operator to assign)'}",
            "",
            _section("Summary", str(finding_payload.get("summary") or "")),
            _section("Details", str(finding_payload.get("root_cause") or "")),
            _section(
                "Affected versions",
                str(finding_payload.get("affected_versions") or "(operator to fill)"),
            ),
            _section(
                "Patches",
                str(finding_payload.get("patch_reference") or "(commit / PR link)"),
            ),
            _section(
                "Workarounds",
                str(finding_payload.get("workaround") or "_(none beyond upgrade)_"),
            ),
            _section(
                "References",
                str(finding_payload.get("references_markdown") or "- (advisory URL)\n- (commit URL)"),
            ),
            _section(
                "Credit",
                str(finding_payload.get("attribution") or "(researcher name)"),
            ),
        ]
        return "\n".join(parts)


BUILTIN_TRACKS: tuple[type[DisclosureTrack], ...] = (
    ChromeVRPTrack,
    BlogPostTrack,
    VendorDirectTrack,
    CnaGithubGsaTrack,
)
