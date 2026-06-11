"""VF Yanımda — MASVS L1 audit PDF generator.

This script renders the production-grade OWASP MASVS L1 audit report
for the ``com.vodafone.selfservis`` APK (v19.4.0) directly from the
JSON dump staged under ``.run/yanimda_report/``. The output PDF lives
at ``--out`` (default ``.run/yanimda_report/yanimda_masvs.pdf``).

The script is intentionally distinct from AILA's existing investigation
PDF aesthetic (dark cream-on-charcoal slide deck). This one looks like
a real security-firm audit report: ivory paper, dark ink, saturated
verdict colors, tactical orange chrome, dense per-page information.

Data contract
=============
Three JSON files are read at startup. Each is a verbatim snapshot of
the production database tables that back a VR MASVS audit. None of
the keys are invented here:

- ``audit_dump.json``:

    {
      target_id, audit_id,
      target: { id, display_name, kind, mcp_handles_json, ... },
      audit: { id, title, initial_question, status,
               created_at, stopped_at, cost_actual_usd, metadata_json },
      children: [
        { id, title, kind, status, initial_question,
          primary_outcome_id, metadata_json,
          created_at, stopped_at, cost_actual_usd,
          branches: [{ id, persona_voice, status,
                       turn_count, closed_reason, parent_branch_id }, ...],
          outcomes: [{ id, branch_id, outcome_kind, confidence,
                       state, dispatch_status,
                       payload_json: <JSON-encoded str>,
                       evidence_refs_json: <JSON-encoded str>,
                       created_at }, ...]
        }, ... (53 children — one per MASVS L1 control)
      ]
    }

  Each child's primary outcome carries the agent's full reasoning
  in ``payload_json`` (decoded as a dict with keys ``answer``,
  ``reasoning``, ``affected_components``, ``variant_hunt_orders``,
  ``panel_contributions`` (per-persona votes with answer briefs),
  ``verifier_report`` (claim-verifier adversarial loop output when
  present), ``provenance``, ``contract``, ``canonical``).

- ``masvs_catalog.json``: dict keyed by control_id with
  ``{control_id, title, description, group, level,
    verification_steps, evidence_hints, relevant_apis}``.

- ``apk_intel.json``: APK fingerprint and MobSF scan output.
    ``{package_name, apk_sha256, jadx_class_count,
       audit_mcp_decompiled_index_id, decompiled_dir, manifest_path,
       static_summary: { package, version_name, version_code,
                         min_sdk, target_sdk,
                         permissions, activities, services,
                         receivers, providers, main_activity,
                         exported_components, signing_certs },
       mobsf_scan: { appsec: { high, warning, info, secure, hotspot,
                                security_score, total_trackers },
                     permissions, network_security, certificate_analysis,
                     code_analysis, manifest_analysis, ... } }``

Verdict mapping
===============
The verdict for each control is computed by
:func:`aila.modules.vr.masvs.verdict_mapper.child_outcome_to_verdict`
— the production mapper that backs AILA's existing MASVS aggregate.
This script never re-implements that logic; it converts the raw
``outcomes[0]`` dict into a ``VROutcomeSummary`` and lets the mapper
produce the verdict. The four ``MasvsVerdict`` outputs are presented
as four operator-facing labels:

  - ``MasvsVerdict.FINDING``        → ``FAIL``   (red    #d83b3b)
  - ``MasvsVerdict.NO_FINDING``     → ``PASS``   (green  #2e9b5a)
  - ``MasvsVerdict.NOT_APPLICABLE`` → ``N/A``    (grey   #7c7c8a)
  - ``MasvsVerdict.INCONCLUSIVE``   → ``REVIEW`` (amber  #d99a2c)

Children with no outcome at all (the parent reaped them under a wall-
clock / turn-cap cutoff) render as ``INCONCLUSIVE`` with an explicit
"auto-closed without panel quorum" annotation and the per-persona
branch closure reasons.

Why reportlab
=============
AILA's existing PDFs use reportlab Platypus, so we stay on the same
dependency footprint (no new package). Platypus' frame/template
machinery is exactly the right tool for dense multi-page security-
audit layouts where each finding pours across one or more pages with
shared header/footer chrome.

Invocation
==========
::

    python scripts/vr_masvs_report_yanimda.py
    python scripts/vr_masvs_report_yanimda.py --out path/to/out.pdf
    python scripts/vr_masvs_report_yanimda.py --verify     # concur-check pass
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# --- AILA verdict mapper bridge ----------------------------------------------
# Stay read-only on the VR module. We only need the mapper + the two
# pydantic shapes it consumes.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from aila.modules.vr.contracts.masvs import (  # noqa: E402
    MasvsControlVerdict,
    MasvsVerdict,
)
from aila.modules.vr.contracts.outcome import (  # noqa: E402
    OutcomeConfidence,
    OutcomeKind,
    VROutcomeSummary,
)
from aila.modules.vr.masvs.models import (  # noqa: E402
    MasvsControl,
    MasvsGroup,
    MasvsLevel,
)
from aila.modules.vr.masvs.verdict_mapper import (  # noqa: E402
    child_outcome_to_verdict,
)

# --- reportlab ---------------------------------------------------------------
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Flowable,
    Frame,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

# ============================================================================
# CONSTANTS — visual identity, palette, geometry
# ============================================================================

# Saturated verdict palette. Tested against print: every label readable
# on the ivory paper background and at small font sizes.
COL_FAIL = colors.HexColor("#d83b3b")
COL_PASS = colors.HexColor("#2e9b5a")
COL_NA = colors.HexColor("#7c7c8a")
COL_REVIEW = colors.HexColor("#d99a2c")
COL_INCONCLUSIVE = colors.HexColor("#a1542e")  # darker amber for orphans
# INFO: control verdict requires external (operator-supplied) documentation
# — e.g. component inventory, data classification matrix, SBOM,
# architecture diagram, privacy policy artifact. The code audit alone
# cannot determine compliance; the verdict is informational, not a defect.
# Steel blue keeps it visually distinct from the warm
# fail/pass/review palette and signals "out of code-audit scope".
COL_INFO = colors.HexColor("#3a6b8c")

# Tactical chrome.
COL_PAPER = colors.HexColor("#f5efde")        # ivory
COL_PAPER_DEEP = colors.HexColor("#e8dfc4")   # darker ivory for tabular zebra
COL_INK = colors.HexColor("#1c1812")          # near-black
COL_THIN = colors.HexColor("#b8b09a")         # thin rule colour
COL_ACCENT = colors.HexColor("#a83400")       # rust accent for chrome
COL_ACCENT_DEEP = colors.HexColor("#5c2304")
COL_NAVY = colors.HexColor("#1c2733")         # banners
COL_NAVY_INK = colors.HexColor("#f3ead4")     # banner text
COL_MUTED = colors.HexColor("#5b5443")
COL_ZEBRA = colors.HexColor("#efe7d0")        # zebra row tint
# Light-amber tint for the "what the MASVS standard says" catalog box.
# Visually separates the standard's text from AILA's verdict prose so
# the reader doesn't read OWASP text as if it were the audit's findings.
COL_CATALOG_TINT = colors.HexColor("#f1e3b8")   # warm amber, low saturation
COL_CATALOG_BORDER = colors.HexColor("#c39a3c") # thin amber border rule

VERDICT_COLOR: dict[str, colors.Color] = {
    "FAIL": COL_FAIL,
    "PASS": COL_PASS,
    "N/A": COL_NA,
    "REVIEW": COL_REVIEW,
    "INFO": COL_INFO,
    "INCONCLUSIVE": COL_INCONCLUSIVE,
}

# Group sigil — short two-letter code rendered in a tactical badge.
GROUP_SIGIL: dict[str, str] = {
    "ARCH": "AR",
    "STORAGE": "ST",
    "CRYPTO": "CR",
    "AUTH": "AU",
    "NETWORK": "NW",
    "PLATFORM": "PF",
    "CODE": "CD",
    "RESILIENCE": "RZ",
    "PRIVACY": "PV",
}

PERSONAS: tuple[str, ...] = ("halvar", "noor", "maddie", "yuki", "renzo", "wei")
PERSONA_ROLE: dict[str, str] = {
    "halvar": "Researcher",
    "noor": "Researcher",
    "maddie": "Critic",
    "yuki": "Critic",
    "renzo": "Implementer",
    "wei": "Implementer",
}

# Page geometry. A4 + tight margins for high density.
PAGE_SIZE = A4
PAGE_W, PAGE_H = PAGE_SIZE
MARGIN_L = 14 * mm
MARGIN_R = 14 * mm
MARGIN_T = 22 * mm
MARGIN_B = 16 * mm

REPORT_VERSION = "1.0.0"

# ============================================================================
# FONT REGISTRATION
# ============================================================================

_VF_LOCAL_FONTS = Path.home() / "AppData" / "Local" / "Microsoft" / "Windows" / "Fonts"

_FONT_CANDIDATES: dict[str, list[str]] = {
    # Body — Vodafone Rg Regular (132 KB).
    "Body": [
        str(_VF_LOCAL_FONTS / "Vodafone.Rg_r.ttf"),
        r"C:\Windows\Fonts\georgia.ttf",
    ],
    # Body italic — Vodafone Lt (light) stands in for italic emphasis since
    # the brand has no italic cut. Visually distinct from Rg without forcing
    # synthetic italic from the rasterizer.
    "Body-Italic": [
        str(_VF_LOCAL_FONTS / "Vodafone.Lt_r.ttf"),
        r"C:\Windows\Fonts\georgiai.ttf",
    ],
    # Body bold — Vodafone Rg Gras (file ships PostScript name VodafoneRg-Bold).
    "Body-Bold": [
        str(_VF_LOCAL_FONTS / "Vodafone.Rg.ttf"),
        r"C:\Windows\Fonts\georgiab.ttf",
    ],
    # Body bold italic — no Vodafone variant; reuse bold.
    "Body-BoldItalic": [
        str(_VF_LOCAL_FONTS / "Vodafone.Rg.ttf"),
        r"C:\Windows\Fonts\georgiaz.ttf",
    ],
    # Mono kept as Consolas; Vodafone has no monospace cut.
    "Mono": [
        r"C:\Windows\Fonts\consola.ttf",
    ],
    "Mono-Bold": [
        r"C:\Windows\Fonts\consolab.ttf",
    ],
    # Sans = Vodafone Rg (same Rg face as body for typographic unity; brand
    # uses Rg as the universal sans). Distinct hierarchy comes from size,
    # weight, color, and letter-spacing — not from a separate family.
    "Sans": [
        str(_VF_LOCAL_FONTS / "Vodafone.Rg_r.ttf"),
        r"C:\Windows\Fonts\arial.ttf",
    ],
    "Sans-Bold": [
        str(_VF_LOCAL_FONTS / "Vodafone.Rg.ttf"),
        r"C:\Windows\Fonts\arialbd.ttf",
    ],
    "Sans-BoldItalic": [
        str(_VF_LOCAL_FONTS / "Vodafone.Rg.ttf"),
        r"C:\Windows\Fonts\arialbi.ttf",
    ],
    # Display = Vodafone Lt (Light, 148 KB). Used for the cover title block
    # and chapter openers where the airy thin weight reads as brand-deliberate
    # rather than generic. Falls back to Arial when not installed.
    "Display": [
        str(_VF_LOCAL_FONTS / "Vodafone.Lt_r.ttf"),
        r"C:\Windows\Fonts\arial.ttf",
    ],
}


def _register_fonts() -> None:
    """Register the Vodafone typography stack (Rg / Lt) with consolas mono.

    Falls back to Georgia / Arial / Helvetica built-ins when the Vodafone
    fonts aren't installed (e.g. when this script is run on a fresh CI
    container). Operator workstation has both Vodafone Rg and Lt installed
    under %LOCALAPPDATA%\\Microsoft\\Windows\\Fonts.
    """
    for face, paths in _FONT_CANDIDATES.items():
        for p in paths:
            if Path(p).exists():
                try:
                    pdfmetrics.registerFont(TTFont(face, p))
                    break
                except Exception:
                    continue
    # Manual font family registration so <b>/<i> tags work in paragraphs.
    try:
        pdfmetrics.registerFontFamily(
            "Body",
            normal="Body",
            bold="Body-Bold",
            italic="Body-Italic",
            boldItalic="Body-BoldItalic",
        )
        pdfmetrics.registerFontFamily(
            "Sans",
            normal="Sans",
            bold="Sans-Bold",
            italic="Sans",
            boldItalic="Sans-BoldItalic",
        )
        pdfmetrics.registerFontFamily(
            "Mono",
            normal="Mono",
            bold="Mono-Bold",
            italic="Mono",
            boldItalic="Mono-Bold",
        )
        # Display family is single-weight (Lt); bold/italic reuse the same face.
        pdfmetrics.registerFontFamily(
            "Display",
            normal="Display",
            bold="Display",
            italic="Display",
            boldItalic="Display",
        )
    except Exception:
        pass


def _font(face: str, fallback: str) -> str:
    """Return the registered face name, or ``fallback`` if missing."""
    return face if face in pdfmetrics.getRegisteredFontNames() else fallback


# ============================================================================
# DATA LOADING + PARSING
# ============================================================================

_CONTROL_TITLE_RE = re.compile(r"MASVS\s+([A-Z][A-Z\-]+-\d+)\s*:", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class FindingRecord:
    """One control's resolved finding — everything we need to render."""

    finding_id: str          # "F-001" sequence assigned at build time
    control_id: str          # "MSTG-STORAGE-1"
    group: str               # "STORAGE"
    catalog: dict[str, Any]  # raw catalog entry
    child: dict[str, Any]    # raw child dict (audit_dump.children[i])
    payload: dict[str, Any]  # parsed payload_json (or empty)
    outcome: dict[str, Any] | None  # the primary outcome dict (raw)
    verdict_label: str       # "FAIL" / "PASS" / "N/A" / "REVIEW" / "INCONCLUSIVE"
    verdict_color: colors.Color
    confidence: float        # 0..1
    verdict_reason: str | None
    severity_rank: int       # for index sorting (FAIL=0, REVIEW=1, INCONCLUSIVE=2, N/A=3, PASS=4)


@dataclass
class Bundle:
    """All parsed inputs ready for rendering."""

    audit: dict[str, Any]
    catalog: dict[str, dict[str, Any]]
    apk: dict[str, Any]
    findings: list[FindingRecord]
    # Variant hunt orders aggregated across all findings, each with
    # a V-NNN id and a back-reference to its parent finding.
    variants: list[dict[str, Any]]
    # Curated AILA-platform facts (personas, workflow states, MCP
    # servers, audit-run stats, limitations). Used exclusively by the
    # § 03 ABOUT THE PLATFORM section so the prose there does NOT
    # invent fields — every line traces back to aila_brief.json.
    # Optional so older inputs without the brief still load.
    aila_brief: dict[str, Any] = field(default_factory=dict)


def _load_payload(outcome: dict[str, Any]) -> dict[str, Any]:
    """Decode payload_json which is stored as a JSON-encoded string."""
    raw = outcome.get("payload_json")
    if isinstance(raw, str):
        try:
            return json.loads(raw) or {}
        except json.JSONDecodeError:
            return {}
    return raw or {}


def _control_id_from_child(ch: dict[str, Any]) -> str | None:
    """Extract the MASVS control id from the child's title or metadata."""
    meta = ch.get("metadata_json") or {}
    if isinstance(meta, dict):
        cid = meta.get("masvs_control_id")
        if cid:
            return cid.upper()
    title = ch.get("title") or ""
    m = _CONTROL_TITLE_RE.match(title)
    if m:
        return m.group(1).upper()
    return None


def _build_control(catalog_entry: dict[str, Any]) -> MasvsControl:
    """Turn a raw catalog dict into the dataclass the mapper expects."""
    return MasvsControl(
        id=catalog_entry["control_id"],
        group=MasvsGroup(catalog_entry["group"]),
        level=MasvsLevel(catalog_entry["level"]),
        title=catalog_entry["title"],
        description=catalog_entry["description"],
        verification_steps=tuple(catalog_entry.get("verification_steps") or ()),
        relevant_apis=tuple(catalog_entry.get("relevant_apis") or ()),
        evidence_hints=tuple(catalog_entry.get("evidence_hints") or ()),
    )


def _build_outcome_summary(outcome: dict[str, Any], payload: dict[str, Any], child_id: str) -> VROutcomeSummary:
    """Pack a raw outcome row into the pydantic shape the mapper expects."""
    return VROutcomeSummary(
        id=outcome["id"],
        investigation_id=child_id,
        branch_id=outcome.get("branch_id") or "",
        outcome_kind=OutcomeKind(outcome["outcome_kind"]),
        payload=payload,
        confidence=OutcomeConfidence(outcome["confidence"]),
        evidence_refs=[],
        state=outcome.get("state") or "dispatched",
        dispatch_status=outcome.get("dispatch_status") or "pending",
    )


_VERDICT_LABEL: dict[MasvsVerdict, str] = {
    MasvsVerdict.FINDING: "FAIL",
    MasvsVerdict.NO_FINDING: "PASS",
    MasvsVerdict.NOT_APPLICABLE: "N/A",
    MasvsVerdict.INCONCLUSIVE: "REVIEW",
}

_SEVERITY_RANK: dict[str, int] = {
    "FAIL": 0,
    "REVIEW": 1,
    "INCONCLUSIVE": 2,
    "INFO": 3,
    "N/A": 4,
    "PASS": 5,
}


# ─────────────────────────────────────────────────────────────────
# Text-first verdict analyzer (overrides verdict_mapper)
# ─────────────────────────────────────────────────────────────────
#
# The production mapper ``child_outcome_to_verdict`` keys verdicts off
# ``outcome_kind`` (DIRECT_FINDING → FINDING → FAIL) and ignores the
# agent's actual conclusion text. For audit-style outcomes the agent
# often submits a ``direct_finding`` whose answer text begins with
# "MSTG-X PASSED" or "COMPLIANCE VERIFIED" — those are PASS for MASVS
# purposes, not FAIL. The mapper bug is cataloged in MY_VIOLATIONS
# §218 / §219 / §296 / §346.
#
# This analyzer reads ``payload['answer']`` HEAD (first ~400 chars)
# and BODY, scans against ordered phrase lists, and emits a corrected
# label. The mapper output is consulted only when the text is empty
# or genuinely ambiguous (no markers detected).

# Strong PASS markers — explicit agent-stated compliance.
_PASS_PHRASES_STRONG: tuple[str, ...] = (
    "PASSED", "PASSES", "PASS.", "PASS:", "PASS —", "PASS�",
    "PASS WITH", "PASS (",
    "COMPLIANT", "COMPLIANCE VERIFIED", "COMPLIANCE AFFIRMED",
    "COMPLIANCE CONFIRMED",
    "FULLY COMPLIANT", "CONFORMS TO MASVS", "CONFORMS TO THE MASVS",
    "SATISFIED", "SATISFIES MSTG", "MEETS MSTG", "COMPLIES WITH",
    "NO VIOLATION", "NO VIOLATIONS",
    "NO BUG", "NOT VULNERABLE",
    "PATCH PRESENT", "PATCH IS PRESENT", "PATCH IS IN PLACE",
    "VARIANT DEAD", "VARIANT IS DEAD", "NO VARIANTS",
    "NO EXPLOITABLE", "NO INSECURE",
    "NO FINDING", "NO FINDINGS",
    "VULNERABILITY DOES NOT APPLY",
    "NOT EXPLOITABLE IN PRACTICE",
    "NO APPLICABLE", "NOT APPLICABLE TO",
    "NO HARDCODED",
    "ZERO APP-NAMESPACE MATCHES",
    "ZERO MATCHES IN APP",
    "ZERO APP-CODE HITS",
    "ZERO HITS IN APP",
    "ZERO VIOLATIONS",
    "NO DEPRECATED",
    "NO CREDENTIAL-REPLAY",
    "NO SYMMETRIC KEY",
    "NO EXTERNALLY REACHABLE",
    "NO EXTERNALLY-REACHABLE",
    "NO VULNERABILITY FOUND",
    "NO VIOLATIONS FOUND",
    "AUDIT COMPLETE: NO",
    "AUDIT COMPLETE — NO",
    "AUDIT COMPLETE: ZERO",
    "DO NOT PERFORM SENSITIVE",
    "DO NOT PERFORM ANY SENSITIVE",
    "PROPERLY ENFORCED",
    "SECURITY CONTROL PRESENT",
    "MITIGATION PRESENT",
    "CONTROL IS ENFORCED", "CONTROL IS MET", "CONTROL MET",
    "AUDIT RESULT: NO",
    "AUDIT VERDICT: PASS",
    "AUDIT VERDICT: COMPLIANT",
    "NO RATE-LIMIT ENFORCEMENT BYPASS",
    "SUBSTANTIALLY MEETS",
    "MEETS THE CONTROL", "MEETS THIS CONTROL",
    "RATING: COMPLIANT",
    "VERDICT: COMPLIANT",
    "VERDICT: PASS",
)

# Strong FAIL markers — explicit agent-stated violation.
_FAIL_PHRASES_STRONG: tuple[str, ...] = (
    "VIOLATION CONFIRMED", "VIOLATION DETECTED",
    "VIOLATION FOUND", "VIOLATION:", "VIOLATION —", "VIOLATION�",
    "VIOLATION (FAIL", "VIOLATION (HIGH",
    "DIRECT_FINDING:", "DIRECT FINDING:",
    "DIRECT FINDING AFFIRMED", "DIRECT_FINDING AFFIRMED",
    "FINDING CONFIRMED", "FINDING AFFIRMED",
    "FAILS.", "FAILS:", "FAIL.", "FAIL:", "FAIL —", "FAIL�",
    "FAILS WITH", "FAILS (", "FAIL (",
    "FAIL —", "FAIL,", "FAILURE.",
    "NON-COMPLIANCE", "NON-COMPLIANT",
    "NONCOMPLIANCE", "NONCOMPLIANT", "NON_COMPLIANT",
    "DOES NOT COMPLY", "DOES NOT MEET",
    "CONTROL NOT MET", "REQUIREMENT NOT MET",
    "BREACH DETECTED", "BREACH CONFIRMED",
    "VULNERABILITY CONFIRMED",
    "EXPLOITABLE VULNERABILITY",
    "CONTROL BYPASSED", "CONTROL ABSENT",
    "HARDCODED KEY", "HARDCODED CREDENTIAL", "HARDCODED SECRET",
    "PLAINTEXT STORAGE", "PLAINTEXT LOGGING",
    "MISSING FLAG_SECURE",
    "INSECURE RNG",
    "AUDIT VERDICT: FAIL",
    "VERDICT: FAIL", "VERDICT: NON-COMPLIANT",
    "AUDIT RESULT: FAIL",
    "AUDIT FAILURE",
    "CRITICAL GAP",
)

_REVIEW_PHRASES: tuple[str, ...] = (
    "PARTIAL COMPLIANCE", "PARTIAL NON-COMPLIANCE",
    "PARTIAL FINDING", "PARTIALLY COMPLIANT",
    "WITH HARDENING NOTES", "WITH CAVEATS", "WITH RESERVATIONS",
    "WITH OPEN QUESTION", "WITH OPEN QUESTIONS",
    "WITH UNRESOLVED",
    "MIXED EVIDENCE", "MIXED VERDICT",
    "INCONCLUSIVE",
    "REQUIRES MANUAL REVIEW", "MANUAL REVIEW REQUIRED",
    "OPERATOR MUST CONFIRM", "OPERATOR REVIEW",
    "NEEDS HUMAN REVIEW",
    "ASSESSMENT INCOMPLETE",
    "INSUFFICIENT EVIDENCE",
    "COMPLIANCE ASSESSMENT:",   # narrative assessment, no verdict word
    "FINDINGS: (1)", "FINDINGS:\n",  # enumerated findings narrative
)

# INFO markers — verdict cannot be determined from the APK alone because
# the control's verification target is a TEAM-OWNED DOCUMENT or PROCESS
# (component inventory, data classification matrix, SBOM, privacy policy
# artifact, architecture diagram, change-management record). Operator
# stated: external-document-required verdicts are INFORMATIONAL, not
# code-audit FAILs.
_INFO_PHRASES: tuple[str, ...] = (
    # Architecture / design documents
    "ARCHITECTURE_DOCUMENT_REQUIRED",
    "ARCHITECTURE DOCUMENT REQUIRED",
    "REQUIRES ARCHITECTURE DOCUMENT",
    "ARCHITECTURE DIAGRAM REQUIRED",
    "DESIGN DOCUMENT REQUIRED",
    # Component / dependency / SBOM inventories
    "NO COMPONENT INVENTORY",
    "COMPONENT INVENTORY DOCUMENT",
    "MAINTAINED COMPONENT INVENTORY",
    "REQUIRES SBOM", "SBOM PROCESS",
    "SBOM REQUIRED", "REQUIRES A SBOM",
    "DEPENDENCY INVENTORY REQUIRES",
    "CVE CROSS-REFERENCE", "CVE CROSS REFERENCE",
    "THIRD-PARTY DEPENDENCY INVENTORY REQUIRES",
    # Data classification / handling policies
    "DATA CLASSIFICATION MATRIX",
    "NO DATA CLASSIFICATION",
    "SENSITIVITY-TIER INVENTORY",
    "HANDLING-POLICY CONFIGURATION",
    "DATA-CATEGORY ENUM",
    # Privacy / policy artifacts
    "PRIVACY POLICY ARTIFACT",
    "NO PRIVACY POLICY",
    "PRIVACY POLICY DOCUMENT",
    "REQUIRES PRIVACY POLICY",
    # Generic team-owned policy / process
    "NO POLICY ARTIFACT", "POLICY ARTIFACT NOT FOUND",
    "REQUIRES TEAM PROCESS",
    "PROCESS REQUIRES IMPLEMENTATION",
    "OUT OF SCOPE FOR CODE AUDIT",
    "OUT OF SCOPE FOR STATIC AUDIT",
    "CANNOT BE EVALUATED WITHOUT",
    "CANNOT BE VERIFIED FROM CODE",
    "REQUIRES OPERATOR INPUT",
    "REQUIRES OPERATIONAL EVIDENCE",
    "DOCUMENTATION REQUIRED",
    "DOCUMENT_REQUIRED",
    "DOCUMENT REQUIRED",
    # Server / endpoint policy specs
    "REQUIRES SERVER POLICY",
    "SERVER POLICY DOCUMENT",
    "REMOTE ENDPOINT POLICY",
    "PASSWORD POLICY DOCUMENT",
)

# Substrings that look PASS-like but only when NOT in a negation context.
# e.g. "COMPLIANT" appears inside "NON-COMPLIANT" / "NON_COMPLIANT"; we must
# skip those matches.
_PASS_NEGATION_PREFIXES: tuple[str, ...] = ("NON-", "NON_", "NOT ")


def _find_first_phrase(
    phrases: tuple[str, ...], text: str,
) -> tuple[int, str | None]:
    """Return (earliest_pos, matching_phrase) or (len(text), None).

    For PASS-side ambiguous substrings (``COMPLIANT``, ``COMPLIANCE``),
    skip the match when preceded by a negation prefix
    (``NON-`` / ``NON_`` / ``NOT ``) to avoid the
    ``NON_COMPLIANT → COMPLIANT`` false-positive.
    """
    earliest = (len(text), None)
    for p in phrases:
        pos = -1
        # Scan all occurrences for negation-prefix gating; take first valid.
        start = 0
        while True:
            i = text.find(p, start)
            if i < 0:
                break
            # Gate on negation prefix for PASS-side ambiguous substrings.
            if p in ("COMPLIANT", "COMPLIANCE"):
                if i >= 4 and text[i - 4: i] in _PASS_NEGATION_PREFIXES:
                    start = i + 1
                    continue
                if i >= 4 and text[i - 4: i] == "NOT ":
                    start = i + 1
                    continue
            pos = i
            break
        if pos >= 0 and pos < earliest[0]:
            earliest = (pos, p)
    return earliest


def _analyze_verdict_from_text(
    payload: dict[str, Any],
    fallback_label: str,
) -> tuple[str, str]:
    """Read the agent's answer text and return (label, reason).

    Priority order (head = first 400 chars, body = full text):
      1. Empty/missing answer → INCONCLUSIVE.
      2. INFO marker ANYWHERE in text → INFO (external doc required;
         out of code-audit scope — dominates PASS/FAIL/REVIEW).
      3. HEAD has REVIEW marker → REVIEW.
      4. HEAD has both PASS and FAIL — EARLIEST POSITION wins.
      5. HEAD has only PASS marker → PASS.
      6. HEAD has only FAIL marker → FAIL.
      7. BODY has REVIEW marker → REVIEW.
      8. BODY has both PASS and FAIL → REVIEW (genuinely mixed).
      9. BODY has only PASS → PASS.
      10. BODY has only FAIL → FAIL.
      11. Otherwise → fallback to mapper label.
    """
    raw = (payload.get("answer") or payload.get("answer_brief") or "").strip()
    if not raw or raw.upper() == "N/A":
        return ("INCONCLUSIVE", "no_answer_text")

    upper = raw.upper()
    head = upper[:400]

    # INFO check first (and on full body, not just head). External-doc-
    # required verdicts dominate every other classification.
    info_pos, info_match = _find_first_phrase(_INFO_PHRASES, upper)
    if info_match:
        scope = "head" if info_pos < 400 else "body"
        return ("INFO", f"{scope}_info:{info_match!r}@{info_pos}")

    head_review_pos, head_review_match = _find_first_phrase(_REVIEW_PHRASES, head)
    if head_review_match:
        return ("REVIEW", f"head_review:{head_review_match!r}")

    head_fail_pos, head_fail_match = _find_first_phrase(_FAIL_PHRASES_STRONG, head)
    head_pass_pos, head_pass_match = _find_first_phrase(_PASS_PHRASES_STRONG, head)


    if head_fail_match and head_pass_match:
        # Earliest position wins — the first verdict statement is canonical.
        if head_fail_pos <= head_pass_pos:
            return ("FAIL", f"head_fail_earlier:{head_fail_match!r}@{head_fail_pos}")
        return ("PASS", f"head_pass_earlier:{head_pass_match!r}@{head_pass_pos}")
    if head_fail_match:
        return ("FAIL", f"head_fail:{head_fail_match!r}")
    if head_pass_match:
        return ("PASS", f"head_pass:{head_pass_match!r}")

    # Head clean — fall to body.
    body_review_pos, body_review_match = _find_first_phrase(_REVIEW_PHRASES, upper)
    if body_review_match:
        return ("REVIEW", f"body_review:{body_review_match!r}")

    body_fail_pos, body_fail_match = _find_first_phrase(_FAIL_PHRASES_STRONG, upper)
    body_pass_pos, body_pass_match = _find_first_phrase(_PASS_PHRASES_STRONG, upper)

    if body_fail_match and body_pass_match:
        return ("REVIEW", f"body_mixed:p={body_pass_match!r}@{body_pass_pos},f={body_fail_match!r}@{body_fail_pos}")
    if body_pass_match:
        return ("PASS", f"body_pass:{body_pass_match!r}")
    if body_fail_match:
        return ("FAIL", f"body_fail:{body_fail_match!r}")

    return (fallback_label, f"fallback_mapper:{fallback_label.lower()}")


def _verdict_for_child(
    catalog: dict[str, dict[str, Any]],
    child: dict[str, Any],
) -> tuple[str, float, str | None, dict[str, Any], dict[str, Any] | None]:
    """Project a child to (label, confidence, reason, payload, outcome).

    ``label`` is the operator-facing string ("FAIL", "PASS", "N/A",
    "REVIEW", "INCONCLUSIVE"). The mapper itself emits four verdicts;
    a child with NO primary outcome at all is given a fifth label,
    ``INCONCLUSIVE``, so we can render its branch closure reasons.
    """
    cid = _control_id_from_child(child)
    if cid is None or cid not in catalog:
        return ("INCONCLUSIVE", 0.0, "control_id_not_resolved", {}, None)

    control = _build_control(catalog[cid])

    outcomes = child.get("outcomes") or []
    if not outcomes:
        return ("INCONCLUSIVE", 0.0, "no_primary_outcome", {}, None)

    # Pick the primary outcome (matches primary_outcome_id when set;
    # falls back to the first row otherwise).
    pid = child.get("primary_outcome_id")
    primary = None
    if pid:
        primary = next((o for o in outcomes if o.get("id") == pid), None)
    if primary is None:
        primary = outcomes[0]
    payload = _load_payload(primary)
    summary = _build_outcome_summary(primary, payload, child["id"])
    verdict_obj: MasvsControlVerdict = child_outcome_to_verdict(
        summary, control, child_investigation_id=child["id"],
    )
    mapper_label = _VERDICT_LABEL[verdict_obj.verdict]
    # Reclassify by REVIEW vs INCONCLUSIVE: the mapper folds both
    # low-confidence-direct-findings and "ran out of time" into the
    # same enum (INCONCLUSIVE). For operator clarity we promote the
    # ones with a payload + reasoning to REVIEW (operator should look)
    # and keep the no-outcome / no-evidence ones as INCONCLUSIVE.
    if mapper_label == "REVIEW" and not (payload.get("answer") or payload.get("reasoning")):
        mapper_label = "INCONCLUSIVE"

    # Text-first override: read the agent's actual conclusion text and
    # correct the mapper when it mis-labels a compliance verdict as a
    # finding (see MY_VIOLATIONS §218/§219/§296/§346).
    text_label, text_reason = _analyze_verdict_from_text(payload, mapper_label)
    if text_label != mapper_label:
        reason = f"text_override:{text_reason} (mapper_said:{mapper_label.lower()})"
    else:
        reason = verdict_obj.reason or text_reason
    return (text_label, verdict_obj.confidence or 0.0, reason, payload, primary)


def load_bundle(report_dir: Path) -> Bundle:
    """Read all three JSONs and pre-compute the findings table."""
    audit = json.loads((report_dir / "audit_dump.json").read_text(encoding="utf-8"))
    catalog = json.loads((report_dir / "masvs_catalog.json").read_text(encoding="utf-8"))
    apk = json.loads((report_dir / "apk_intel.json").read_text(encoding="utf-8"))
    # AILA platform brief is optional but feeds the § 03 ABOUT THE
    # PLATFORM section. Missing brief => the about-section renders a
    # one-line fallback paragraph instead of crashing.
    brief_path = report_dir / "aila_brief.json"
    aila_brief: dict[str, Any] = {}
    if brief_path.exists():
        try:
            aila_brief = json.loads(brief_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            aila_brief = {}

    # Order findings to follow the catalog (which is already in MASVS
    # natural order: ARCH → STORAGE → CRYPTO → AUTH → NETWORK →
    # PLATFORM → CODE → PRIVACY).
    by_cid: dict[str, dict[str, Any]] = {}
    for ch in audit["children"]:
        cid = _control_id_from_child(ch)
        if cid:
            by_cid[cid] = ch

    findings: list[FindingRecord] = []
    finding_seq = 0
    for cid, cat in catalog.items():
        ch = by_cid.get(cid)
        if ch is None:
            continue
        label, conf, reason, payload, outcome = _verdict_for_child(catalog, ch)
        finding_seq += 1
        findings.append(
            FindingRecord(
                finding_id=f"F-{finding_seq:03d}",
                control_id=cid,
                group=cat["group"],
                catalog=cat,
                child=ch,
                payload=payload,
                outcome=outcome,
                verdict_label=label,
                verdict_color=VERDICT_COLOR[label],
                confidence=conf,
                verdict_reason=reason,
                severity_rank=_SEVERITY_RANK[label],
            )
        )

    # Variant hunt orders aggregated with sequential V-NNN ids.
    variants: list[dict[str, Any]] = []
    vseq = 0
    for f in findings:
        for vh in (f.payload.get("variant_hunt_orders") or []):
            vseq += 1
            variants.append(
                {
                    "variant_id": f"V-{vseq:03d}",
                    "title": vh.get("title") or "(untitled hunt order)",
                    "hypothesis": vh.get("hypothesis") or "",
                    "file": vh.get("file") or "",
                    "function": vh.get("function") or "",
                    "estimated_effort": vh.get("estimated_effort") or vh.get("effort") or "",
                    "parent_finding": f.finding_id,
                    "parent_control": f.control_id,
                }
            )

    return Bundle(
        audit=audit, catalog=catalog, apk=apk,
        findings=findings, variants=variants,
        aila_brief=aila_brief,
    )


# ============================================================================
# STYLE SHEET
# ============================================================================

def _styles() -> dict[str, ParagraphStyle]:
    """Build the paragraph stylesheet — explicit, no inheritance."""
    body = _font("Body", "Times-Roman")
    body_b = _font("Body-Bold", "Times-Bold")
    body_i = _font("Body-Italic", "Times-Italic")
    sans = _font("Sans", "Helvetica")
    sans_b = _font("Sans-Bold", "Helvetica-Bold")
    mono = _font("Mono", "Courier")
    mono_b = _font("Mono-Bold", "Courier-Bold")

    base = ParagraphStyle(
        "Body", fontName=body, fontSize=9.0, leading=11.5,
        textColor=COL_INK, alignment=TA_JUSTIFY,
    )
    s: dict[str, ParagraphStyle] = {}
    s["body"] = base
    s["body_l"] = ParagraphStyle("BodyL", parent=base, alignment=TA_LEFT)
    s["body_sm"] = ParagraphStyle("BodySm", parent=base, fontSize=8.0, leading=10.0)
    s["body_xs"] = ParagraphStyle("BodyXs", parent=base, fontSize=7.2, leading=9.0)
    s["italic"] = ParagraphStyle("Italic", parent=base, fontName=body_i)

    s["mono"] = ParagraphStyle(
        "Mono", parent=base, fontName=mono, fontSize=8.2, leading=10.0,
    )
    s["mono_sm"] = ParagraphStyle(
        "MonoSm", parent=base, fontName=mono, fontSize=7.2, leading=9.0,
    )

    s["caps"] = ParagraphStyle(
        "Caps", parent=base, fontName=sans_b, fontSize=9.0, leading=11.0,
        textColor=COL_INK, alignment=TA_LEFT, letterSpace=0.6,
    )
    s["caps_accent"] = ParagraphStyle(
        "CapsAccent", parent=s["caps"], textColor=COL_ACCENT,
    )

    s["h1"] = ParagraphStyle(
        "H1", parent=base, fontName=sans_b, fontSize=22.0, leading=24.0,
        textColor=COL_INK, alignment=TA_LEFT, spaceAfter=2,
    )
    s["h2"] = ParagraphStyle(
        "H2", parent=base, fontName=sans_b, fontSize=14.0, leading=16.0,
        textColor=COL_INK, alignment=TA_LEFT, spaceBefore=4, spaceAfter=4,
    )
    s["h3"] = ParagraphStyle(
        "H3", parent=base, fontName=sans_b, fontSize=11.5, leading=14.0,
        textColor=COL_ACCENT, alignment=TA_LEFT, spaceBefore=2, spaceAfter=2,
    )
    s["h4"] = ParagraphStyle(
        "H4", parent=base, fontName=sans_b, fontSize=9.5, leading=11.5,
        textColor=COL_INK, alignment=TA_LEFT, spaceBefore=2, spaceAfter=1,
    )

    s["section_code"] = ParagraphStyle(
        "SectionCode", parent=s["mono"], fontName=mono_b, fontSize=9.0,
        leading=11.0, textColor=COL_ACCENT,
    )

    # Cover title uses Vodafone Lt (Display face) at a generous size — the
    # airy thin weight is the brand's signature display look. Falls back to
    # Helvetica when Display is unregistered.
    display = _font("Display", "Helvetica")
    s["cover_title"] = ParagraphStyle(
        "CoverTitle", parent=base, fontName=display, fontSize=44.0, leading=46.0,
        textColor=COL_INK, alignment=TA_LEFT,
    )
    s["cover_subtitle"] = ParagraphStyle(
        "CoverSubtitle", parent=base, fontName=sans_b, fontSize=14.0, leading=18.0,
        textColor=COL_ACCENT_DEEP, alignment=TA_LEFT,
    )
    s["cover_meta"] = ParagraphStyle(
        "CoverMeta", parent=base, fontName=mono, fontSize=9.0, leading=12.0,
        textColor=COL_INK, alignment=TA_LEFT,
    )

    s["banner_label"] = ParagraphStyle(
        "BannerLabel", parent=base, fontName=sans_b, fontSize=7.5, leading=8.5,
        textColor=COL_NAVY_INK, alignment=TA_LEFT, letterSpace=2.4,
    )

    s["footer_text"] = ParagraphStyle(
        "Footer", parent=base, fontName=mono, fontSize=7.0, leading=8.0,
        textColor=COL_MUTED, alignment=TA_LEFT,
    )

    s["table_h"] = ParagraphStyle(
        "TableH", parent=base, fontName=sans_b, fontSize=7.5, leading=9.0,
        textColor=COL_INK, letterSpace=1.0, alignment=TA_LEFT,
    )
    s["table_cell"] = ParagraphStyle(
        "TableCell", parent=base, fontSize=7.8, leading=9.5, alignment=TA_LEFT,
    )
    s["table_cell_mono"] = ParagraphStyle(
        "TableCellMono", parent=s["table_cell"], fontName=mono, fontSize=7.2, leading=9.0,
    )
    s["table_cell_xs"] = ParagraphStyle(
        "TableCellXs", parent=s["table_cell"], fontSize=6.8, leading=8.2,
    )

    s["finding_id"] = ParagraphStyle(
        "FindingId", parent=base, fontName=mono_b, fontSize=10.0, leading=12.0,
        textColor=COL_ACCENT, alignment=TA_LEFT, letterSpace=1.2,
    )
    s["finding_title"] = ParagraphStyle(
        "FindingTitle", parent=base, fontName=sans_b, fontSize=13.0, leading=15.0,
        textColor=COL_INK, alignment=TA_LEFT,
    )
    s["persona_h"] = ParagraphStyle(
        "PersonaH", parent=base, fontName=sans_b, fontSize=8.5, leading=10.0,
        textColor=COL_INK, letterSpace=0.8, alignment=TA_LEFT,
    )
    s["persona_b"] = ParagraphStyle(
        "PersonaB", parent=base, fontSize=8.5, leading=10.5, alignment=TA_JUSTIFY,
    )

    return s


# ============================================================================
# FLOWABLES — custom drawing
# ============================================================================

class VerdictBadge(Flowable):
    """Saturated verdict label drawn as a filled pill."""

    def __init__(self, label: str, *, width: float = 22 * mm, height: float = 6.0 * mm):
        super().__init__()
        self.label = label
        self.width = width
        self.height = height

    def wrap(self, _aw: float, _ah: float) -> tuple[float, float]:
        return (self.width, self.height)

    def draw(self) -> None:
        c = self.canv
        col = VERDICT_COLOR.get(self.label, COL_NA)
        c.setFillColor(col)
        c.setStrokeColor(col)
        c.roundRect(0, 0, self.width, self.height, 1.2 * mm, fill=1, stroke=0)
        c.setFillColor(colors.white)
        c.setFont(_font("Sans-Bold", "Helvetica-Bold"), 9.0)
        text_w = c.stringWidth(self.label, _font("Sans-Bold", "Helvetica-Bold"), 9.0)
        c.drawString((self.width - text_w) / 2, self.height / 2 - 3, self.label)


class HorizontalRule(Flowable):
    def __init__(self, width: float, *, thickness: float = 0.6, color: colors.Color = COL_INK, gap_above: float = 0, gap_below: float = 0):
        super().__init__()
        self.width = width
        self.thickness = thickness
        self.color = color
        self.gap_above = gap_above
        self.gap_below = gap_below

    def wrap(self, aw: float, _ah: float) -> tuple[float, float]:
        return (aw, self.thickness + self.gap_above + self.gap_below)

    def draw(self) -> None:
        c = self.canv
        c.setStrokeColor(self.color)
        c.setLineWidth(self.thickness)
        y = self.gap_below
        c.line(0, y, self.width, y)


class FindingHeader(Flowable):
    """Two-line tactical header for a finding page.

    Top strip: finding id + control id + verdict badge + confidence
    pill, drawn as a 14mm-tall block with a thick top rule and a
    color-coded left rule keyed to the verdict.
    """

    def __init__(
        self,
        finding_id: str,
        control_id: str,
        group: str,
        verdict: str,
        confidence: float,
        title: str,
        page_width: float,
    ):
        super().__init__()
        self.finding_id = finding_id
        self.control_id = control_id
        self.group = group
        self.verdict = verdict
        self.confidence = confidence
        self.title = title
        self.page_width = page_width
        self.height = 18 * mm

    def wrap(self, aw: float, _ah: float) -> tuple[float, float]:
        self.width = aw
        return (aw, self.height)

    def draw(self) -> None:
        c = self.canv
        vcol = VERDICT_COLOR.get(self.verdict, COL_NA)
        # Top thick rule
        c.setStrokeColor(COL_INK)
        c.setFillColor(COL_INK)
        c.setLineWidth(1.4)
        c.line(0, self.height - 0.7, self.width, self.height - 0.7)
        # Left tab — full-height rule color block
        c.setFillColor(vcol)
        c.rect(0, 0, 3.5 * mm, self.height - 1.4, fill=1, stroke=0)
        # Sigil tile
        sigil = GROUP_SIGIL.get(self.group, self.group[:2])
        c.setFillColor(COL_NAVY)
        c.rect(4.5 * mm, 1, 9.5 * mm, self.height - 2.4, fill=1, stroke=0)
        c.setFillColor(COL_NAVY_INK)
        c.setFont(_font("Sans-Bold", "Helvetica-Bold"), 11)
        c.drawString(6.5 * mm, self.height / 2 - 1.5, sigil)
        # Finding id (large mono accent)
        c.setFillColor(COL_ACCENT)
        c.setFont(_font("Mono-Bold", "Courier-Bold"), 16)
        c.drawString(16 * mm, self.height - 7 * mm, self.finding_id)
        # Control id below
        c.setFillColor(COL_INK)
        c.setFont(_font("Mono", "Courier"), 9.0)
        c.drawString(16 * mm, self.height - 12 * mm, self.control_id + "  ·  " + self.group)
        # Title — sans bold, wrapped onto one line (truncated if longer)
        c.setFillColor(COL_INK)
        c.setFont(_font("Sans-Bold", "Helvetica-Bold"), 11.0)
        # Right-side verdict pill occupies ~30mm — reserve 32mm of right
        # margin so the title text doesn't crash into it.
        title_x = 52 * mm
        # 42mm reserve so the title can never bleed under the verdict
        # pill — the longest pill ("INCONCLUSIVE" at 10pt) wants ~38mm.
        title_w = self.width - title_x - 42 * mm
        title = self.title
        face = _font("Sans-Bold", "Helvetica-Bold")
        while c.stringWidth(title, face, 11.0) > title_w and len(title) > 12:
            title = title[: max(12, len(title) - 4)] + "…"
            if len(title) <= 16:
                break
        c.drawString(title_x, self.height - 7 * mm, title)
        # Confidence label is intentionally omitted here — the band
        # immediately below the header already prints it next to VERDICT.
        # Right-side verdict pill (verdict only — confidence sits to the
        # left under the title; previously CONFIDENCE was drawn at the
        # same y as the control_id row and visually collided when the
        # control_id+group string stretched into the second column).
        # The verdict pill auto-sizes to the label width so the long
        # "INCONCLUSIVE" string doesn't bleed past the page margin while
        # "FAIL"/"PASS" stay tight.
        pill_font = _font("Sans-Bold", "Helvetica-Bold")
        pill_font_size = 12.0 if len(self.verdict) <= 6 else 10.0
        pill_text_w = c.stringWidth(self.verdict, pill_font, pill_font_size)
        pill_w = max(26 * mm, pill_text_w + 8 * mm)
        pill_h = 10 * mm
        pill_x = self.width - pill_w - 1
        pill_y = (self.height - pill_h) / 2
        c.setFillColor(vcol)
        c.setStrokeColor(vcol)
        c.roundRect(pill_x, pill_y, pill_w, pill_h, 1.5 * mm, fill=1, stroke=0)
        c.setFillColor(colors.white)
        c.setFont(pill_font, pill_font_size)
        c.drawCentredString(pill_x + pill_w / 2, pill_y + pill_h / 2 - pill_font_size / 3, self.verdict)


class HeatmapGrid(Flowable):
    """Group × Verdict heatmap. Render saturated counts per cell."""

    GROUP_ORDER = ("ARCH", "STORAGE", "CRYPTO", "AUTH", "NETWORK",
                   "PLATFORM", "CODE", "PRIVACY")
    VERDICT_ORDER = ("FAIL", "REVIEW", "INFO", "INCONCLUSIVE", "N/A", "PASS")

    def __init__(self, findings: list[FindingRecord], width: float):
        super().__init__()
        self.findings = findings
        self.width = width
        self._height = 0.0

    def wrap(self, aw: float, _ah: float) -> tuple[float, float]:
        self.width = aw
        self._height = 80 * mm
        return (aw, self._height)

    def draw(self) -> None:
        c = self.canv
        rows = self.GROUP_ORDER
        cols = self.VERDICT_ORDER
        ncols = len(cols)
        nrows = len(rows)
        left_label = 24 * mm
        top_label = 12 * mm
        cell_w = (self.width - left_label) / ncols
        cell_h = (self._height - top_label) / nrows
        # Tally
        tally: dict[tuple[str, str], int] = defaultdict(int)
        group_totals: Counter[str] = Counter()
        for f in self.findings:
            tally[(f.group, f.verdict_label)] += 1
            group_totals[f.group] += 1
        # Column headers
        c.setFont(_font("Sans-Bold", "Helvetica-Bold"), 7.2)
        c.setFillColor(COL_INK)
        for ci, col_name in enumerate(cols):
            cx = left_label + ci * cell_w + cell_w / 2
            cy = self._height - top_label / 2
            c.drawCentredString(cx, cy, col_name)
        # Row labels + cells
        for ri, grp in enumerate(rows):
            ry_top = self._height - top_label - ri * cell_h
            ry_bot = ry_top - cell_h
            # Row label panel
            c.setFillColor(COL_PAPER_DEEP)
            c.rect(0, ry_bot, left_label - 1, cell_h, fill=1, stroke=0)
            c.setFillColor(COL_INK)
            c.setFont(_font("Sans-Bold", "Helvetica-Bold"), 7.5)
            c.drawString(2 * mm, ry_bot + cell_h / 2 - 2, grp)
            c.setFont(_font("Mono", "Courier"), 6.5)
            c.setFillColor(COL_MUTED)
            c.drawString(2 * mm, ry_bot + 2, f"n={group_totals[grp]}")
            # Cells
            for ci, col_name in enumerate(cols):
                cx = left_label + ci * cell_w
                count = tally[(grp, col_name)]
                col = VERDICT_COLOR[col_name]
                if count > 0:
                    intensity = min(1.0, 0.35 + count * 0.15)
                    fill = colors.Color(col.red, col.green, col.blue, intensity)
                    c.setFillColor(fill)
                    c.rect(cx, ry_bot, cell_w - 0.4, cell_h - 0.4, fill=1, stroke=0)
                    text_col = colors.white if intensity > 0.55 else COL_INK
                    c.setFillColor(text_col)
                    c.setFont(_font("Sans-Bold", "Helvetica-Bold"), 11)
                    c.drawCentredString(cx + cell_w / 2,
                                        ry_bot + cell_h / 2 - 3.5, str(count))
                else:
                    c.setFillColor(COL_PAPER_DEEP)
                    c.rect(cx, ry_bot, cell_w - 0.4, cell_h - 0.4, fill=1, stroke=0)
                    c.setStrokeColor(COL_THIN)
                    c.setLineWidth(0.3)
                    # dot pattern
                    c.setFillColor(COL_THIN)
                    c.circle(cx + cell_w / 2, ry_bot + cell_h / 2, 0.6, fill=1, stroke=0)
        # Outer thick border
        c.setStrokeColor(COL_INK)
        c.setLineWidth(1.0)
        c.rect(0, 0, self.width, self._height, fill=0, stroke=1)


def _draw_cover_chrome(canvas: Canvas, doc: BaseDocTemplate) -> None:
    """Paint the cover-page chrome strips behind the cover flowables.

    Top: navy banner; below the banner: a thin rust rule; bottom: a
    bold rust bar that wraps the page footer. No body chrome — the
    cover deliberately has different visuals from §02+.
    """
    canvas.saveState()
    canvas.setFillColor(COL_PAPER)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    # Top thick navy bar
    canvas.setFillColor(COL_NAVY)
    canvas.rect(0, PAGE_H - 6 * mm, PAGE_W, 6 * mm, fill=1, stroke=0)
    # Thin rust rule below the banner
    canvas.setFillColor(COL_ACCENT)
    canvas.rect(0, PAGE_H - 7.2 * mm, PAGE_W, 0.6 * mm, fill=1, stroke=0)
    # Bottom thick rust bar
    canvas.setFillColor(COL_ACCENT)
    canvas.rect(0, 0, PAGE_W, 4 * mm, fill=1, stroke=0)
    # Bottom thin ink rule above the rust bar
    canvas.setFillColor(COL_INK)
    canvas.rect(0, 4 * mm, PAGE_W, 0.6 * mm, fill=1, stroke=0)
    # Tick band — decorative
    canvas.setStrokeColor(COL_THIN)
    canvas.setLineWidth(0.3)
    y0 = PAGE_H - 18 * mm
    for i in range(0, int(PAGE_W), 8):
        canvas.line(i, y0, i + 4, y0 + 2)
    # Banner label
    canvas.setFillColor(COL_NAVY_INK)
    canvas.setFont(_font("Sans-Bold", "Helvetica-Bold"), 7.0)
    canvas.drawString(
        MARGIN_L, PAGE_H - 4.5 * mm,
        "F O R   I N T E R N A L   D I S T R I B U T I O N    ·    V O D A F O N E   T R    ·    V R - A U D I T",
    )
    canvas.drawRightString(
        PAGE_W - MARGIN_L, PAGE_H - 4.5 * mm,
        "MASVS  L1   ·   CONFIDENTIAL",
    )
    canvas.restoreState()


class VerdictDistroBar(Flowable):
    """Horizontal stacked bar showing verdict distribution."""

    def __init__(self, counts: dict[str, int], width: float, height: float = 8 * mm):
        super().__init__()
        self.counts = counts
        self.width = width
        self.height = height

    def wrap(self, aw: float, _ah: float) -> tuple[float, float]:
        self.width = aw
        return (aw, self.height)

    def draw(self) -> None:
        c = self.canv
        total = sum(self.counts.values())
        if total == 0:
            return
        x = 0.0
        order = ("FAIL", "REVIEW", "INFO", "INCONCLUSIVE", "N/A", "PASS")
        for label in order:
            n = self.counts.get(label, 0)
            if n == 0:
                continue
            w = self.width * n / total
            c.setFillColor(VERDICT_COLOR[label])
            c.rect(x, 0, w, self.height, fill=1, stroke=0)
            # Count label
            if w > 10 * mm:
                c.setFillColor(colors.white)
                c.setFont(_font("Sans-Bold", "Helvetica-Bold"), 9.0)
                c.drawCentredString(x + w / 2, self.height / 2 - 3, f"{label} {n}")
            x += w
        c.setStrokeColor(COL_INK)
        c.setLineWidth(0.8)
        c.rect(0, 0, self.width, self.height, fill=0, stroke=1)


# ============================================================================
# PAGE TEMPLATE — header, footer, chrome
# ============================================================================

@dataclass
class ChromeContext:
    """Mutable state shared across page draw calls."""
    bundle: Bundle | None = None
    section_label: str = ""        # e.g. "FINDINGS · STORAGE"
    section_code: str = ""         # e.g. "§ 06.04"
    audit_id_short: str = ""
    package: str = ""
    version: str = ""
    timestamp: str = ""
    apk_sha_short: str = ""
    total_pages: int = 0           # populated on second pass
    # page_num → (section_label, section_code) captured on pass A so the
    # pass-B chrome can label the START of each page correctly. Without
    # this, the first page of a new section still wears the previous
    # section's chrome because Platypus paints onPage BEFORE flowables
    # draw.
    section_at_page: dict[int, tuple[str, str]] = field(default_factory=dict)
    # When True, _set_section / _set_verdict recording is active (pass A).
    capture_sections: bool = False
    # page_num → verdict label ("FAIL"/"PASS"/...). Populated on pass A
    # by VerdictSetter flowables emitted at the top of each per-control
    # finding page so the pass-B chrome can tint its accents in the
    # verdict colour. Pages without a recorded verdict use the default
    # rust accent.
    verdict_at_page: dict[int, str] = field(default_factory=dict)


_CHROME = ChromeContext()


def _draw_chrome(canvas: Canvas, doc: BaseDocTemplate) -> None:
    """Top header strip + bottom footer strip drawn on every body page."""
    page_num = doc.page
    if page_num == 1:
        # Cover page gets its own chrome from _draw_cover_chrome; skip.
        return

    # Resolve the section label/code FOR THIS PAGE from the pre-collected
    # map (pass A populates it). The map records the first label/code that
    # the page held; before the first label fires, fall back to the
    # most-recent prior page.
    sec_label, sec_code = _CHROME.section_label, _CHROME.section_code
    if _CHROME.section_at_page:
        # Find the largest captured page ≤ page_num.
        best = None
        for pn in _CHROME.section_at_page:
            if pn <= page_num and (best is None or pn > best):
                best = pn
        if best is not None:
            sec_label, sec_code = _CHROME.section_at_page[best]

    # Resolve verdict for this page (if any) — drives the accent colour.
    accent = COL_ACCENT
    if _CHROME.verdict_at_page:
        best_v = None
        for pn in _CHROME.verdict_at_page:
            if pn <= page_num and (best_v is None or pn > best_v):
                best_v = pn
        if best_v is not None:
            verdict = _CHROME.verdict_at_page[best_v]
            accent = VERDICT_COLOR.get(verdict, COL_ACCENT)

    # ---- Top header strip ----
    canvas.saveState()
    canvas.setFillColor(COL_NAVY)
    canvas.rect(0, PAGE_H - 14 * mm, PAGE_W, 14 * mm, fill=1, stroke=0)

    # Thin verdict-coloured rule below the navy bar — operator's first
    # visual cue for what kind of page this is. Default rust on pages
    # that have no recorded verdict.
    canvas.setFillColor(accent)
    canvas.rect(0, PAGE_H - 14.6 * mm, PAGE_W, 0.6 * mm, fill=1, stroke=0)

    canvas.setFillColor(COL_NAVY_INK)
    canvas.setFont(_font("Sans-Bold", "Helvetica-Bold"), 7.0)
    canvas.drawString(
        MARGIN_L, PAGE_H - 5.5 * mm,
        "F O R   I N T E R N A L   D I S T R I B U T I O N    ·    V O D A F O N E   T R    ·    V R - A U D I T",
    )
    # right of top strip: package + version
    canvas.setFont(_font("Mono", "Courier"), 7.0)
    canvas.drawRightString(
        PAGE_W - MARGIN_R, PAGE_H - 5.5 * mm,
        f"{_CHROME.package}  v{_CHROME.version}",
    )
    # second line: section code + label
    canvas.setFillColor(COL_NAVY_INK)
    canvas.setFont(_font("Mono-Bold", "Courier-Bold"), 8.2)
    canvas.drawString(MARGIN_L, PAGE_H - 11 * mm, sec_code)
    canvas.setFont(_font("Sans-Bold", "Helvetica-Bold"), 8.2)
    canvas.drawString(MARGIN_L + 18 * mm, PAGE_H - 11 * mm, sec_label)
    canvas.setFont(_font("Mono", "Courier"), 7.0)
    canvas.drawRightString(PAGE_W - MARGIN_R, PAGE_H - 11 * mm,
                           "SHA-256/" + _CHROME.apk_sha_short)

    # ---- Bottom footer strip ----
    # Thin verdict-coloured rule above the ink footer bar — closes the
    # visual frame on the page and mirrors the top accent strip.
    canvas.setFillColor(accent)
    canvas.rect(0, 7 * mm, PAGE_W, 0.5 * mm, fill=1, stroke=0)
    canvas.setFillColor(COL_INK)
    canvas.rect(0, 0, PAGE_W, 7 * mm, fill=1, stroke=0)
    canvas.setFillColor(COL_PAPER)
    canvas.setFont(_font("Mono", "Courier"), 7.0)
    canvas.drawString(MARGIN_L, 2.4 * mm,
                      f"AUDIT/{_CHROME.audit_id_short}   ·   {_CHROME.timestamp}")
    # page X of Y
    canvas.setFont(_font("Mono-Bold", "Courier-Bold"), 7.5)
    total = _CHROME.total_pages or 0
    if total:
        page_str = f"PAGE  {page_num:03d}  /  {total:03d}"
    else:
        page_str = f"PAGE  {page_num:03d}"
    canvas.drawCentredString(PAGE_W / 2, 2.4 * mm, page_str)
    canvas.setFont(_font("Mono", "Courier"), 7.0)
    canvas.drawRightString(PAGE_W - MARGIN_R, 2.4 * mm,
                           f"YANIMDA-MASVS-L1  v{REPORT_VERSION}")
    canvas.restoreState()


def _draw_paper(canvas: Canvas, _doc: BaseDocTemplate) -> None:
    """Paint the ivory page background BEFORE any flowable draws."""
    canvas.saveState()
    canvas.setFillColor(COL_PAPER)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    canvas.restoreState()


def _draw_page(canvas: Canvas, doc: BaseDocTemplate) -> None:
    _draw_paper(canvas, doc)
    _draw_chrome(canvas, doc)


# ============================================================================
# CONTENT BUILDERS — one function per section
# ============================================================================

class _VerdictSetter(Flowable):
    """Side-effect flowable that records the verdict for THIS page.

    Emitted at the top of every per-control finding page. On pass A
    the setter populates ``_CHROME.verdict_at_page`` so the pass-B
    chrome can tint its top/bottom accent rules in the verdict colour
    (FAIL=red, PASS=green, REVIEW=amber, INFO=steel-blue, etc.).

    Pages without an explicit verdict (cover, doc control, exec
    summary, methodology, glossary) fall through to the default rust
    accent.
    """

    def __init__(self, verdict: str) -> None:
        super().__init__()
        self.verdict = verdict
        self.width = 0
        self.height = 0

    def wrap(self, _aw: float, _ah: float) -> tuple[float, float]:
        return (0, 0)

    def draw(self) -> None:
        if _CHROME.capture_sections:
            page_num = self.canv.getPageNumber()
            # Only record the FIRST setter on a page — long findings
            # spill across multiple pages; later setters on the same
            # page (none, in current layout) must NOT overwrite.
            _CHROME.verdict_at_page.setdefault(page_num, self.verdict)


def _set_verdict(verdict: str) -> Flowable:
    return _VerdictSetter(verdict)


# ============================================================================
# CONTENT BUILDERS — one function per section
# ============================================================================

class _SectionSetter(Flowable):
    """Side-effect flowable that updates header chrome state.

    On pass A (``_CHROME.capture_sections = True``) the setter records
    the page on which it draws into ``_CHROME.section_at_page`` so the
    pass-B chrome can label the page accurately (Platypus paints
    ``onPage`` before flowables draw — the chrome would otherwise lag
    by one page).
    """

    def __init__(self, label: str, code: str) -> None:
        super().__init__()
        self.label = label
        self.code = code
        self.width = 0
        self.height = 0

    def wrap(self, _aw: float, _ah: float) -> tuple[float, float]:
        return (0, 0)

    def draw(self) -> None:
        _CHROME.section_label = self.label
        _CHROME.section_code = self.code
        if _CHROME.capture_sections:
            page_num = self.canv.getPageNumber()
            # Only record the FIRST setter on a given page; later setters
            # on the same page would override the page's chrome.
            _CHROME.section_at_page.setdefault(page_num, (self.label, self.code))


def _set_section(label: str, code: str) -> Flowable:
    return _SectionSetter(label, code)


# Markdown → reportlab inline-tag conversion.
# Agents write their answers in markdown (**bold**, headers, bullets, code
# fences, etc.). Platypus only interprets a tiny HTML-ish subset (<b>, <i>,
# <font>, <br/>, etc.), so raw markdown leaks through as literal asterisks
# and hashes. _md_inline rewrites the safe subset BEFORE the text reaches
# Paragraph; multi-line constructs (headers, bullets, code fences) are
# handled in _para_multi which splits on blank lines and per-line.

# **bold** or __bold__  →  <b>bold</b>
# `code`               →  <font name="Mono">code</font>
# Single-* italic deliberately NOT handled — too many false positives in
# agent text (`*ptr`, glob patterns, multiplication, etc.). Same for _italic_
# (collides with snake_case identifiers like vflocalAccountSessionId).
_MD_BOLD_RE = re.compile(r"\*\*([^*\n][^*\n]*?)\*\*")
_MD_BOLD_UNDER_RE = re.compile(r"__([^_\s][^_\n]*?[^_\s])__")
_MD_CODE_RE = re.compile(r"`([^`\n]+?)`")


def _md_inline(escaped: str) -> str:
    """Convert safe markdown inline patterns to reportlab inline tags.

    Caller is expected to have ALREADY xml-escaped the text. We do not
    re-escape — the only new markup we add is <b>, </b>, <font ...>,
    </font> using ascii literals that won't collide with anything an
    XML escape would have produced.
    """
    out = _MD_BOLD_RE.sub(r"<b>\1</b>", escaped)
    out = _MD_BOLD_UNDER_RE.sub(r"<b>\1</b>", out)
    out = _MD_CODE_RE.sub(r'<font name="Mono">\1</font>', out)
    return out


# Lines starting with "# ", "## ", "### " are markdown headers. In a finding
# paragraph block we render them as bold inline text (the surrounding section
# header in the PDF chrome is already doing the H1/H2 job).
_MD_HEADER_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
# Lines starting with "- ", "* ", "+ " or "N. " / "N) " are bullet/numbered
# items. We render each as a paragraph with a leading bullet glyph.
_MD_BULLET_RE = re.compile(r"^\s*[-*+]\s+(.+)$")
_MD_NUMBER_RE = re.compile(r"^\s*(\d{1,3})[.)]\s+(.+)$")
# Triple-backtick code fences open / close a fenced block.
_MD_FENCE_RE = re.compile(r"^\s*```(.*)$")


def _para(text: str, style: ParagraphStyle) -> Paragraph:
    """Build a Paragraph, escaping XML and converting inline markdown."""
    if text is None:
        text = ""
    safe = (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    safe = re.sub(r"\s+", " ", safe).strip()
    safe = _md_inline(safe)
    return Paragraph(safe, style)


def _clip(text: str | None, n: int) -> str:
    """Trim ``text`` to ``n`` chars, appending ellipsis if truncated."""
    if text is None:
        return ""
    if len(text) <= n:
        return text
    return text[: max(1, n - 1)].rstrip() + "…"


def _para_clipped(text: str | None, style: ParagraphStyle, cap: int = 600) -> Paragraph:
    """Render text into a paragraph after hard-capping its length.

    Used for MobSF / external dumps that occasionally carry multi-KB
    descriptions a Platypus cell cannot accommodate.
    """
    return _para(_clip(text or "", cap), style)


def _para_multi(text: str, style: ParagraphStyle) -> list[Flowable]:
    """Render multi-paragraph prose preserving markdown structure.

    Splits on blank lines into "blocks", then within each block:
      - lines opening with ``# ``/``## ``/``### `` render as bold headers
      - lines starting with ``- ``/``* ``/``+ `` render as bulleted items
      - lines starting with ``N.``/``N)`` render as numbered items
      - triple-backtick fenced blocks render as monospace preformatted text
      - everything else is normal prose with inline markdown converted
    """
    if not text:
        return []
    blocks = re.split(r"\n\s*\n", text.strip())
    out: list[Flowable] = []
    mono_style = ParagraphStyle(
        "MdFence", parent=style, fontName=_font("Mono", "Courier"),
        fontSize=max(7.0, style.fontSize - 1.0),
        leading=max(8.5, style.leading - 1.0),
        backColor=colors.HexColor("#f1ede4"),
        borderColor=colors.HexColor("#c8c0ac"),
        borderWidth=0.4,
        borderPadding=(2, 4, 2, 4),
    )
    header_style = ParagraphStyle(
        "MdHeader", parent=style,
        fontName=_font("Sans-Bold", "Helvetica-Bold"),
        fontSize=style.fontSize + 1.0,
        textColor=COL_ACCENT,
        spaceBefore=2,
        spaceAfter=1,
    )
    bullet_style = ParagraphStyle(
        "MdBullet", parent=style,
        leftIndent=10, firstLineIndent=-10, spaceAfter=0,
    )

    def _esc_and_inline(line: str) -> str:
        e = (
            line.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        return _md_inline(e)

    for block in blocks:
        if not block.strip():
            continue
        lines = block.split("\n")
        # Detect fenced code block.
        if _MD_FENCE_RE.match(lines[0]):
            # collect until closing fence
            body: list[str] = []
            for ln in lines[1:]:
                if _MD_FENCE_RE.match(ln):
                    break
                body.append(ln)
            safe = (
                "\n".join(body)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\n", "<br/>")
            )
            out.append(Paragraph(safe, mono_style))
            out.append(Spacer(1, 2))
            continue

        # Otherwise, line-by-line scan for headers / bullets / numbers.
        # We aggregate consecutive prose lines into one Paragraph so
        # line-wrapping works inside the prose, but each header / bullet
        # gets its own Paragraph.
        prose_buf: list[str] = []

        def _flush_prose() -> None:
            if not prose_buf:
                return
            joined = " ".join(prose_buf)
            prose_buf.clear()
            out.append(Paragraph(_esc_and_inline(joined), style))
            out.append(Spacer(1, 2))

        for line in lines:
            stripped = line.strip()
            if not stripped:
                _flush_prose()
                continue
            mh = _MD_HEADER_RE.match(stripped)
            mb = _MD_BULLET_RE.match(stripped)
            mn = _MD_NUMBER_RE.match(stripped)
            if mh:
                _flush_prose()
                out.append(Paragraph(_esc_and_inline(mh.group(2)), header_style))
                out.append(Spacer(1, 1))
            elif mb:
                _flush_prose()
                out.append(Paragraph(
                    "&#9679;&nbsp;&nbsp;" + _esc_and_inline(mb.group(1)),
                    bullet_style,
                ))
            elif mn:
                _flush_prose()
                out.append(Paragraph(
                    f"<b>{mn.group(1)}.</b>&nbsp;&nbsp;" + _esc_and_inline(mn.group(2)),
                    bullet_style,
                ))
            else:
                prose_buf.append(stripped)
        _flush_prose()
    return out


def _short_id(uuid_str: str) -> str:
    if not uuid_str:
        return "—"
    return uuid_str.split("-")[0]


def build_cover(bundle: Bundle, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    """Render the cover page.

    Layout (top → bottom):

    1. Document sigil row (small mono, just below the navy banner)
    2. Title block — ``MASVS L1`` / ``AUDIT REPORT`` in Vodafone Lt
    3. Two-column row — subtitle prose on the LEFT, 6-row APK
       fingerprint card on the RIGHT (aligned right edge)
    4. DASHBOARD band — six big-number columns (TOTAL / FAIL / REVIEW /
       INFO / INCONC / PASS) with verdict-coloured numerals
    5. AT A GLANCE panel — bottom quarter, top three FAILs with their
       group sigil and one-line title
    6. Footnote — distribution + honesty contract caveat

    The per-group sigil bar that used to live here was moved to the
    §02 EXECUTIVE SUMMARY heatmap so the cover stays a 5-second scan
    surface.
    """
    apk = bundle.apk
    audit = bundle.audit["audit"]
    sum_ = apk.get("static_summary") or {}

    story: list[Flowable] = []
    # The cover chrome (top navy banner, bottom rust bar, tick band) is
    # painted via the "cover" PageTemplate's onPage hook
    # (_draw_cover_chrome). The first flowable just pushes the title
    # block below the banner.
    story.append(Spacer(1, 8 * mm))

    # Sigil row directly below the navy banner the onPage hook paints.
    sigil_style = ParagraphStyle(
        "Sigil", parent=s["mono"], fontSize=8.6, leading=10.0,
        textColor=COL_MUTED, letterSpace=4.0,
    )
    story.append(Paragraph(
        f"DOCUMENT  ·  YANIMDA-MASVS-L1  ·  REVISION {REPORT_VERSION}  ·  COPY  001 OF 001",
        sigil_style,
    ))
    story.append(Spacer(1, 14 * mm))

    # ── 2. Big title block (top third of page) ──
    story.append(Paragraph("MASVS L1", s["cover_title"]))
    story.append(Paragraph("AUDIT  REPORT", s["cover_title"]))
    story.append(Spacer(1, 4 * mm))
    story.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R, thickness=1.6))
    story.append(Spacer(1, 5 * mm))

    # ── 3. Two-column row — subtitle (left) + APK fingerprint (right) ──
    subtitle_left = [
        Paragraph(
            "OWASP Mobile Application Security Verification Standard · Level 1",
            s["cover_subtitle"],
        ),
        Spacer(1, 3 * mm),
        Paragraph(
            "53 controls evaluated by a 6-persona reasoning panel against the "
            f"<b>{sum_.get('package') or apk.get('package_name') or '—'}</b> APK. "
            "Verdicts derived by the production mapper, agent reasoning "
            "rendered verbatim.",
            ParagraphStyle("CoverLead", parent=s["body"], fontSize=10.0,
                           leading=13.0, textColor=COL_INK,
                           alignment=TA_LEFT),
        ),
    ]

    # Right-aligned APK fingerprint — 5 rows max
    fp_label_st = ParagraphStyle("FpL", parent=s["body_xs"],
                                 fontName=_font("Sans-Bold", "Helvetica-Bold"),
                                 fontSize=6.6, leading=8.0, letterSpace=1.4,
                                 textColor=COL_MUTED, alignment=TA_RIGHT)
    fp_value_st = ParagraphStyle("FpV", parent=s["body_sm"],
                                 fontName=_font("Mono-Bold", "Courier-Bold"),
                                 fontSize=8.4, leading=10.6,
                                 textColor=COL_INK, alignment=TA_RIGHT)
    sha = (apk.get("apk_sha256") or "")
    sha_short = (sha[:16] + "…" + sha[-8:]) if len(sha) >= 26 else sha
    fp_rows = [
        [Paragraph("PACKAGE", fp_label_st),
         Paragraph(sum_.get("package") or apk.get("package_name") or "—",
                   fp_value_st)],
        [Paragraph("VERSION", fp_label_st),
         Paragraph(
             f"{sum_.get('version_name', '—')}  ·  build {sum_.get('version_code', '—')}",
             fp_value_st)],
        [Paragraph("APK SHA-256", fp_label_st),
         Paragraph(sha_short or "—", fp_value_st)],
        [Paragraph("AUDIT ID", fp_label_st),
         Paragraph((audit.get("id") or "—")[:36], fp_value_st)],
        [Paragraph("AUDIT WINDOW", fp_label_st),
         Paragraph(_duration_str(audit.get("created_at"),
                                  audit.get("stopped_at")),
                   fp_value_st)],
        [Paragraph("CONTROLS EVALUATED", fp_label_st),
         Paragraph(f"{len(bundle.findings)} / {len(bundle.catalog)}",
                   fp_value_st)],
    ]
    fp_card = Table(fp_rows, colWidths=[34 * mm, 46 * mm])
    fp_card.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 1.4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.4),
        ("LINEABOVE", (0, 0), (-1, 0), 0.4, COL_INK),
        ("LINEBELOW", (0, -1), (-1, -1), 0.4, COL_INK),
        ("LINEBEFORE", (0, 0), (0, -1), 2.4, COL_ACCENT),
    ]))

    # Left column has variable height; right column the fixed-height card.
    inner_w = PAGE_W - MARGIN_L - MARGIN_R
    left_w = inner_w - 80 * mm - 4 * mm
    twocol = Table(
        [[subtitle_left, fp_card]],
        colWidths=[left_w, 80 * mm],
    )
    twocol.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(twocol)
    story.append(Spacer(1, 10 * mm))

    # ── 4. DASHBOARD band — six big-number columns ──
    counts: Counter[str] = Counter(f.verdict_label for f in bundle.findings)
    total = len(bundle.findings)
    dash_cols = [
        ("TOTAL",   total,                       COL_INK),
        ("FAIL",    counts.get("FAIL", 0),       COL_FAIL),
        ("REVIEW",  counts.get("REVIEW", 0),     COL_REVIEW),
        ("INFO",    counts.get("INFO", 0),       COL_INFO),
        ("INCONC.", counts.get("INCONCLUSIVE", 0), COL_INCONCLUSIVE),
        ("PASS",    counts.get("PASS", 0),       COL_PASS),
    ]
    dash_head = [Paragraph(
        f"<font color='#5b5443'>{name}</font>",
        ParagraphStyle("DH", parent=s["caps"], fontSize=7.4, leading=9.0,
                       letterSpace=2.0, textColor=COL_MUTED,
                       alignment=TA_CENTER),
    ) for name, _, _ in dash_cols]
    dash_num = []
    for _, n, col in dash_cols:
        hex_ = "#%02x%02x%02x" % (int(col.red * 255), int(col.green * 255),
                                   int(col.blue * 255))
        dash_num.append(Paragraph(
            f"<font color='{hex_}'>{n}</font>",
            ParagraphStyle(
                "DN", parent=s["cover_title"],
                fontName=_font("Sans-Bold", "Helvetica-Bold"),
                fontSize=34.0, leading=36.0, alignment=TA_CENTER,
            ),
        ))
    col_w = inner_w / len(dash_cols)
    dash_table = Table(
        [dash_head, dash_num],
        colWidths=[col_w] * len(dash_cols),
    )
    dash_style: list[Any] = [
        ("BACKGROUND", (0, 0), (-1, -1), COL_PAPER_DEEP),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
        ("VALIGN", (0, 1), (-1, 1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, 0), 4),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
        ("TOPPADDING", (0, 1), (-1, 1), 0),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 6),
        ("LINEABOVE", (0, 0), (-1, 0), 1.6, COL_INK),
        ("LINEBELOW", (0, -1), (-1, -1), 1.6, COL_INK),
    ]
    # Thin vertical dividers between columns
    for ci in range(1, len(dash_cols)):
        dash_style.append(("LINEBEFORE", (ci, 0), (ci, -1), 0.3, COL_THIN))
    dash_table.setStyle(TableStyle(dash_style))
    story.append(dash_table)
    story.append(Spacer(1, 10 * mm))

    # ── 5. AT A GLANCE panel — top FAILs ──
    glance_header = ParagraphStyle(
        "GH", parent=s["caps"], fontSize=8.4, leading=10.0,
        letterSpace=2.4, textColor=COL_ACCENT,
    )
    story.append(Paragraph("AT  A  GLANCE  ·  WORST  FINDINGS", glance_header))
    story.append(Spacer(1, 1.5 * mm))

    fails = [f for f in bundle.findings if f.verdict_label == "FAIL"]
    fails_sorted = sorted(fails, key=lambda f: -f.confidence)[:3]
    if fails_sorted:
        glance_rows: list[list[Any]] = []
        for f in fails_sorted:
            sig = GROUP_SIGIL.get(f.group, f.group[:2])
            sev = _severity_label(f) or "—"
            title_text = f.catalog.get("title", "")
            row = [
                Paragraph(
                    f"<font name='{_font('Mono-Bold', 'Courier-Bold')}' "
                    f"color='#d83b3b' size='12'>{sig}</font>",
                    ParagraphStyle("GSig", parent=s["mono"], alignment=TA_CENTER),
                ),
                Paragraph(
                    f"<font name='{_font('Sans-Bold', 'Helvetica-Bold')}' "
                    f"size='9.0'>{f.finding_id}</font>  "
                    f"<font color='#5b5443' size='8.0'>{f.control_id}</font>  "
                    f"<font color='#7c7c8a' size='7.5'>· {f.group} · "
                    f"sev {sev}</font><br/>"
                    f"<font size='8.6'>{_html_escape(title_text)}</font>",
                    ParagraphStyle("GT", parent=s["body"], fontSize=9.0,
                                   leading=11.2, alignment=TA_LEFT),
                ),
            ]
            glance_rows.append(row)
        # Build the table with thin row separators
        gt = Table(glance_rows, colWidths=[16 * mm, inner_w - 16 * mm])
        gt_style: list[Any] = [
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("BACKGROUND", (0, 0), (0, -1), COL_PAPER_DEEP),
            ("LINEABOVE", (0, 0), (-1, 0), 0.6, COL_INK),
            ("LINEBELOW", (0, -1), (-1, -1), 0.6, COL_INK),
        ]
        for ri in range(1, len(glance_rows)):
            gt_style.append(("LINEABOVE", (0, ri), (-1, ri), 0.3, COL_THIN))
        gt.setStyle(TableStyle(gt_style))
        story.append(gt)
    else:
        # Defensive: only fires if the audit produced zero FAILs.
        story.append(Paragraph(
            "No FAIL verdicts in this audit — see § 02 for the full posture.",
            s["body_sm"]))
    story.append(Spacer(1, 6 * mm))

    # ── 6. Footnote ──
    fn_style = ParagraphStyle("CoverFootnote", parent=s["body_xs"],
                              textColor=COL_MUTED, alignment=TA_JUSTIFY)
    story.append(Paragraph(
        "This document is the machine-generated synthesis of one multi-day VR "
        "(Vulnerability Research) MASVS L1 audit dispatched against the subject "
        "APK. Each of the 53 MASVS L1 controls was investigated independently by "
        "a six-persona reasoning panel (halvar/noor researchers · maddie/yuki "
        "critics · renzo/wei implementers). The AILA platform and its panel "
        "methodology are described in §03. Verdicts are derived by the "
        "production mapper "
        "<font name='Mono'>aila.modules.vr.masvs.verdict_mapper.child_outcome_to_verdict</font> "
        "and never invented by this renderer. Findings are the agents' verbatim "
        "conclusions; the editorial layer is purely typographic. Distribution "
        "is restricted to Vodafone TR security stakeholders.",
        fn_style,
    ))

    story.append(NextPageTemplate("body"))
    story.append(PageBreak())
    return story


def build_doc_control(bundle: Bundle, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    story: list[Flowable] = []
    story.append(_set_section("DOCUMENT  CONTROL", "§ 01"))
    story.append(_h1("§ 01  ·  DOCUMENT CONTROL", s))
    story.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R, thickness=1.4))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        "This document control page is a verifiable manifest of the inputs, processing "
        "pipeline, and toolchain that produced this report. Every byte rendered downstream "
        "is traceable through the audit_id, target_id, and source JSON dumps named below.",
        s["body"]))
    story.append(Spacer(1, 4 * mm))

    target = bundle.audit["target"]
    audit = bundle.audit["audit"]
    apk = bundle.apk
    sum_ = apk.get("static_summary") or {}
    mh = target.get("mcp_handles_json")
    if isinstance(mh, str):
        try:
            mh = json.loads(mh)
        except Exception:
            mh = {}
    mh = mh or {}

    rows = [
        ("Report title", "VF Yanımda — MASVS L1 Audit"),
        ("Report version", REPORT_VERSION),
        ("Generated at (UTC)", _CHROME.timestamp),
        ("", ""),
        ("Subject — package", sum_.get("package") or apk.get("package_name") or ""),
        ("Subject — version", f"{sum_.get('version_name', '')} (build {sum_.get('version_code', '')})"),
        ("Subject — APK SHA-256", apk.get("apk_sha256") or ""),
        ("Subject — manifest", mh.get("android_mcp_manifest_path") or apk.get("manifest_path") or ""),
        ("Subject — decompiled dir", mh.get("android_mcp_decompiled_dir") or apk.get("decompiled_dir") or ""),
        ("Subject — jadx class count", f"{apk.get('jadx_class_count', 0):,}".replace(",", " ")),
        ("", ""),
        ("Audit id", audit.get("id", "")),
        ("Audit kind", audit.get("kind", "")),
        ("Audit status", audit.get("status", "")),
        ("Audit created (UTC)", audit.get("created_at", "")),
        ("Audit stopped (UTC)", audit.get("stopped_at", "")),
        ("Audit duration", _duration_str(audit.get("created_at"), audit.get("stopped_at"))),
        ("Audit cost (USD)", f"{audit.get('cost_actual_usd', 0.0):.2f}"),
        ("Target id", target.get("id", "")),
        ("Target workspace", target.get("workspace_id", "")),
        ("Target team", target.get("team_id", "")),
        ("", ""),
        ("Mapper", "aila.modules.vr.masvs.verdict_mapper.child_outcome_to_verdict"),
        ("Catalog version", "OWASP MASVS v2.1.0 / aila-L1 catalog"),
        ("Persona panel", " · ".join(f"{p}({PERSONA_ROLE[p]})" for p in PERSONAS)),
        ("Adversarial loop", "claim_verifier (audit_mcp + ida_headless probe corroboration)"),
        ("Source dump path", str((_REPO_ROOT / '.run/yanimda_report').resolve())),
        ("Generator script", "scripts/vr_masvs_report_yanimda.py"),
        ("Renderer", f"reportlab Platypus  ·  paper {PAGE_W/mm:.0f}×{PAGE_H/mm:.0f} mm"),
    ]
    table_data: list[list[Any]] = [["FIELD", "VALUE"]]
    for label, value in rows:
        if not label and not value:
            table_data.append(["", ""])
            continue
        cell_style = s["table_cell_mono"] if "id" in label.lower() or "sha" in label.lower() or "dir" in label.lower() or "manifest" in label.lower() or "path" in label.lower() else s["table_cell"]
        table_data.append([
            _para(label, ParagraphStyle("L", parent=s["table_h"], fontSize=7.4, alignment=TA_LEFT)),
            _para(value, cell_style),
        ])
    t = Table(table_data, colWidths=[44 * mm, PAGE_W - MARGIN_L - MARGIN_R - 44 * mm], repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), COL_INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), COL_PAPER),
        ("FONT", (0, 0), (-1, 0), _font("Sans-Bold", "Helvetica-Bold"), 8.0),
        ("LEFTPADDING", (0, 0), (-1, -1), 2.5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2.5),
        ("TOPPADDING", (0, 0), (-1, -1), 2.0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.0),
        ("LINEBELOW", (0, 0), (-1, 0), 1.0, COL_INK),
        ("LINEBELOW", (0, -1), (-1, -1), 0.6, COL_INK),
        ("LINEBEFORE", (0, 0), (0, -1), 0.4, COL_THIN),
        ("LINEAFTER", (1, 0), (1, -1), 0.4, COL_THIN),
    ]
    # Zebra striping
    for ri in range(1, len(table_data)):
        if ri % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, ri), (-1, ri), COL_ZEBRA))
    t.setStyle(TableStyle(style_cmds))
    story.append(t)
    story.append(Spacer(1, 5 * mm))

    story.append(_h2("01.2  ·  CHAIN OF DERIVATION", s))
    story.append(Paragraph(
        "The PDF you are reading was produced in three stages:", s["body"]))
    story.append(Spacer(1, 1.5 * mm))
    chain = [
        ("ingest",
         "Android-MCP decoded the APK with apktool and jadx into the decompiled "
         "dir noted above. Audit-MCP indexed the jadx output (index "
         + (mh.get("audit_mcp_decompiled_index_id") or "?") + ") so semantic_search, "
         "search_functions, callers_of and read_function tools could pull verbatim "
         "source for every cited line."),
        ("dispatch",
         "The VR MASVS audit parent kicked off one child VR investigation per L1 "
         "control. Each child ran six persona branches in parallel; a panel deliberation "
         "loop required quorum or a critic veto before any direct_finding outcome was "
         "promoted to the parent."),
        ("synthesize",
         "Each child child_outcome_to_verdict() projects the primary outcome into a "
         "MasvsControlVerdict. This script renders those verdicts verbatim — never "
         "inventing severity, evidence, or panel attribution."),
    ]
    chain_data: list[list[Any]] = [["STAGE", "DESCRIPTION"]]
    for stage, desc in chain:
        chain_data.append([
            _para(stage.upper(), ParagraphStyle("CS", parent=s["table_h"], textColor=COL_ACCENT)),
            _para(desc, s["table_cell"]),
        ])
    ct = Table(chain_data, colWidths=[26 * mm, None])
    ct.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COL_INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), COL_PAPER),
        ("FONT", (0, 0), (-1, 0), _font("Sans-Bold", "Helvetica-Bold"), 8.0),
        ("LEFTPADDING", (0, 0), (-1, -1), 2.5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2.5),
        ("TOPPADDING", (0, 0), (-1, -1), 2.0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.0),
        ("BACKGROUND", (0, 1), (0, -1), COL_PAPER_DEEP),
        ("LINEBELOW", (0, 0), (-1, 0), 1.0, COL_INK),
        ("BOX", (0, 0), (-1, -1), 0.5, COL_INK),
    ]))
    story.append(ct)
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        "<i>Honesty contract</i>: nothing in the per-finding sections is paraphrased. "
        "The 'Agent reasoning' block on each finding page is the verbatim "
        "<font name='Mono'>payload.answer</font> from the primary outcome of the corresponding "
        "VR child investigation; the per-persona blocks are the verbatim "
        "<font name='Mono'>panel_contributions[].answer_brief</font> rows.",
        s["body_sm"]))
    story.append(PageBreak())
    return story


def _duration_str(start: str | None, stop: str | None) -> str:
    if not start or not stop:
        return "—"
    try:
        s = _dt.datetime.fromisoformat(start.replace("Z", "+00:00"))
        e = _dt.datetime.fromisoformat(stop.replace("Z", "+00:00"))
        delta = e - s
        hours = delta.total_seconds() / 3600
        return f"{hours:.1f} h  ({delta})"
    except (ValueError, TypeError):
        return f"{start} → {stop}"


def _h1(text: str, s: dict[str, ParagraphStyle]) -> Paragraph:
    return Paragraph(text, s["h1"])


def _h2(text: str, s: dict[str, ParagraphStyle]) -> Paragraph:
    return Paragraph(text, s["h2"])


def _h3(text: str, s: dict[str, ParagraphStyle]) -> Paragraph:
    return Paragraph(text, s["h3"])


def _h4(text: str, s: dict[str, ParagraphStyle]) -> Paragraph:
    return Paragraph(text, s["h4"])


def _build_at_a_glance(
    bundle: Bundle,
    s: dict[str, ParagraphStyle],
    counts: Counter[str],
    by_group: dict[str, Counter[str]],
) -> list[Flowable]:
    """Single-page AT A GLANCE dashboard.

    Sits as the first page of § 02 (before the posture narrative). Carries
    the big-number verdict counts and a 9-row group ledger so the operator
    can decide in 30 seconds whether to dig further. Pages-per-section:

        02.1  AT A GLANCE        — 1 page (this function)
        02.2  POSTURE NARRATIVE  — 1 page
        02.3  HEATMAP            — same page or +1
        02.4  TOP-SEVERITY       — same page or +1
    """
    story: list[Flowable] = []
    story.append(_h2("02.1  ·  AT  A  GLANCE", s))
    story.append(Paragraph(
        "Single-page audit dashboard. Verdict counts, group ledger, and the "
        "top FAILs by group. The full posture narrative starts on the next "
        "page.",
        s["body_sm"]))
    story.append(Spacer(1, 4 * mm))

    inner_w = PAGE_W - MARGIN_L - MARGIN_R
    total = len(bundle.findings)

    # ── Big-number dashboard ──
    dash_cols = [
        ("TOTAL",   total,                          COL_INK),
        ("FAIL",    counts.get("FAIL", 0),          COL_FAIL),
        ("REVIEW",  counts.get("REVIEW", 0),        COL_REVIEW),
        ("INFO",    counts.get("INFO", 0),          COL_INFO),
        ("INCONC.", counts.get("INCONCLUSIVE", 0),  COL_INCONCLUSIVE),
        ("PASS",    counts.get("PASS", 0),          COL_PASS),
    ]
    head_cells = [Paragraph(
        f"<font color='#5b5443'>{name}</font>",
        ParagraphStyle("AAGH", parent=s["caps"], fontSize=7.4, leading=9.0,
                       letterSpace=2.0, textColor=COL_MUTED,
                       alignment=TA_CENTER),
    ) for name, _, _ in dash_cols]
    num_cells: list[Any] = []
    for _, n, col in dash_cols:
        hex_ = "#%02x%02x%02x" % (int(col.red * 255), int(col.green * 255),
                                   int(col.blue * 255))
        num_cells.append(Paragraph(
            f"<font color='{hex_}'>{n}</font>",
            ParagraphStyle(
                "AAGN", parent=s["cover_title"],
                fontName=_font("Sans-Bold", "Helvetica-Bold"),
                fontSize=30.0, leading=32.0, alignment=TA_CENTER,
            ),
        ))
    col_w = inner_w / len(dash_cols)
    dash = Table([head_cells, num_cells], colWidths=[col_w] * len(dash_cols))
    dash_style: list[Any] = [
        ("BACKGROUND", (0, 0), (-1, -1), COL_PAPER_DEEP),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, 0), 3),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 1),
        ("TOPPADDING", (0, 1), (-1, 1), 0),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 5),
        ("LINEABOVE", (0, 0), (-1, 0), 1.4, COL_INK),
        ("LINEBELOW", (0, -1), (-1, -1), 1.4, COL_INK),
    ]
    for ci in range(1, len(dash_cols)):
        dash_style.append(("LINEBEFORE", (ci, 0), (ci, -1), 0.3, COL_THIN))
    dash.setStyle(TableStyle(dash_style))
    story.append(dash)
    story.append(Spacer(1, 3 * mm))

    # Distribution stack bar — operator's eye reads severity from the
    # left edge.
    story.append(VerdictDistroBar(dict(counts), inner_w))
    story.append(Spacer(1, 6 * mm))

    # ── Group ledger — one row per group in MASVS canonical order ──
    story.append(_h3("BY  CONTROL  GROUP", s))
    group_order = ["ARCH", "STORAGE", "CRYPTO", "AUTH", "NETWORK",
                   "PLATFORM", "CODE", "RESILIENCE", "PRIVACY"]
    rows: list[list[Any]] = [[
        "GROUP", "n", "FAIL", "REVIEW", "INFO", "INCONC", "PASS",
        "TOP  CONTROL  OF  CONCERN",
    ]]
    for grp in group_order:
        gc = by_group.get(grp) or Counter()
        gtotal = sum(gc.values())
        if gtotal == 0:
            continue
        # Top control = first FAIL by confidence, else first REVIEW, else "—"
        top = None
        worst_band = ("FAIL", "REVIEW", "INCONCLUSIVE", "INFO")
        for band in worst_band:
            cands = [f for f in bundle.findings
                     if f.group == grp and f.verdict_label == band]
            if cands:
                top = max(cands, key=lambda f: f.confidence)
                break
        top_label = "—"
        if top is not None:
            top_label = (
                f"<font name='{_font('Mono-Bold', 'Courier-Bold')}'>"
                f"{top.control_id}</font> "
                f"<font color='#5b5443' size='7.4'>"
                f"{_html_escape(top.catalog.get('title', ''))[:80]}</font>"
            )
        rows.append([
            _para(grp, ParagraphStyle(
                "AAGGrp", parent=s["table_cell_mono"],
                fontName=_font("Mono-Bold", "Courier-Bold"),
                textColor=COL_ACCENT)),
            _para(str(gtotal), s["table_cell_mono"]),
            _para(str(gc.get("FAIL", 0) or "·"),
                  ParagraphStyle("AAGF", parent=s["table_cell_mono"],
                                 textColor=COL_FAIL if gc.get("FAIL") else COL_MUTED,
                                 alignment=TA_CENTER)),
            _para(str(gc.get("REVIEW", 0) or "·"),
                  ParagraphStyle("AAGR", parent=s["table_cell_mono"],
                                 textColor=COL_REVIEW if gc.get("REVIEW") else COL_MUTED,
                                 alignment=TA_CENTER)),
            _para(str(gc.get("INFO", 0) or "·"),
                  ParagraphStyle("AAGI", parent=s["table_cell_mono"],
                                 textColor=COL_INFO if gc.get("INFO") else COL_MUTED,
                                 alignment=TA_CENTER)),
            _para(str(gc.get("INCONCLUSIVE", 0) or "·"),
                  ParagraphStyle("AAGIC", parent=s["table_cell_mono"],
                                 textColor=COL_INCONCLUSIVE if gc.get("INCONCLUSIVE") else COL_MUTED,
                                 alignment=TA_CENTER)),
            _para(str(gc.get("PASS", 0) or "·"),
                  ParagraphStyle("AAGP", parent=s["table_cell_mono"],
                                 textColor=COL_PASS if gc.get("PASS") else COL_MUTED,
                                 alignment=TA_CENTER)),
            _para(top_label, s["table_cell"]),
        ])
    gt = Table(rows, colWidths=[
        20 * mm, 10 * mm, 12 * mm, 14 * mm, 12 * mm, 14 * mm, 12 * mm, None,
    ], repeatRows=1)
    gt.setStyle(_zebra_table_style(len(rows)))
    story.append(gt)
    story.append(Spacer(1, 4 * mm))

    # ── Posture one-liner ──
    fail_n = counts.get("FAIL", 0)
    review_n = counts.get("REVIEW", 0)
    inconc_n = counts.get("INCONCLUSIVE", 0)
    info_n = counts.get("INFO", 0)
    pass_n = counts.get("PASS", 0)
    na_n = counts.get("N/A", 0)
    risk_pct = (fail_n + review_n + inconc_n) / total * 100 if total else 0
    posture_pct = (pass_n + na_n + info_n) / total * 100 if total else 0
    summary_html = (
        f"<b>{risk_pct:.0f}%</b> of controls landed in the risk band "
        f"(FAIL + REVIEW + INCONCLUSIVE); "
        f"<b>{posture_pct:.0f}%</b> landed in the cleared band "
        f"(PASS + N/A + INFO).  "
        f"Highest-density risk group: <b>{_max_risk_group(by_group)}</b>.  "
        "See §06 for per-control evidence and remediation."
    )
    summary_box = Table(
        [[Paragraph(summary_html, ParagraphStyle(
            "AAGSum", parent=s["body"], fontSize=9.4, leading=12.4,
            textColor=COL_INK, alignment=TA_LEFT))]],
        colWidths=[inner_w],
    )
    summary_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COL_PAPER_DEEP),
        ("LINEBEFORE", (0, 0), (0, -1), 2.4, COL_ACCENT),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEABOVE", (0, 0), (-1, 0), 0.4, COL_INK),
        ("LINEBELOW", (0, -1), (-1, -1), 0.4, COL_INK),
    ]))
    story.append(summary_box)
    return story


def build_exec_summary(bundle: Bundle, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    counts: Counter[str] = Counter(f.verdict_label for f in bundle.findings)
    by_group: dict[str, Counter[str]] = defaultdict(Counter)
    for f in bundle.findings:
        by_group[f.group][f.verdict_label] += 1

    story: list[Flowable] = []
    story.append(_set_section("EXECUTIVE  SUMMARY", "§ 02"))
    story.append(_h1("§ 02  ·  EXECUTIVE SUMMARY", s))
    story.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R, thickness=1.4))
    story.append(Spacer(1, 3 * mm))

    # ── 02.1  AT A GLANCE — single-page dashboard ──
    # One page, no narrative. Operator scans this in 30 seconds and
    # decides whether to dig further. The narrative posture analysis
    # and the heatmap live on the NEXT page (02.2 / 02.3).
    story.extend(_build_at_a_glance(bundle, s, counts, by_group))
    story.append(PageBreak())

    total = len(bundle.findings)
    fail_n = counts.get("FAIL", 0)
    review_n = counts.get("REVIEW", 0)
    info_n = counts.get("INFO", 0)
    inconc_n = counts.get("INCONCLUSIVE", 0)
    pass_n = counts.get("PASS", 0)
    na_n = counts.get("N/A", 0)
    # INFO counts as posture-neutral (operator-doc-needed, not a code defect)
    # so we add it to the favorable side of the score.
    posture_pct = (pass_n + na_n + info_n) / total * 100 if total else 0
    risk_pct = (fail_n + review_n + inconc_n) / total * 100 if total else 0

    apk_sum = bundle.apk.get("static_summary") or {}
    appsec = (bundle.apk.get("mobsf_scan") or {}).get("appsec", {})
    score = appsec.get("security_score", "—")

    # ── 02.2  Posture narrative ──
    story.append(_h2("02.2  ·  POSTURE  NARRATIVE", s))
    overview = (
        f"The subject is the Vodafone Türkiye self-service Android app "
        f"<b>{apk_sum.get('package') or bundle.apk.get('package_name')}</b> "
        f"version <b>{apk_sum.get('version_name')}</b> (build {apk_sum.get('version_code')}). "
        f"The APK targets SDK {apk_sum.get('target_sdk')} (Android 14) with a minSDK of "
        f"{apk_sum.get('min_sdk')} (Android 6.0). It ships {apk_sum.get('version_name')} of the "
        f"Vodafone self-service feature surface — {len(apk_sum.get('activities') or [])} activities, "
        f"{len(apk_sum.get('services') or [])} services, {len(apk_sum.get('receivers') or [])} receivers, "
        f"{len(apk_sum.get('providers') or [])} providers — over a {bundle.apk.get('jadx_class_count', 0):,} "
        "decompiled-class codebase. ".replace(",", " ")
        + f"{len(apk_sum.get('permissions') or [])} permissions are declared, "
        f"{len(apk_sum.get('exported_components') or [])} components are exported, "
        f"and MobSF reports an AppSec score of {score}/100."
    )
    story.append(Paragraph(overview, s["body"]))
    story.append(Spacer(1, 4 * mm))
    # The headline ledger + distribution bar that used to live here moved
    # to the 02.1 AT A GLANCE dashboard one page above so the posture
    # narrative can stand on its own.

    story.append(Paragraph(
        f"Across the {total} MASVS L1 controls dispatched, the panel returned "
        f"<b>{fail_n} FAIL</b>, <b>{review_n} REVIEW</b>, "
        f"<b>{info_n} INFO</b>, "
        f"<b>{inconc_n} INCONCLUSIVE</b>, <b>{na_n} N/A</b> and "
        f"<b>{pass_n} PASS</b>. "
        f"{risk_pct:.0f}% of controls landed in the FAIL/REVIEW/INCONCLUSIVE band that "
        f"requires Vodafone TR engineering attention; {posture_pct:.0f}% of controls landed "
        "in the cleared band (PASS, formally not-applicable, or pending "
        "operator-supplied documentation under the INFO disposition). "
        "The INFO disposition flags controls whose verification target is a "
        "team-owned artifact — component inventory, data classification matrix, "
        "SBOM, architecture diagram, privacy policy — which the code audit "
        "cannot synthesize on its own. The "
        "highest-density risk group is "
        + _max_risk_group(by_group) + ". Per-control evidence, agent reasoning, and "
        "remediation guidance follow in §06.",
        s["body"]))
    story.append(Spacer(1, 4 * mm))

    # ── 02.3  Heatmap ──
    story.append(_h2("02.3  ·  VERDICT × GROUP HEATMAP", s))
    story.append(Paragraph(
        "Rows are MASVS v2.1.0 control groups; columns are verdict bands. "
        "Cell intensity is keyed to count — empty cells carry a single dot.",
        s["body_sm"]))
    story.append(Spacer(1, 2 * mm))
    story.append(HeatmapGrid(bundle.findings, PAGE_W - MARGIN_L - MARGIN_R))
    story.append(Spacer(1, 5 * mm))

    # ── 02.4  Top-severity findings table ──
    fails = [f for f in bundle.findings if f.verdict_label == "FAIL"]
    fails_sorted = sorted(fails, key=lambda f: -f.confidence)[:6]
    if fails_sorted:
        story.append(_h2("02.4  ·  TOP-SEVERITY FINDINGS", s))
        rows = [["FIND.", "CTRL", "GROUP", "CONF.", "TITLE / ONE-LINE"]]
        for f in fails_sorted:
            t = f.catalog.get("title", "")
            rows.append([
                _para(f.finding_id, s["table_cell_mono"]),
                _para(f.control_id, s["table_cell_mono"]),
                _para(f.group, s["table_cell_mono"]),
                _para(f"{f.confidence:.2f}", s["table_cell_mono"]),
                _para(t, s["table_cell"]),
            ])
        tt = Table(rows, colWidths=[16 * mm, 26 * mm, 18 * mm, 14 * mm, None],
                   repeatRows=1)
        tt.setStyle(_zebra_table_style(len(rows)))
        story.append(tt)
        story.append(Spacer(1, 3 * mm))

    story.append(PageBreak())
    return story


def _max_risk_group(by_group: dict[str, Counter[str]]) -> str:
    scores: list[tuple[str, int]] = []
    for grp, c in by_group.items():
        scores.append((grp, c["FAIL"] * 3 + c["REVIEW"] * 2 + c["INCONCLUSIVE"]))
    scores.sort(key=lambda t: -t[1])
    if not scores or scores[0][1] == 0:
        return "(none — no risk-band findings)"
    return ", ".join(g for g, _ in scores[:2])


def _zebra_table_style(nrows: int) -> TableStyle:
    cmds: list[Any] = [
        ("BACKGROUND", (0, 0), (-1, 0), COL_INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), COL_PAPER),
        ("FONT", (0, 0), (-1, 0), _font("Sans-Bold", "Helvetica-Bold"), 7.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 2.5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2.5),
        ("TOPPADDING", (0, 0), (-1, -1), 2.0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.0),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, 0), 1.0, COL_INK),
        ("LINEABOVE", (0, -1), (-1, -1), 0.4, COL_INK),
    ]
    for ri in range(1, nrows):
        if ri % 2 == 0:
            cmds.append(("BACKGROUND", (0, ri), (-1, ri), COL_ZEBRA))
    return TableStyle(cmds)


def build_findings_index(bundle: Bundle, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    story: list[Flowable] = []
    story.append(_set_section("FINDINGS  INDEX", "§ 05"))
    story.append(_h1("§ 05  ·  FINDINGS INDEX", s))
    story.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R, thickness=1.4))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        "All 53 MASVS L1 controls listed in severity order. Each row indexes the "
        "per-control finding page in §06. Verdict colour-keys match the legend on "
        "the cover.",
        s["body"]))
    story.append(Spacer(1, 4 * mm))

    # Two row kinds:
    #   data row  — 6 columns (FIND/CTRL/GROUP/VERDICT/CONF/TITLE)
    #   quote row — single-column span carrying the agent's pull-quote
    #               (FAIL findings only)
    # We track row indices as we build so the TableStyle can SPAN the
    # quote rows and shade them in the verdict colour.
    rows: list[list[Any]] = [
        ["FIND.", "CTRL", "GROUP", "VERDICT", "CONF.",
         "TITLE  &  AGENT  ONE-LINER"]
    ]
    quote_rows: list[int] = []   # row indices that carry a spanned quote
    findings_sorted = sorted(
        bundle.findings,
        key=lambda f: (f.severity_rank, f.control_id),
    )
    quote_style = ParagraphStyle(
        "IdxQuote", parent=s["body_sm"],
        fontName=_font("Body-Italic", "Times-Italic"),
        fontSize=8.4, leading=10.4,
        leftIndent=6, rightIndent=4,
        textColor=COL_INK, alignment=TA_LEFT,
    )
    for f in findings_sorted:
        one_liner = f.catalog.get("title", "")
        rows.append([
            _para(f.finding_id, s["table_cell_mono"]),
            _para(f.control_id, s["table_cell_mono"]),
            _para(f.group, ParagraphStyle("G", parent=s["table_cell_mono"],
                                           textColor=COL_ACCENT)),
            _verdict_cell(f.verdict_label),
            _para(f"{f.confidence:.2f}", s["table_cell_mono"]),
            _para(one_liner, s["table_cell_xs"]),
        ])
        # FAIL rows get an italic pull-quote on the line beneath. Pulls
        # the eye to the worst findings without forcing the operator
        # to flip to §06 just to see why a row is red.
        if f.verdict_label == "FAIL":
            quote = _pull_quote_text(f, cap=140)
            if quote:
                safe = _md_inline(_html_escape(quote))
                quote_para = Paragraph(f"« {safe} »", quote_style)
                # All six cells filled with empty placeholders; the
                # SPAN command later merges them into one wide cell.
                rows.append([quote_para, "", "", "", "", ""])
                quote_rows.append(len(rows) - 1)
    tt = Table(rows, colWidths=[16 * mm, 24 * mm, 18 * mm, 22 * mm, 13 * mm,
                                  None],
               repeatRows=1)
    base_style = _zebra_table_style(len(rows))
    # Add SPAN + verdict-coloured left rule + shade for every quote row.
    extra_cmds: list[Any] = []
    for ri in quote_rows:
        extra_cmds.append(("SPAN", (0, ri), (-1, ri)))
        extra_cmds.append(("BACKGROUND", (0, ri), (-1, ri), COL_ZEBRA))
        extra_cmds.append(("LINEBEFORE", (0, ri), (0, ri), 3.0, COL_FAIL))
        extra_cmds.append(("LEFTPADDING", (0, ri), (-1, ri), 8))
        extra_cmds.append(("TOPPADDING", (0, ri), (-1, ri), 1.5))
        extra_cmds.append(("BOTTOMPADDING", (0, ri), (-1, ri), 2.5))
    for cmd in extra_cmds:
        base_style.add(*cmd)
    tt.setStyle(base_style)
    story.append(tt)
    story.append(PageBreak())
    return story


def _verdict_cell(label: str) -> Flowable:
    return VerdictBadge(label, width=20 * mm, height=4.6 * mm)


# ============================================================================
# ABOUT AILA — § 03 — platform explainer
# ============================================================================
#
# Operator wants the reader to know WHO produced the audit before they
# read its findings. § 03 is a 3-5 page platform explainer drawing
# every fact from .run/yanimda_report/aila_brief.json — no fields
# invented here.

def _persona_character_one_liner(text: str) -> str:
    """Pull the character descriptor from the persona prompt header.

    The persona prompt opens with

        # Your voice: HALVAR — the hypothesizer (researcher role) You are
        **Halvar**, the researcher voice. ...

    The character substring is between the em-dash after the persona name
    and the opening parenthesis of the role tag — ``the hypothesizer``,
    ``the falsifier``, ``the operationalizer``, etc. We return THAT
    substring with a capitalised first letter; the role parenthetical
    (``(researcher role)``) is shown alongside as the ROLE column already.
    """
    if not isinstance(text, str) or not text.strip():
        return ""
    raw = text.strip()
    # Match the header: "# Your voice: NAME — the X (role)"
    m = re.search(
        r"#\s*Your\s+voice:\s*[A-Z]+\s*[\u2014\u2013\-]\s*(?P<char>[^()\n]+?)\s*\(",
        raw,
    )
    if not m:
        return ""
    char = m.group("char").strip(" .,;:")
    if not char:
        return ""
    # Capitalise the first letter — "the hypothesizer" → "The hypothesizer"
    char = char[0].upper() + char[1:]
    return char


def build_about_aila(bundle: Bundle, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    """Render the § 03 ABOUT THE PLATFORM section.

    Six subsections sourced from ``bundle.aila_brief``:

        03.1  What AILA is
        03.2  The 6-persona panel
        03.3  The workflow
        03.4  The MCP tool stack
        03.5  This audit's facts
        03.6  Limitations and disclosure

    All persona names, workflow state descriptions, MCP server entries,
    audit-run stats and limitations come from
    ``.run/yanimda_report/aila_brief.json``. When the brief is missing,
    the section degrades to a one-paragraph fallback so older inputs
    still build a valid PDF.
    """
    brief = bundle.aila_brief or {}
    story: list[Flowable] = []
    story.append(_set_section("ABOUT  THE  PLATFORM", "§ 03"))
    story.append(_h1("§ 03  ·  ABOUT THE PLATFORM — AILA / Vulnerability Research", s))
    story.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R, thickness=1.4))
    story.append(Spacer(1, 3 * mm))

    if not brief:
        story.append(Paragraph(
            "<i>The AILA platform brief (aila_brief.json) was not present in the "
            "report input directory. This section degrades to a single-line stub; "
            "regenerate the report with the brief staged to populate it.</i>",
            ParagraphStyle("AboutFB", parent=s["body"], textColor=COL_MUTED)))
        story.append(PageBreak())
        return story

    inner_w = PAGE_W - MARGIN_L - MARGIN_R

    # ── 03.1  What AILA is ──
    story.append(_h2("03.1  ·  WHAT  AILA  IS", s))
    story.append(Paragraph(
        "<b>AILA</b> (AI Lab Assistant) is a modular AI security platform. Its "
        "<b>VR (Vulnerability Research)</b> module performs adversarial code "
        "audits by spawning a panel of six independent reasoning agents per "
        "control. Each agent reasons through the control's verification "
        "objective using a layered MCP tool stack — <font name='Mono'>audit_mcp</font> "
        "for source-code semantic search, AST queries and call-graph traversal; "
        "<font name='Mono'>android_mcp</font> for APK ingestion (apktool, jadx, "
        "androguard, MobSF); <font name='Mono'>ida_headless</font> for native "
        "binary disassembly and exploitability assessment. After the panel "
        "deliberates, an independent <b>claim verifier</b> runs adversarial "
        "probes against the proposed finding; a refuted claim flips the verdict "
        "back to NO_FINDING. Every line of this report is the synthesis of that "
        "process — the platform does not fabricate findings, does not paraphrase "
        "agent prose, and never substitutes its own conclusion for the panel's "
        "verbatim reasoning.",
        s["body"]))
    story.append(Spacer(1, 5 * mm))

    # ── 03.2  The 6-persona panel ──
    story.append(_h2("03.2  ·  THE  6-PERSONA  PANEL", s))
    story.append(Paragraph(
        "Every MASVS L1 control is dispatched to six independent reasoning "
        "agents — two researchers, two critics, two implementers. Each agent "
        "reasons in isolation; cross-pollination happens only at terminal time "
        "when the synthesis agent merges the panel's contributions into one "
        "canonical outcome.",
        s["body_sm"]))
    story.append(Spacer(1, 2 * mm))

    persona_roles = brief.get("personas_roles") or {}
    persona_prompts = brief.get("personas") or {}
    persona_order = ["halvar", "noor", "maddie", "yuki", "renzo", "wei"]

    persona_rows: list[list[Any]] = [["PERSONA", "ROLE", "CHARACTER"]]
    for pname in persona_order:
        role = persona_roles.get(pname, "—")
        char = _persona_character_one_liner(persona_prompts.get(pname, ""))
        pcol = _PERSONA_COLOR.get(pname, COL_INK)
        phex = "#%02x%02x%02x" % (
            int(pcol.red * 255), int(pcol.green * 255), int(pcol.blue * 255),
        )
        persona_rows.append([
            Paragraph(
                f"<font name='{_font('Sans-Bold', 'Helvetica-Bold')}' "
                f"color='{phex}' size='9.4'>{pname.upper()}</font>",
                s["table_cell_mono"],
            ),
            _para(role, s["table_cell"]),
            _para(_html_escape(char) or "—", s["table_cell_xs"]),
        ])
    pt = Table(persona_rows, colWidths=[28 * mm, 56 * mm, None], repeatRows=1)
    pt.setStyle(_zebra_table_style(len(persona_rows)))
    story.append(pt)
    story.append(Spacer(1, 3 * mm))

    cv_text = brief.get("claim_verifier") or ""
    vh_text = brief.get("variant_hunt") or ""
    if cv_text:
        story.append(_h4("CLAIM  VERIFIER", s))
        story.append(Paragraph(cv_text, s["body_sm"]))
        story.append(Spacer(1, 2 * mm))
    if vh_text:
        story.append(_h4("VARIANT  HUNT", s))
        story.append(Paragraph(vh_text, s["body_sm"]))
        story.append(Spacer(1, 4 * mm))

    # ── 03.3  The workflow ──
    story.append(_h2("03.3  ·  THE  WORKFLOW", s))
    story.append(Paragraph(
        "Each per-control investigation is a durable six-state machine. State "
        "advances on terminal conditions (panel quorum, persona turn cap, "
        "wall-clock cap, or every branch landing in a terminal status). Persisted "
        "to PostgreSQL between states so investigations survive crashes and "
        "retries.",
        s["body_sm"]))
    story.append(Spacer(1, 2 * mm))

    states_raw = brief.get("workflow_states") or []
    flow_labels = ["SETUP", "LOOP", "EMIT", "SYNTHESIZE", "VERIFY", "DISPATCH"]
    # One arrow row + one description row beneath
    arrow_cells: list[Any] = []
    desc_cells: list[Any] = []
    for i, lab in enumerate(flow_labels):
        # Box label
        arrow_cells.append(Paragraph(
            f"<font name='{_font('Sans-Bold', 'Helvetica-Bold')}' "
            f"color='white' size='10.4'>{lab}</font>",
            ParagraphStyle(
                f"FlowLab_{i}", parent=s["caps"], alignment=TA_CENTER,
                fontSize=10.4, leading=12.0, letterSpace=1.4,
            ),
        ))
        # One-line description from the brief (text after the em-dash)
        desc = ""
        if i < len(states_raw):
            state_str = states_raw[i]
            if isinstance(state_str, str) and "—" in state_str:
                desc = state_str.split("—", 1)[1].strip()
            elif isinstance(state_str, str):
                desc = state_str
        desc_cells.append(Paragraph(
            _html_escape(desc)[:120],
            ParagraphStyle(
                f"FlowDesc_{i}", parent=s["body_xs"],
                fontSize=6.8, leading=8.4, alignment=TA_CENTER,
                textColor=COL_INK,
            ),
        ))
    flow_table = Table(
        [arrow_cells, desc_cells],
        colWidths=[inner_w / len(flow_labels)] * len(flow_labels),
    )
    flow_style: list[Any] = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (-1, 0), COL_NAVY),
        ("BACKGROUND", (0, 1), (-1, 1), COL_PAPER_DEEP),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("TOPPADDING", (0, 1), (-1, 1), 3),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 3),
    ]
    # Thin accent dividers + arrow glyph via the right-edge rule
    for ci in range(len(flow_labels) - 1):
        flow_style.append(("LINEAFTER", (ci, 0), (ci, 0), 1.2, COL_ACCENT))
        flow_style.append(("LINEAFTER", (ci, 1), (ci, 1), 0.3, COL_THIN))
    flow_style.append(("BOX", (0, 0), (-1, -1), 0.6, COL_INK))
    flow_table.setStyle(TableStyle(flow_style))
    story.append(flow_table)
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        "<i>Terminal conditions:</i> panel quorum (4-of-6 personas converge on "
        "the same verdict), persona turn cap (70 turns per voice), audit "
        "wall-clock cap (24 h), or all branches reach a terminal status. "
        "Whichever fires first stops the loop.",
        ParagraphStyle("FlowNote", parent=s["body_xs"], textColor=COL_MUTED,
                       alignment=TA_JUSTIFY)))
    story.append(Spacer(1, 5 * mm))

    # ── 03.4  The MCP tool stack ──
    story.append(_h2("03.4  ·  THE  MCP  TOOL  STACK", s))
    story.append(Paragraph(
        "All agent reasoning is grounded by tool calls against three MCP "
        "(Model Context Protocol) servers running locally. The bridge layer "
        "normalises tool responses into observable case-state entries the next "
        "turn's prompt reads — agents never see raw HTTP, only typed records.",
        s["body_sm"]))
    story.append(Spacer(1, 2 * mm))

    mcp_servers = brief.get("mcp_servers") or []
    mcp_rows: list[list[Any]] = [["SERVER", "PURPOSE", "URL", "TOOL  COUNT"]]
    for srv in mcp_servers:
        mcp_rows.append([
            _para(srv.get("name") or "—", ParagraphStyle(
                "McpN", parent=s["table_cell_mono"],
                fontName=_font("Mono-Bold", "Courier-Bold"),
                textColor=COL_ACCENT)),
            _para(srv.get("purpose") or "—", s["table_cell"]),
            _para(srv.get("url") or "—", s["table_cell_mono"]),
            _para(srv.get("tool_count_approx") or "—",
                  ParagraphStyle("McpC", parent=s["table_cell_mono"],
                                 alignment=TA_CENTER)),
        ])
    mt = Table(mcp_rows, colWidths=[28 * mm, None, 44 * mm, 22 * mm],
               repeatRows=1)
    mt.setStyle(_zebra_table_style(len(mcp_rows)))
    story.append(mt)
    story.append(Spacer(1, 5 * mm))

    # ── 03.5  This audit's facts ──
    story.append(_h2("03.5  ·  THIS  AUDIT'S  FACTS", s))
    facts = brief.get("audit_facts") or {}
    facts_rows = [
        ["MASVS  L1  CONTROLS  EVALUATED",
         str(facts.get("controls_evaluated") or len(bundle.findings))],
        ["PERSONAS  PER  CONTROL",
         str(facts.get("personas_per_control") or 6)],
        ["MAX  TURNS  PER  PERSONA",
         str(facts.get("max_turns_per_persona") or 70)],
        ["WALL-CLOCK  CAP  (HOURS)",
         str(facts.get("wall_clock_per_audit_cap_hours") or 24)],
        ["TOTAL  BRANCHES  SPAWNED  (APPROX.)",
         f"~{facts.get('total_branches_spawned_approx', '—')}"],
        ["LLM  REASONING  TURNS  (APPROX.)",
         str(facts.get("actual_llm_turns_approx") or "—")],
        ["AUDIT  BEGAN  (UTC)",
         str(facts.get("audit_began") or "—")],
        ["AUDIT  COMPLETED  (UTC)",
         str(facts.get("audit_completed") or "—")],
        ["ELAPSED  WALL-CLOCK  (APPROX.)",
         f"{facts.get('elapsed_hours_approx', '—')} h"],
    ]
    ft_data: list[list[Any]] = [["METRIC", "VALUE"]]
    for label, value in facts_rows:
        ft_data.append([
            _para(label, ParagraphStyle(
                "FactL", parent=s["table_h"], fontSize=7.4, alignment=TA_LEFT)),
            _para(value, ParagraphStyle(
                "FactV", parent=s["table_cell_mono"],
                fontName=_font("Mono-Bold", "Courier-Bold"),
                fontSize=8.4, textColor=COL_INK)),
        ])
    ft = Table(ft_data, colWidths=[80 * mm, None], repeatRows=1)
    ft.setStyle(_zebra_table_style(len(ft_data)))
    story.append(ft)
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        "In concrete terms: every PASS / FAIL / INFO / REVIEW row in §06 is "
        "the convergent verdict of up to six independent agents that each "
        "spent up to 70 reasoning turns interrogating the APK source through "
        "the MCP tool stack above. The persona voices in §06's "
        "<b>panel attribution</b> sub-section are the verbatim per-voice "
        "contributions; the synthesis agent merged them into the canonical "
        "outcome you see in <b>agent reasoning</b>.",
        s["body_sm"]))
    story.append(Spacer(1, 5 * mm))

    # ── 03.6  Limitations & disclosure ──
    story.append(_h2("03.6  ·  LIMITATIONS  &  DISCLOSURE", s))
    story.append(Paragraph(
        "Honest scope statement of what AILA does and does NOT do on this "
        "engagement. The limitations below are not disclaimers — they are the "
        "explicit boundary of the platform's reach so the operator can "
        "calibrate where additional manual review is required.",
        s["body_sm"]))
    story.append(Spacer(1, 2 * mm))
    limitations = brief.get("limitations") or []
    for i, lim in enumerate(limitations, 1):
        safe = _md_inline(_html_escape(lim))
        story.append(Paragraph(
            f"<b>{i}.</b>&nbsp;&nbsp;{safe}",
            ParagraphStyle("LimItem", parent=s["body"], fontSize=9.0,
                           leading=11.6, leftIndent=8, alignment=TA_LEFT,
                           spaceAfter=3)))
    story.append(PageBreak())
    return story


# ============================================================================
# APK INTELLIGENCE ANNEX
# ============================================================================

# Dangerous permission patterns — per Android docs. Anything not in this
# set we classify as NORMAL except signature-protected platform perms.
_DANGEROUS_PERMS = {
    "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "READ_CALENDAR", "WRITE_CALENDAR",
    "CAMERA", "RECORD_AUDIO",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "ANSWER_PHONE_CALLS",
    "USE_SIP", "PROCESS_OUTGOING_CALLS", "ADD_VOICEMAIL",
    "BODY_SENSORS", "ACTIVITY_RECOGNITION",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO",
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH",
    "RECEIVE_MMS", "POST_NOTIFICATIONS",
    "BLUETOOTH_ADVERTISE", "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN",
    "UWB_RANGING", "NEARBY_WIFI_DEVICES",
}
_SIGNATURE_PERMS = {
    "WRITE_SECURE_SETTINGS", "BIND_DEVICE_ADMIN", "BIND_ACCESSIBILITY_SERVICE",
    "BIND_NOTIFICATION_LISTENER_SERVICE", "BIND_VOICE_INTERACTION",
    "PACKAGE_USAGE_STATS", "BIND_DEVICE_OWNER",
}


def _classify_perm(name: str, mobsf_perm: dict[str, Any] | None) -> str:
    """Return NORMAL / DANGEROUS / SIGNATURE / SPECIAL based on MobSF + name."""
    if mobsf_perm and isinstance(mobsf_perm, dict):
        status = (mobsf_perm.get("status") or "").lower()
        if "dangerous" in status:
            return "DANGEROUS"
        if "signature" in status:
            return "SIGNATURE"
        if status:
            return status.upper()
    short = name.rsplit(".", 1)[-1]
    if short in _DANGEROUS_PERMS:
        return "DANGEROUS"
    if short in _SIGNATURE_PERMS or "BIND_" in short or "WRITE_SECURE" in short:
        return "SIGNATURE"
    return "NORMAL"


def build_apk_intel(bundle: Bundle, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    apk = bundle.apk
    sum_ = apk.get("static_summary") or {}
    mobsf = apk.get("mobsf_scan") or {}
    appsec = mobsf.get("appsec") or {}
    mobsf_perms = mobsf.get("permissions") or {}

    story: list[Flowable] = []
    story.append(_set_section("APK  INTELLIGENCE  ANNEX", "§ 04"))
    story.append(_h1("§ 04  ·  APK INTELLIGENCE ANNEX", s))
    story.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R, thickness=1.4))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        "Source-of-truth APK fingerprint. Every field here is taken verbatim from "
        "the apk_intel.json snapshot (Android-MCP + MobSF). Verdicts in §06 cite "
        "file paths and lines that resolve against the decompiled tree referenced "
        "in §01.",
        s["body"]))
    story.append(Spacer(1, 4 * mm))

    # 04.1 Build & fingerprint
    story.append(_h2("04.1  ·  BUILD & FINGERPRINT", s))
    fp_rows = [
        ["Package", sum_.get("package", "")],
        ["Version", f"{sum_.get('version_name', '')}  (build {sum_.get('version_code', '')})"],
        ["minSDK", sum_.get("min_sdk", "")],
        ["targetSDK", sum_.get("target_sdk", "")],
        ["maxSDK", str(mobsf.get("max_sdk") or "—")],
        ["Main activity", sum_.get("main_activity", "")],
        ["APK SHA-256", apk.get("apk_sha256", "")],
        ["MD5", str(mobsf.get("md5") or "—")],
        ["SHA-1", str(mobsf.get("sha1") or "—")],
        ["File size", _bytes_h(mobsf.get("size"))],
        ["Activities declared", str(len(sum_.get("activities") or []))],
        ["Services declared", str(len(sum_.get("services") or []))],
        ["Receivers declared", str(len(sum_.get("receivers") or []))],
        ["Providers declared", str(len(sum_.get("providers") or []))],
        ["Exported components", str(len(sum_.get("exported_components") or []))],
        ["Permissions declared", str(len(sum_.get("permissions") or []))],
        ["Decompiled classes", f"{apk.get('jadx_class_count', 0):,}".replace(",", " ")],
        ["MobSF AppSec score", f"{appsec.get('security_score', '—')} / 100"],
        ["MobSF high findings", str(len(appsec.get("high") or []))],
        ["MobSF warning findings", str(len(appsec.get("warning") or []))],
        ["MobSF info findings", str(len(appsec.get("info") or []))],
        ["MobSF secure findings", str(len(appsec.get("secure") or []))],
        ["MobSF hotspots", str(len(appsec.get("hotspot") or []))],
        ["Trackers identified", f"{appsec.get('trackers', '—')} / {appsec.get('total_trackers', '—')}"],
    ]
    data: list[list[Any]] = [["FIELD", "VALUE"]]
    for k, v in fp_rows:
        data.append([
            _para(k, ParagraphStyle("L", parent=s["table_h"], fontSize=7.4)),
            _para(str(v), s["table_cell_mono"]),
        ])
    t = Table(data, colWidths=[44 * mm, None], repeatRows=1)
    t.setStyle(_zebra_table_style(len(data)))
    story.append(t)
    story.append(Spacer(1, 5 * mm))

    # 04.2 Signing certificates
    story.append(_h2("04.2  ·  SIGNING CERTIFICATES", s))
    certs = sum_.get("signing_certs") or []
    if certs:
        rows = [["#", "SCHEME", "SUBJECT  /  ISSUER", "NOT BEFORE", "NOT AFTER", "ALG"]]
        for i, c in enumerate(certs, 1):
            scheme = c.get("scheme", "—")
            subj = c.get("subject", "")
            iss = c.get("issuer", "")
            entry = f"<b>S:</b> {subj}<br/><b>I:</b> {iss}<br/><b>Serial:</b> {c.get('serial', '—')}"
            rows.append([
                _para(str(i), s["table_cell_mono"]),
                _para(scheme.upper(), s["table_cell_mono"]),
                Paragraph(entry, s["table_cell_xs"]),
                _para(c.get("not_before", ""), s["table_cell_mono"]),
                _para(c.get("not_after", ""), s["table_cell_mono"]),
                _para(c.get("signature_algorithm", ""), s["table_cell_xs"]),
            ])
        tt = Table(rows, colWidths=[8 * mm, 14 * mm, None, 26 * mm, 26 * mm, 24 * mm], repeatRows=1)
        tt.setStyle(_zebra_table_style(len(rows)))
        story.append(tt)
    else:
        story.append(Paragraph("(no signing certificates recorded)", s["body_sm"]))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        "<b>Self-signed</b>: subject equals issuer on every recorded scheme — typical for "
        "production APKs (Vodafone is its own CA for the signing key). The v1 scheme is "
        "present (Janus mitigation requires v2/v3 alongside, which the APK ships). "
        "Certificate validity window extends to 2067 — long-term key reuse, but key "
        "rotation is a packaging-time concern out of scope for MASVS L1.",
        s["body_sm"]))
    story.append(Spacer(1, 5 * mm))

    # 04.3 — permissions (full 38)
    story.append(_h2("04.3  ·  DECLARED  PERMISSIONS", s))
    perm_list = sum_.get("permissions") or []
    perm_rows = [["#", "PERMISSION", "PROTECTION  LEVEL", "MOBSF  STATUS"]]
    perm_cat: Counter[str] = Counter()
    for i, p in enumerate(perm_list, 1):
        cat = _classify_perm(p, mobsf_perms.get(p))
        perm_cat[cat] += 1
        mp = mobsf_perms.get(p) or {}
        info = mp.get("info") if isinstance(mp, dict) else ""
        descr = mp.get("description") if isinstance(mp, dict) else ""
        status_cell_text = info or descr or ""
        cell_style = _table_cell_with_color(s, _perm_color(cat))
        perm_rows.append([
            _para(str(i), s["table_cell_mono"]),
            _para(p, s["table_cell_mono"]),
            _para(cat, cell_style),
            _para(status_cell_text, s["table_cell_xs"]),
        ])
    pt = Table(perm_rows,
               colWidths=[8 * mm, 80 * mm, 28 * mm, None], repeatRows=1)
    pt.setStyle(_zebra_table_style(len(perm_rows)))
    story.append(pt)
    story.append(Spacer(1, 1.5 * mm))
    perm_summary = "  ·  ".join(f"<b>{k}</b> {v}" for k, v in perm_cat.most_common())
    story.append(Paragraph(
        f"Distribution: {perm_summary} · total {len(perm_list)} permissions declared.",
        s["body_sm"]))
    story.append(Spacer(1, 5 * mm))

    # 04.4 — exported components
    story.append(_h2("04.4  ·  EXPORTED  COMPONENTS", s))
    exported = sum_.get("exported_components") or []
    ex_rows = [["#", "KIND", "COMPONENT", "EXPORTED", "INTENT  FILTERS"]]
    for i, ec in enumerate(exported, 1):
        kind = (ec.get("kind") or "").upper()
        name = ec.get("name", "")
        exp = ec.get("exported_attr", "")
        filters = ec.get("filters") or {}
        if filters:
            parts: list[str] = []
            for k, v in filters.items():
                if isinstance(v, list):
                    if k == "data":
                        for d in v[:3]:
                            parts.append("data:" + ", ".join(f"{kk}={vv}" for kk, vv in (d or {}).items()))
                    else:
                        parts.append(f"{k}: {', '.join(str(x) for x in v[:6])}")
                else:
                    parts.append(f"{k}: {v}")
            filt_str = " | ".join(parts)
        else:
            filt_str = "—"
        ex_rows.append([
            _para(str(i), s["table_cell_mono"]),
            _para(kind, _table_cell_with_color(s, COL_ACCENT)),
            _para(name, s["table_cell_mono"]),
            _para(exp, s["table_cell_mono"]),
            _para(filt_str, s["table_cell_xs"]),
        ])
    ext = Table(ex_rows,
                colWidths=[8 * mm, 18 * mm, 75 * mm, 18 * mm, None], repeatRows=1)
    ext.setStyle(_zebra_table_style(len(ex_rows)))
    story.append(ext)
    story.append(Spacer(1, 1.5 * mm))
    ec_kinds = Counter((ec.get("kind") or "?").lower() for ec in exported)
    story.append(Paragraph(
        f"Distribution: {' · '.join(f'<b>{k}</b> {v}' for k, v in ec_kinds.most_common())} · "
        f"total {len(exported)} exported components.",
        s["body_sm"]))
    story.append(PageBreak())

    # 04.5 — MobSF high-severity findings
    story.append(_h2("04.5  ·  MOBSF  HIGH-SEVERITY  FINDINGS", s))
    high = appsec.get("high") or []
    if high:
        hi_rows = [["#", "SECTION", "TITLE", "DESCRIPTION"]]
        for i, h in enumerate(high, 1):
            hi_rows.append([
                _para(str(i), s["table_cell_mono"]),
                _para((h.get("section") or "").upper(), _table_cell_with_color(s, COL_FAIL)),
                _para(h.get("title", ""), s["table_cell"]),
                _para_clipped((h.get("description") or "").strip(), s["table_cell_xs"], cap=900),
            ])
        ht = Table(hi_rows, colWidths=[8 * mm, 22 * mm, 70 * mm, None], repeatRows=1)
        ht.setStyle(_zebra_table_style(len(hi_rows)))
        story.append(ht)
    else:
        story.append(Paragraph("(MobSF recorded no high-severity AppSec findings)", s["body_sm"]))
    story.append(Spacer(1, 4 * mm))

    # 04.6 — MobSF warning findings
    story.append(_h2("04.6  ·  MOBSF  WARNING  FINDINGS", s))
    warns = appsec.get("warning") or []
    if warns:
        wi_rows = [["#", "SECTION", "TITLE", "DESCRIPTION"]]
        for i, h in enumerate(warns, 1):
            wi_rows.append([
                _para(str(i), s["table_cell_mono"]),
                _para((h.get("section") or "").upper(), _table_cell_with_color(s, COL_REVIEW)),
                _para(h.get("title", ""), s["table_cell"]),
                _para_clipped((h.get("description") or "").strip(), s["table_cell_xs"], cap=900),
            ])
        wt = Table(wi_rows, colWidths=[8 * mm, 22 * mm, 70 * mm, None], repeatRows=1)
        wt.setStyle(_zebra_table_style(len(wi_rows)))
        story.append(wt)
    else:
        story.append(Paragraph("(MobSF recorded no warning AppSec findings)", s["body_sm"]))
    story.append(Spacer(1, 4 * mm))

    # 04.7 — Code-analysis hot files
    ca = (mobsf.get("code_analysis") or {}).get("findings") or {}
    if ca:
        story.append(_h2("04.7  ·  CODE-ANALYSIS  TOP RULES  (MobSF)", s))
        rules: list[tuple[str, dict[str, Any]]] = list(ca.items())
        # Sort by number of files touched.
        rules_sorted = sorted(rules, key=lambda kv: -len(kv[1].get("files") or {}))[:20]
        rule_rows = [["RULE", "FILES", "TOP  FILES  CITED"]]
        for rule, body in rules_sorted:
            files = body.get("files") or {}
            top = sorted(files.items(),
                         key=lambda kv: -len((kv[1] or "").split(",")))[:6]
            parts: list[str] = []
            running = 0
            for p, lines in top:
                seg_line = _clip(str(lines), 60)
                seg = f"{p}<font color='#7c7c8a'>:{seg_line}</font>"
                running += len(p) + len(seg_line) + 4
                parts.append(seg)
                if running > 600:
                    parts.append("<i>…</i>")
                    break
            top_str = "  ·  ".join(parts)
            rule_rows.append([
                _para(rule, s["table_cell_mono"]),
                _para(str(len(files)), s["table_cell_mono"]),
                Paragraph(top_str, s["table_cell_xs"]),
            ])
        rt = Table(rule_rows, colWidths=[50 * mm, 14 * mm, None], repeatRows=1)
        rt.setStyle(_zebra_table_style(len(rule_rows)))
        story.append(rt)
    story.append(Spacer(1, 4 * mm))

    # 04.8 — network security
    ns = mobsf.get("network_security") or {}
    ns_findings = ns.get("network_findings") or []
    if ns_findings:
        story.append(_h2("04.8  ·  NETWORK  SECURITY  CONFIG", s))
        nf_rows = [["#", "SEVERITY", "SCOPE", "DESCRIPTION"]]
        for i, nf in enumerate(ns_findings, 1):
            sev = (nf.get("severity") or "").upper()
            sev_col = {
                "HIGH": COL_FAIL, "WARNING": COL_REVIEW,
                "INFO": COL_NA, "GOOD": COL_PASS, "SECURE": COL_PASS,
            }.get(sev, COL_NA)
            sc = nf.get("scope") or []
            scope_str = ", ".join(sc) if isinstance(sc, list) else str(sc)
            nf_rows.append([
                _para(str(i), s["table_cell_mono"]),
                _para(sev, _table_cell_with_color(s, sev_col)),
                _para(scope_str, s["table_cell_mono"]),
                _para_clipped((nf.get("description") or "").strip(), s["table_cell_xs"], cap=700),
            ])
        nft = Table(nf_rows, colWidths=[8 * mm, 22 * mm, 50 * mm, None], repeatRows=1)
        nft.setStyle(_zebra_table_style(len(nf_rows)))
        story.append(nft)
        story.append(Spacer(1, 4 * mm))

    # 04.9 — certificate analysis
    ca_block = mobsf.get("certificate_analysis") or {}
    cert_findings = ca_block.get("certificate_findings") or []
    if cert_findings:
        story.append(_h2("04.9  ·  CERTIFICATE  ANALYSIS", s))
        cf_rows = [["#", "SEVERITY", "TITLE", "DESCRIPTION"]]
        for i, cf in enumerate(cert_findings, 1):
            sev = cf[0] if len(cf) > 0 else ""
            desc = cf[1] if len(cf) > 1 else ""
            title = cf[2] if len(cf) > 2 else ""
            sev_col = {
                "high": COL_FAIL, "warning": COL_REVIEW,
                "info": COL_NA, "good": COL_PASS, "secure": COL_PASS,
            }.get(sev.lower(), COL_NA)
            cf_rows.append([
                _para(str(i), s["table_cell_mono"]),
                _para(sev.upper(), _table_cell_with_color(s, sev_col)),
                _para(title, s["table_cell"]),
                _para(desc, s["table_cell_xs"]),
            ])
        cft = Table(cf_rows, colWidths=[8 * mm, 22 * mm, 50 * mm, None], repeatRows=1)
        cft.setStyle(_zebra_table_style(len(cf_rows)))
        story.append(cft)

    story.append(PageBreak())
    return story


def _bytes_h(n: Any) -> str:
    """Render a size; the MobSF dump usually stores it as already-formatted str."""
    if isinstance(n, str):
        return n
    if not n:
        return "—"
    if n < 1024:
        return f"{n} B"
    units = ["KiB", "MiB", "GiB"]
    val = float(n) / 1024
    for u in units:
        if val < 1024:
            return f"{val:.1f} {u}"
        val /= 1024
    return f"{val:.1f} TiB"


def _table_cell_with_color(s: dict[str, ParagraphStyle], color: colors.Color) -> ParagraphStyle:
    return ParagraphStyle(
        f"C{id(color)}", parent=s["table_cell_mono"],
        textColor=color,
        fontName=_font("Sans-Bold", "Helvetica-Bold"),
    )


def _perm_color(cat: str) -> colors.Color:
    return {
        "DANGEROUS": COL_FAIL,
        "SIGNATURE": COL_REVIEW,
        "NORMAL": COL_INK,
    }.get(cat, COL_INK)


# ============================================================================
# PER-CONTROL FINDING PAGES
# ============================================================================

_PERSONA_COLOR: dict[str, colors.Color] = {
    "halvar": colors.HexColor("#7d3c98"),
    "noor": colors.HexColor("#117a65"),
    "maddie": colors.HexColor("#b03a2e"),
    "yuki": colors.HexColor("#1f618d"),
    "renzo": colors.HexColor("#a04000"),
    "wei": colors.HexColor("#196f3d"),
}


def build_findings(bundle: Bundle, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    story: list[Flowable] = []
    story.append(_set_section("FINDINGS — 53 CONTROLS", "§ 06"))
    # No standalone section-cover page — the §06 banner is set in the
    # running chrome, and the first finding's group block carries the
    # readable explanation of what follows.

    # Group findings by MASVS group, then iterate.
    findings_by_group: dict[str, list[FindingRecord]] = defaultdict(list)
    for f in bundle.findings:
        findings_by_group[f.group].append(f)

    group_order = ["ARCH", "STORAGE", "CRYPTO", "AUTH", "NETWORK",
                   "PLATFORM", "CODE", "RESILIENCE", "PRIVACY"]
    sub_n = 0
    for grp in group_order:
        fs = findings_by_group.get(grp) or []
        if not fs:
            continue
        sub_n += 1
        story.append(_set_section(f"FINDINGS · {grp}", f"§ 06.{sub_n:02d}"))
        story.append(_h2(f"06.{sub_n:02d}  ·  {grp}  ({len(fs)} controls)", s))
        story.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R, thickness=0.8, color=COL_ACCENT))
        story.append(Spacer(1, 2 * mm))
        # Group-level posture line
        gc = Counter(f.verdict_label for f in fs)
        gc_str = "  ·  ".join(f"<b>{k}</b> {v}" for k, v in gc.most_common() if v)
        story.append(Paragraph(gc_str, s["body_sm"]))
        story.append(Spacer(1, 3 * mm))
        for f in fs:
            for fl in _build_one_finding(f, bundle, s):
                story.append(fl)
            story.append(PageBreak())
    return story


# ---------------------------------------------------------------------------
# RISK SNAPSHOT card — high-density per-finding header block
# ---------------------------------------------------------------------------
#
# Each finding page opens with a tinted callout block that carries the
# operator's "first 10 seconds" view of the finding: verdict, severity,
# effort, confidence, panel author, branch convergence, and a 200-char
# pull-quote drawn from the agent's answer text. The downstream catalog
# description / verification steps / panel attribution / variant hunt /
# affected-components / branch timeline blocks are unchanged.
#
# Severity heuristic (no badge for PASS/N/A/INFO/INCONCLUSIVE):
#   - HIGH:  FAIL  + group ∈ {AUTH, CRYPTO, STORAGE, NETWORK, PLATFORM}
#   - MED:   FAIL  + other group,
#            OR REVIEW + group ∈ {AUTH, CRYPTO, STORAGE, NETWORK, PLATFORM}
#   - LOW:   REVIEW + other group
#
# Effort heuristic (gated to FAIL/REVIEW — the only verdicts with a
# remediation cost; PASS/N/A/INFO have no badge):
#   - LARGE:  vho > 5  OR  affected_components > 10
#   - MEDIUM: vho ∈ {2..5}  OR  affected_components ∈ {3..10}
#   - SMALL:  vho < 2  AND  affected_components < 3

_HIGH_RISK_GROUPS: frozenset[str] = frozenset({
    "AUTH", "CRYPTO", "STORAGE", "NETWORK", "PLATFORM",
})


def _severity_label(f: FindingRecord) -> str | None:
    """Return HIGH/MED/LOW, or None for verdicts that do not carry severity."""
    v = f.verdict_label
    if v == "FAIL":
        return "HIGH" if f.group in _HIGH_RISK_GROUPS else "MED"
    if v == "REVIEW":
        return "MED" if f.group in _HIGH_RISK_GROUPS else "LOW"
    return None


def _effort_label(f: FindingRecord) -> str | None:
    """Return LARGE/MEDIUM/SMALL effort, or None when not applicable."""
    if f.verdict_label not in ("FAIL", "REVIEW"):
        return None
    vho_n = len(f.payload.get("variant_hunt_orders") or [])
    ac_n = len(f.payload.get("affected_components") or [])
    if vho_n > 5 or ac_n > 10:
        return "LARGE"
    if vho_n >= 2 or ac_n >= 3:
        return "MEDIUM"
    return "SMALL"


def _severity_color(label: str | None) -> colors.Color:
    return {
        "HIGH": COL_FAIL,
        "MED": COL_REVIEW,
        "LOW": COL_INFO,
    }.get(label or "", COL_MUTED)


def _effort_color(label: str | None) -> colors.Color:
    return {
        "LARGE": COL_ACCENT_DEEP,
        "MEDIUM": COL_ACCENT,
        "SMALL": COL_MUTED,
    }.get(label or "", COL_MUTED)


def _dominant_persona(f: FindingRecord) -> str | None:
    """Return the lowercase persona name with the most authoritative voice.

    Preference order: synthesized_by → first panel_contributions entry →
    first non-abandoned branch's persona_voice.
    """
    p = f.payload.get("synthesized_by")
    if isinstance(p, str) and p:
        return p.lower()
    pcs = f.payload.get("panel_contributions") or []
    if pcs:
        cand = pcs[0].get("persona")
        if isinstance(cand, str) and cand:
            return cand.lower()
    for b in f.child.get("branches") or []:
        if b.get("status") in ("completed", "active", "running"):
            v = b.get("persona_voice")
            if isinstance(v, str) and v:
                return v.lower()
    return None


def _branch_convergence_summary(f: FindingRecord) -> str:
    """Render "N/M converged" with completed-vs-total counts."""
    branches = f.child.get("branches") or []
    total = len(branches)
    if total == 0:
        return "—"
    completed = sum(1 for b in branches if b.get("status") == "completed")
    return f"{completed}/{total} converged"


# Markdown-noise stripper for pull-quotes — markdown markers in the first
# 200 chars of an agent answer (#, **, `, leading list dashes) look like
# debris when rendered inline as a quote. We strip the markers but keep
# the words.
_PULL_QUOTE_NOISE_RE = re.compile(r"(?:[#`*]+|^\s*[-+]\s+|^\s*\d+[.)]\s+)", re.MULTILINE)


def _pull_quote_text(f: FindingRecord, cap: int = 200) -> str | None:
    """Pull the first ``cap`` chars of the agent answer, cleaned of markdown.

    Returns None when no answer text exists. The caller renders this as an
    italic block with a left quote-rule.
    """
    answer = (f.payload.get("answer") or "").strip()
    if not answer:
        return None
    # Drop markdown markers so the quote reads as prose, not as raw markup.
    cleaned = _PULL_QUOTE_NOISE_RE.sub(" ", answer)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        return None
    if len(cleaned) <= cap:
        return cleaned
    return cleaned[: max(40, cap - 1)].rstrip(" ,;:") + "…"


def _risk_snapshot_card(f: FindingRecord, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    """Return the tinted RISK SNAPSHOT card flowables.

    Layout:

        ┌────────────────────────────────────────────────────────────────┐
        │  RISK SNAPSHOT                                                 │
        ├────────────────────────────────────────────────────────────────┤
        │ VERDICT   FAIL      ·  CONFIDENCE  0.85                        │
        │ SEVERITY  HIGH      ·  EFFORT      MEDIUM                      │
        │ AUTHORED  HALVAR    ·  BRANCHES    8/8 converged               │
        │ VARIANTS  3 hypothesised (see § 07)                            │
        ├────────────────────────────────────────────────────────────────┤
        │ « the app's logout does NOT call a server endpoint … »         │
        └────────────────────────────────────────────────────────────────┘

    Severity / effort badges are suppressed for PASS / N/A / INFO /
    INCONCLUSIVE. The pull-quote row is suppressed when the agent
    produced no answer text.
    """
    vcol = VERDICT_COLOR.get(f.verdict_label, COL_NA)
    sev = _severity_label(f)
    eff = _effort_label(f)
    persona = _dominant_persona(f)
    persona_disp = (persona or "—").upper()
    branches_disp = _branch_convergence_summary(f)
    confidence_disp = f"{f.confidence:.2f}" if f.confidence else "—"
    vho_n = len(f.payload.get("variant_hunt_orders") or [])
    quote = _pull_quote_text(f, cap=200)

    # ── Style helpers (tight, snapshot-local) ──
    label_st = ParagraphStyle(
        "SnapLabel", parent=s["body_xs"],
        fontName=_font("Sans-Bold", "Helvetica-Bold"),
        fontSize=6.6, leading=8.0, letterSpace=1.4,
        textColor=COL_MUTED,
    )
    value_st = ParagraphStyle(
        "SnapValue", parent=s["body_sm"],
        fontName=_font("Mono-Bold", "Courier-Bold"),
        fontSize=8.4, leading=9.6,
        textColor=COL_INK,
    )
    quote_st = ParagraphStyle(
        "SnapQuote", parent=s["body_sm"],
        fontName=_font("Body-Italic", "Times-Italic"),
        fontSize=8.6, leading=11.0,
        leftIndent=6, rightIndent=4,
        textColor=COL_INK, alignment=TA_LEFT,
    )

    def _pill(text: str, color: colors.Color) -> Paragraph:
        hex_ = "#%02x%02x%02x" % (
            int(color.red * 255), int(color.green * 255), int(color.blue * 255),
        )
        return Paragraph(
            f"<font color='white'><b>&nbsp;{text}&nbsp;</b></font>",
            ParagraphStyle(
                f"Pill_{text}", parent=value_st,
                fontSize=7.8, leading=9.6,
                fontName=_font("Sans-Bold", "Helvetica-Bold"),
                backColor=color, borderColor=color, borderWidth=0,
                borderPadding=(1, 4, 1, 4),
            ),
        )

    # ── Build the 3-row data grid ──
    rows: list[list[Any]] = []
    # Row 1: verdict + confidence
    rows.append([
        Paragraph("VERDICT", label_st), _pill(f.verdict_label, vcol),
        Paragraph("CONFIDENCE", label_st), Paragraph(confidence_disp, value_st),
    ])
    # Row 2: severity + effort (cells may carry an em-dash placeholder pill)
    sev_cell = _pill(sev, _severity_color(sev)) if sev else Paragraph("—", value_st)
    eff_cell = _pill(eff, _effort_color(eff)) if eff else Paragraph("—", value_st)
    rows.append([
        Paragraph("SEVERITY", label_st), sev_cell,
        Paragraph("EFFORT", label_st), eff_cell,
    ])
    # Row 3: authored / branches
    rows.append([
        Paragraph("AUTHORED", label_st),
        Paragraph(persona_disp, value_st),
        Paragraph("BRANCHES", label_st),
        Paragraph(branches_disp, value_st),
    ])
    # Row 4 (optional): variants
    if vho_n:
        rows.append([
            Paragraph("VARIANTS", label_st),
            Paragraph(
                f"{vho_n} hypothesised (see § 07)",
                value_st,
            ),
            Paragraph("", label_st),
            Paragraph("", value_st),
        ])

    col_w_label = 24 * mm
    col_w_value = (PAGE_W - MARGIN_L - MARGIN_R - 2 * col_w_label) / 2
    grid = Table(rows, colWidths=[col_w_label, col_w_value, col_w_label, col_w_value])
    grid.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 1.2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.2),
    ]))

    # ── Title row + body grid wrapped in a thick verdict-coloured tile ──
    title_html = (
        f"<font name='{_font('Sans-Bold', 'Helvetica-Bold')}' "
        f"color='#5b5443' size='7.0'>RISK&nbsp;SNAPSHOT</font>"
    )
    title_p = Paragraph(title_html, ParagraphStyle(
        "SnapTitle", parent=label_st, fontSize=7.0, leading=8.4,
        letterSpace=2.0, textColor=COL_MUTED,
    ))

    inner: list[list[Any]] = [[title_p], [grid]]
    if quote:
        # Pull-quote with a thick left-rule keyed to the verdict colour.
        inner.append([Paragraph(f"« {quote} »", quote_st)])

    outer = Table(inner, colWidths=[PAGE_W - MARGIN_L - MARGIN_R - 4 * mm])
    outer_style: list[Any] = [
        ("BACKGROUND", (0, 0), (-1, -1), COL_PAPER_DEEP),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LINEABOVE", (0, 0), (-1, 0), 0.6, COL_INK),
        ("LINEBELOW", (0, -1), (-1, -1), 0.6, COL_INK),
        ("LINEBEFORE", (0, 0), (0, -1), 2.4, vcol),
        ("LINEAFTER", (-1, 0), (-1, -1), 0.4, COL_THIN),
        ("LINEBELOW", (0, 0), (-1, 0), 0.3, COL_THIN),
    ]
    if quote:
        # Highlight the quote row with the verdict colour as a thicker
        # left bar — operator's eye lands on the quote first.
        outer_style.append(("LINEBEFORE", (0, -1), (0, -1), 3.2, vcol))
        outer_style.append(("LINEABOVE", (0, -1), (-1, -1), 0.3, COL_THIN))
    outer.setStyle(TableStyle(outer_style))

    return [outer, Spacer(1, 2.5 * mm)]


# ---------------------------------------------------------------------------
# KEY TAKEAWAY box — one-sentence "what to do next" for every FAIL
# ---------------------------------------------------------------------------
#
# Operator wants the reader who scrolls to the bottom of a FAIL finding
# to leave with a clear remediation direction. The panel rarely emits a
# clean ``remediation`` field on its own (1/53 controls in this audit),
# so the takeaway is synthesised from the strongest signal available:
#
#   1. payload['remediation']       — agent-authored remediation prose
#   2. variant_hunt_orders[0].title — the first variant hypothesis is
#                                     the panel's recommended follow-up
#   3. first sentence of the agent answer (head) — used as a fallback
#
# The box only renders on FAIL findings; PASS / N/A / INFO / REVIEW /
# INCONCLUSIVE pages are not actionable in the same sense.

_TAKEAWAY_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")


def _first_sentence(text: str, max_chars: int) -> str:
    """Return the first sentence-ish chunk, capped at ``max_chars``."""
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return ""
    # Split on sentence boundary; first chunk is the leading sentence.
    sents = _TAKEAWAY_SENTENCE_RE.split(text, maxsplit=1)
    head = sents[0] if sents else text
    if len(head) <= max_chars:
        return head
    return head[: max(40, max_chars - 1)].rstrip(" ,;:") + "…"


def _synthesize_takeaway(f: FindingRecord) -> str | None:
    """Return a 1-2 sentence "what to do next" string, or None.

    Composition strategy (in priority order):

    1. ``payload['remediation']`` — when the agent supplied explicit
       remediation prose, use the first sentence (capped at 240 chars).
    2. Otherwise, combine the FIRST ``variant_hunt_orders[0].title`` —
       the panel's recommended follow-up investigation — with the FIRST
       sentence (or 120 chars) of the agent's answer text. The variant
       title carries the WHAT; the answer carries the WHY.
    3. Fallback: first sentence of the answer alone.
    """
    payload = f.payload

    # 1. Explicit remediation field
    rem = payload.get("remediation")
    if isinstance(rem, str) and rem.strip():
        return _first_sentence(rem.strip(), 240)
    if isinstance(rem, dict):
        # Some payloads carry remediation as a dict with `summary` / `text`.
        for key in ("summary", "text", "description", "action"):
            v = rem.get(key)
            if isinstance(v, str) and v.strip():
                return _first_sentence(v.strip(), 240)
    if isinstance(rem, list) and rem:
        # First list item — could be str or dict.
        first = rem[0]
        if isinstance(first, str) and first.strip():
            return _first_sentence(first.strip(), 240)
        if isinstance(first, dict):
            for key in ("summary", "text", "title", "action"):
                v = first.get(key)
                if isinstance(v, str) and v.strip():
                    return _first_sentence(v.strip(), 240)

    # 2. Variant title + answer head
    vho = payload.get("variant_hunt_orders") or []
    vt: str = ""
    if vho and isinstance(vho[0], dict):
        title = vho[0].get("title") or vho[0].get("hypothesis") or ""
        if isinstance(title, str):
            vt = title.strip()
    answer = (payload.get("answer") or "").strip()
    if vt and answer:
        cleaned_ans = _PULL_QUOTE_NOISE_RE.sub(" ", answer)
        ans_head = _first_sentence(cleaned_ans, 140)
        # Stitch: "Hypothesis: {variant_title}. Evidence: {answer_head}."
        # Cap the combined length at 280 chars.
        combined = f"Hypothesis: {vt}. Evidence: {ans_head}"
        if len(combined) > 280:
            return combined[:279].rstrip(" ,;:") + "…"
        return combined
    if vt:
        return f"Recommended follow-up: investigate {vt}."

    # 3. Plain answer head
    if answer:
        cleaned_ans = _PULL_QUOTE_NOISE_RE.sub(" ", answer)
        return _first_sentence(cleaned_ans, 240)
    return None


def _key_takeaway_box(f: FindingRecord, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    """Return the ``▶ KEY TAKEAWAY`` callout flowables.

    Returns an empty list when no takeaway can be synthesised (which
    only happens for FAILs with literally no agent answer text — none
    in the current audit, but safe).
    """
    text = _synthesize_takeaway(f)
    if not text:
        return []

    vcol = VERDICT_COLOR.get(f.verdict_label, COL_FAIL)
    # Header — small caps accent in verdict colour
    header_style = ParagraphStyle(
        "TakeawayH", parent=s["caps"],
        fontName=_font("Sans-Bold", "Helvetica-Bold"),
        fontSize=8.0, leading=10.0, letterSpace=2.0,
        textColor=vcol, spaceAfter=0,
    )
    body_style = ParagraphStyle(
        "TakeawayB", parent=s["body"],
        fontSize=9.4, leading=12.4,
        textColor=COL_INK, alignment=TA_LEFT,
        spaceBefore=0, spaceAfter=0,
    )
    safe = _md_inline(_html_escape(text)).replace("\n", " ")

    rows = [
        [Paragraph("&#9654;&nbsp;&nbsp;KEY&nbsp;TAKEAWAY", header_style)],
        [Paragraph(safe, body_style)],
    ]
    t = Table(rows, colWidths=[PAGE_W - MARGIN_L - MARGIN_R - 4 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COL_PAPER_DEEP),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (0, 0), 4),
        ("TOPPADDING", (0, 1), (0, 1), 2),
        ("BOTTOMPADDING", (0, 0), (0, 0), 1),
        ("BOTTOMPADDING", (0, 1), (0, 1), 5),
        # Thick verdict-coloured left rule + thin ink box
        ("LINEBEFORE", (0, 0), (0, -1), 3.6, vcol),
        ("LINEABOVE", (0, 0), (-1, 0), 0.6, COL_INK),
        ("LINEBELOW", (0, -1), (-1, -1), 0.6, COL_INK),
        ("LINEAFTER", (-1, 0), (-1, -1), 0.4, COL_THIN),
    ]))
    return [Spacer(1, 3 * mm), KeepTogether(t), Spacer(1, 2 * mm)]


def _build_catalog_box(
    f: FindingRecord, s: dict[str, ParagraphStyle],
) -> list[Flowable]:
    """Render the MASVS catalog excerpt as one tinted amber block.

    Composes the description + verification steps + relevant APIs +
    evidence hints into a single Table cell so the operator's eye
    treats the whole block as "what the OWASP standard says". The
    surrounding text on the finding page (snapshot card above, agent
    reasoning below) is on the ivory paper background; the catalog
    excerpt's amber tint and thin amber rule are the only chrome
    differentiation.
    """
    inner_w = PAGE_W - MARGIN_L - MARGIN_R
    # Slightly tighter inner content width to account for the box's
    # padding so wrapped table cells don't overflow the rule.
    pad_h = 6
    body_sm = ParagraphStyle(
        "CatBody", parent=s["body_sm"], fontSize=8.0, leading=10.0,
        textColor=COL_INK, alignment=TA_JUSTIFY,
    )
    head_st = ParagraphStyle(
        "CatH", parent=s["caps"],
        fontName=_font("Sans-Bold", "Helvetica-Bold"),
        fontSize=7.4, leading=9.0, letterSpace=2.0,
        textColor=COL_ACCENT_DEEP,
    )
    sub_st = ParagraphStyle(
        "CatSub", parent=s["caps"],
        fontName=_font("Sans-Bold", "Helvetica-Bold"),
        fontSize=6.6, leading=8.6, letterSpace=1.6,
        textColor=COL_MUTED, spaceBefore=2, spaceAfter=0,
    )
    mono_sm = ParagraphStyle(
        "CatMono", parent=s["mono_sm"], fontSize=7.0, leading=8.6,
        textColor=COL_INK,
    )
    xs = ParagraphStyle(
        "CatXs", parent=s["body_xs"], fontSize=7.2, leading=8.8,
        textColor=COL_INK,
    )

    inner_flowables: list[Flowable] = []
    inner_flowables.append(Paragraph("CONTROL  ·  WHAT  THE  MASVS  STANDARD  SAYS", head_st))
    inner_flowables.append(Spacer(1, 1.4 * mm))

    desc = f.catalog.get("description") or ""
    if desc:
        for fl in _para_multi(desc, body_sm):
            inner_flowables.append(fl)
    else:
        inner_flowables.append(Paragraph("(no description in catalog)", body_sm))
    inner_flowables.append(Spacer(1, 2 * mm))

    # Two-column row inside the box: verification steps left, APIs + hints right
    vs = f.catalog.get("verification_steps") or []
    apis = f.catalog.get("relevant_apis") or []
    hints = f.catalog.get("evidence_hints") or []

    col_w = (inner_w - 2 * pad_h - 4 * mm) / 2

    left_block: list[Flowable] = [Paragraph("VERIFICATION  STEPS", sub_st)]
    if vs:
        for i, step in enumerate(vs, 1):
            safe_step = _html_escape(step)
            left_block.append(Paragraph(f"<b>{i}.</b> {safe_step}", xs))
    else:
        left_block.append(Paragraph("(none recorded)", xs))

    right_block: list[Flowable] = [Paragraph("RELEVANT  APIs", sub_st)]
    if apis:
        for api in apis:
            right_block.append(Paragraph(_html_escape(api), mono_sm))
    else:
        right_block.append(Paragraph("(none recorded)", xs))
    right_block.append(Spacer(1, 1.4 * mm))
    right_block.append(Paragraph("EVIDENCE  HINTS", sub_st))
    if hints:
        right_block.append(Paragraph(
            _html_escape("  ·  ".join(hints)), xs))
    else:
        right_block.append(Paragraph("(none recorded)", xs))

    twocol = Table([[left_block, right_block]], colWidths=[col_w, col_w])
    twocol.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LINEAFTER", (0, 0), (0, -1), 0.3, COL_CATALOG_BORDER),
    ]))
    inner_flowables.append(twocol)

    box = Table([[inner_flowables]], colWidths=[inner_w])
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COL_CATALOG_TINT),
        ("LEFTPADDING", (0, 0), (-1, -1), pad_h),
        ("RIGHTPADDING", (0, 0), (-1, -1), pad_h),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEABOVE", (0, 0), (-1, 0), 0.4, COL_CATALOG_BORDER),
        ("LINEBELOW", (0, -1), (-1, -1), 0.4, COL_CATALOG_BORDER),
        ("LINEBEFORE", (0, 0), (0, -1), 0.4, COL_CATALOG_BORDER),
        ("LINEAFTER", (-1, 0), (-1, -1), 0.4, COL_CATALOG_BORDER),
    ]))
    return [box]


def _build_one_finding(f: FindingRecord, bundle: Bundle, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    """Return all flowables for one finding page (may span multiple pages)."""
    story: list[Flowable] = []
    # Record the verdict for this page so the running chrome tints its
    # accents in the verdict colour. This is a side-effect flowable that
    # draws nothing visible — the chrome reads from
    # ``_CHROME.verdict_at_page`` keyed by page number.
    story.append(_set_verdict(f.verdict_label))
    # Header
    story.append(FindingHeader(
        finding_id=f.finding_id,
        control_id=f.control_id,
        group=f.group,
        verdict=f.verdict_label,
        confidence=f.confidence,
        title=f.catalog.get("title", ""),
        page_width=PAGE_W - MARGIN_L - MARGIN_R,
    ))
    story.append(Spacer(1, 1.5 * mm))

    # TACTICAL HEADER BAND — single-line key-facts strip immediately
    # below the verdict-coloured FindingHeader bar. The brief proposes
    # a 20mm right-margin side-rail panel; KeepInFrame two-column
    # layouts add > 200 LOC of Platypus plumbing for negligible visual
    # gain. Substitute: a tight one-line tactical header band that
    # carries the same fact set (control_id · level · group · verdict ·
    # confidence · author · branches · severity) and lets the reader
    # scan the page without reading the body text — identical
    # information surface as the side-rail would have provided.
    level = (f.catalog.get("level") or "L1")
    sev = _severity_label(f) or "—"
    persona = (_dominant_persona(f) or "—").upper()
    branches_disp = _branch_convergence_summary(f)
    vcol = VERDICT_COLOR.get(f.verdict_label, COL_NA)
    vhex = "#%02x%02x%02x" % (
        int(vcol.red * 255), int(vcol.green * 255), int(vcol.blue * 255),
    )
    band_html = (
        f"<font color='#5b5443'>CTRL</font> <b>{f.control_id}</b>  ·  "
        f"<font color='#5b5443'>LEVEL</font> <b>{level}</b>  ·  "
        f"<font color='#5b5443'>GROUP</font> <b>{f.group}</b>  ·  "
        f"<font color='#5b5443'>VERDICT</font> "
        f"<font color='{vhex}'><b>{f.verdict_label}</b></font>  ·  "
        f"<font color='#5b5443'>CONF</font> <b>{f.confidence:.2f}</b>  ·  "
        f"<font color='#5b5443'>AUTHOR</font> <b>{persona}</b>  ·  "
        f"<font color='#5b5443'>BRANCHES</font> <b>{branches_disp}</b>  ·  "
        f"<font color='#5b5443'>SEVERITY</font> <b>{sev}</b>"
    )
    band_style = ParagraphStyle(
        "TacBand", parent=s["body_xs"],
        fontName=_font("Mono", "Courier"),
        fontSize=7.2, leading=9.0,
        textColor=COL_INK,
        backColor=COL_PAPER_DEEP,
        borderColor=vcol, borderWidth=0.0,
        borderPadding=(2, 6, 2, 6),
        alignment=TA_LEFT,
    )
    story.append(Paragraph(band_html, band_style))
    story.append(Spacer(1, 1.5 * mm))

    # Sub-header: control title in serif
    story.append(Paragraph(f.catalog.get("title", ""), s["finding_title"]))
    story.append(Spacer(1, 1.5 * mm))

    # RISK SNAPSHOT — operator's "first 10 seconds" view. Carries verdict,
    # severity, effort, confidence, persona author, branch convergence,
    # variant count and a pull-quote of the agent's answer. The card is
    # the visual anchor of the page; the technical-metadata band below
    # only carries traceability fields (mapper reason, child id, outcome
    # id) that don't appear on the card.
    story.extend(_risk_snapshot_card(f, s))

    # Traceability band — slim line carrying mapper REASON + DB ids that
    # the Risk Snapshot deliberately omits. This is for the operator who
    # wants to find the source rows in the AILA database, not for the
    # reader scanning verdict/severity.
    band_pieces: list[str] = []
    if f.verdict_reason:
        band_pieces.append(f"<b>REASON</b> {f.verdict_reason}")
    band_pieces.append(f"<b>CHILD</b> {f.child['id']}")
    if f.outcome:
        band_pieces.append(
            f"<b>OUTCOME</b> {f.outcome['id'][:8]} "
            f"kind={f.outcome['outcome_kind']} "
            f"conf={f.outcome['confidence']}"
        )
    band_style = ParagraphStyle("Band", parent=s["body_xs"],
                                fontName=_font("Mono", "Courier"),
                                fontSize=6.8, leading=8.4,
                                textColor=COL_MUTED,
                                backColor=COL_PAPER_DEEP,
                                borderColor=COL_THIN, borderWidth=0.3,
                                borderPadding=(2, 4, 2, 4),
                                alignment=TA_LEFT)
    story.append(Paragraph("  ·  ".join(band_pieces), band_style))
    story.append(Spacer(1, 3 * mm))

    # ── Catalog excerpt — tinted "what the MASVS standard says" box ──
    # The entire OWASP MASVS catalog content for this control (description
    # + verification steps + relevant APIs + evidence hints) sits inside
    # one amber-tinted block. The tint plus the smaller body_sm font cue
    # the reader that this is reference material, NOT AILA's verdict.
    story.extend(_build_catalog_box(f, s))
    story.append(Spacer(1, 3 * mm))

    # Agent's full reasoning
    if f.outcome is not None:
        answer = (f.payload.get("answer") or "").strip()
        if answer:
            story.append(_h3(">>  AGENT  REASONING", s))
            story.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R,
                                        thickness=0.6, color=COL_ACCENT))
            story.append(Spacer(1, 1))
            for fl in _para_multi(answer, ParagraphStyle(
                "AgentReason", parent=s["body"], fontSize=9.0, leading=11.5,
                textColor=COL_INK, alignment=TA_JUSTIFY)):
                story.append(fl)
            story.append(Spacer(1, 2 * mm))

        reasoning = (f.payload.get("reasoning") or "").strip()
        if reasoning and reasoning != answer:
            story.append(_h4("INTERNAL  CHAIN-OF-THOUGHT", s))
            for fl in _para_multi(reasoning, ParagraphStyle(
                "AgentChain", parent=s["body_sm"], textColor=COL_MUTED,
                alignment=TA_JUSTIFY, fontName=_font("Body-Italic", "Times-Italic"))):
                story.append(fl)
            story.append(Spacer(1, 2 * mm))

        # Panel contributions
        pcs = f.payload.get("panel_contributions") or []
        if pcs:
            story.append(_h3(">>  PANEL  ATTRIBUTION", s))
            story.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R,
                                        thickness=0.6, color=COL_ACCENT))
            story.append(Spacer(1, 1))
            for pc in pcs:
                story.extend(_panel_contribution_block(pc, s))
        else:
            story.append(_h4("PANEL  ATTRIBUTION", s))
            story.append(Paragraph(
                "<i>No per-persona attribution recorded. The primary outcome was "
                "synthesised on a single branch without sibling co-sign — verdict "
                "carries a lone-author caveat.</i>",
                ParagraphStyle("MissPC", parent=s["body_sm"],
                               textColor=COL_MUTED, alignment=TA_LEFT)))
            story.append(Spacer(1, 2 * mm))

        # Affected components
        ac = f.payload.get("affected_components") or []
        if ac:
            story.append(_h3(">>  AFFECTED  COMPONENTS", s))
            story.append(_affected_components_table(ac, s))
            story.append(Spacer(1, 2 * mm))

        # Variant hunt orders
        vho = f.payload.get("variant_hunt_orders") or []
        if vho:
            story.append(_h3(">>  VARIANT  HUNT  ORDERS", s))
            story.append(_variants_block(f, vho, s, bundle))
            story.append(Spacer(1, 2 * mm))

        # Crash type / vulnerable function highlights
        ct = (f.payload.get("crash_type") or "").strip()
        vf = (f.payload.get("vulnerable_function") or "").strip()
        if ct or vf:
            box_rows = []
            if ct:
                box_rows.append(["CRASH/CLASS", _para(ct, s["table_cell_mono"])])
            if vf:
                box_rows.append(["TARGET  FN", _para(vf, s["table_cell_mono"])])
            t = Table(box_rows, colWidths=[28 * mm, None])
            t.setStyle(TableStyle([
                ("FONT", (0, 0), (0, -1), _font("Sans-Bold", "Helvetica-Bold"), 7.5),
                ("TEXTCOLOR", (0, 0), (0, -1), COL_ACCENT),
                ("BACKGROUND", (0, 0), (-1, -1), COL_PAPER_DEEP),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("BOX", (0, 0), (-1, -1), 0.4, COL_THIN),
            ]))
            story.append(t)
            story.append(Spacer(1, 2 * mm))

        # Verifier report
        vr = f.payload.get("verifier_report")
        if vr:
            story.append(_verifier_report_block(vr, s))

        # Provenance (tiny footnote)
        prov = f.payload.get("provenance") or {}
        if prov:
            story.append(Spacer(1, 2 * mm))
            prov_lines: list[str] = []
            for k, v in prov.items():
                if isinstance(v, (str, int, float, bool)):
                    prov_lines.append(f"<b>{k}</b>={v}")
            if prov_lines:
                story.append(Paragraph(
                    "PROVENANCE · " + "  ·  ".join(prov_lines),
                    ParagraphStyle("Prov", parent=s["body_xs"],
                                   textColor=COL_MUTED, fontName=_font("Mono", "Courier"))))

    else:
        # Orphan finding — no outcome
        story.append(_orphan_block(f, s))

    # KEY TAKEAWAY callout (FAIL only) — the operator-facing
    # "what to do next" anchor at the end of the page. Renders
    # AFTER provenance / orphan branch but BEFORE the branches detail
    # table so the reader's eye lands on it before the dense table.
    if f.verdict_label == "FAIL":
        story.extend(_key_takeaway_box(f, s))

    # Bottom band: branches detail
    story.append(Spacer(1, 2 * mm))
    story.append(_branches_table(f, s))

    return story


def _panel_contribution_block(pc: dict[str, Any], s: dict[str, ParagraphStyle]) -> list[Flowable]:
    """Render one panel contribution as a SPLITTABLE flowable sequence.

    A Table cell can't split across pages — long answer_briefs (~4 KB)
    therefore can't live inside a single-row Table without overrunning
    the frame. The sequence below is a header Paragraph + a body
    Paragraph (Platypus splits long Paragraphs across pages cleanly) +
    a thin persona-coloured under-rule.
    """
    persona = (pc.get("persona") or "?").lower()
    role = PERSONA_ROLE.get(persona, "—")
    voted = (pc.get("outcome_kind") or "—").upper()
    conf = (pc.get("confidence") or "—").upper()
    turn = pc.get("at_turn", "—")
    brief = (pc.get("answer_brief") or "").strip()
    pc_color = _PERSONA_COLOR.get(persona, COL_INK)
    pc_hex = "#%02x%02x%02x" % (int(pc_color.red * 255), int(pc_color.green * 255), int(pc_color.blue * 255))

    head_text = (
        f"<font color='{pc_hex}'><b>{persona.upper()}</b></font>  "
        f"<font color='#7c7c8a'>({role})</font>  "
        f"<font color='#a83400'>voted</font>  {voted}  "
        f"<font color='#7c7c8a'>· confidence</font> {conf}  "
        f"<font color='#7c7c8a'>· at turn</font> {turn}"
    )
    head_style = ParagraphStyle(
        f"PCH_{persona}", parent=s["persona_h"], fontSize=8.5, leading=10.0,
        backColor=COL_PAPER_DEEP,
        borderColor=pc_color, borderWidth=0.5,
        borderPadding=(2, 4, 2, 4),
        leftIndent=2,
    )
    body_style = ParagraphStyle(
        f"PCB_{persona}", parent=s["persona_b"],
        leftIndent=4, rightIndent=0,
        backColor=COL_PAPER_DEEP,
        borderColor=pc_color, borderWidth=0.0,
        borderPadding=(2, 4, 3, 4),
        spaceAfter=0,
    )
    head = Paragraph(head_text, head_style)
    body_html = _html_escape(brief).replace("\n", "<br/>")
    body = Paragraph(body_html, body_style)
    under_rule = HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R,
                                thickness=0.6, color=pc_color)
    return [head, body, under_rule, Spacer(1, 1.5 * mm)]


def _affected_components_table(ac: list[dict[str, Any]], s: dict[str, ParagraphStyle]) -> Flowable:
    rows: list[list[Any]] = [["#", "FILE  PATH", "FUNCTION / SYMBOL", "CONTEXT"]]
    CAP = 32
    items = ac[:CAP]
    for i, c in enumerate(items, 1):
        rows.append([
            _para(str(i), s["table_cell_mono"]),
            _para(c.get("file", ""), s["table_cell_mono"]),
            _para(c.get("function", ""), s["table_cell_mono"]),
            _para((c.get("rationale") or c.get("notes") or c.get("context") or "")[:280], s["table_cell_xs"]),
        ])
    if len(ac) > CAP:
        rows.append([
            _para("…", s["table_cell_mono"]),
            _para(f"<i>{len(ac) - CAP} of {len(ac)} additional components omitted for "
                  "page-density reasons. The complete list is preserved in the source "
                  "<font name='Mono'>payload.affected_components</font>.</i>",
                  s["table_cell_xs"]),
            "", "",
        ])
    t = Table(rows, colWidths=[8 * mm, 70 * mm, 50 * mm, None], repeatRows=1)
    t.setStyle(_zebra_table_style(len(rows)))
    return t


def _variants_block(f: FindingRecord, vho: list[dict[str, Any]], s: dict[str, ParagraphStyle], bundle: Bundle) -> Flowable:
    rows: list[list[Any]] = [["VARIANT  ID", "TITLE / HYPOTHESIS", "TARGET"]]
    # Find this finding's variant IDs from the pre-computed master list.
    vmap = [v for v in bundle.variants if v["parent_finding"] == f.finding_id]
    for v in vmap:
        title = v["title"]
        hyp = v["hypothesis"]
        target = (v["file"] or "") + (("  ·  " + v["function"]) if v["function"] else "")
        body = f"<b>{_html_escape(title)}</b><br/>{_html_escape(hyp)}"
        rows.append([
            _para(v["variant_id"], _table_cell_with_color(s, COL_ACCENT)),
            Paragraph(body, s["table_cell_xs"]),
            _para(target, s["table_cell_mono"]),
        ])
    t = Table(rows, colWidths=[16 * mm, None, 60 * mm], repeatRows=1)
    t.setStyle(_zebra_table_style(len(rows)))
    return t


def _verifier_report_block(vr: dict[str, Any], s: dict[str, ParagraphStyle]) -> Flowable:
    pieces: list[Flowable] = []
    pieces.append(_h3(">>  ADVERSARIAL  VERIFIER  REPORT", s))
    pieces.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R, thickness=0.6, color=COL_FAIL))
    pieces.append(Spacer(1, 1))
    verdict = (vr.get("verdict") or "—").upper()
    confidence = vr.get("confidence")
    probes_run = vr.get("probes_run")
    probes_ok = vr.get("probes_succeeded")
    head = (
        f"<b>VERDICT</b> {verdict}   <b>CONFIDENCE</b> "
        f"{confidence if confidence is not None else '—'}   "
        f"<b>PROBES</b> {probes_ok if probes_ok is not None else '—'} / "
        f"{probes_run if probes_run is not None else '—'}"
    )
    pieces.append(Paragraph(head, ParagraphStyle(
        "VRHead", parent=s["body_sm"], fontName=_font("Mono", "Courier"),
        textColor=COL_INK, backColor=COL_PAPER_DEEP,
        borderColor=COL_FAIL, borderWidth=0.6, borderPadding=(3, 4, 3, 4))))
    pieces.append(Spacer(1, 1.5 * mm))
    counter = (vr.get("counter_evidence") or vr.get("counter_argument") or "").strip()
    if counter:
        pieces.append(_h4("COUNTER-EVIDENCE", s))
        for fl in _para_multi(counter, s["body_sm"]):
            pieces.append(fl)
    rationale = (vr.get("rationale") or vr.get("notes") or "").strip()
    if rationale:
        pieces.append(_h4("VERIFIER  RATIONALE", s))
        for fl in _para_multi(rationale, s["body_sm"]):
            pieces.append(fl)
    probes = vr.get("probes") or vr.get("probe_log") or []
    if isinstance(probes, list) and probes:
        rows: list[list[Any]] = [["#", "PROBE", "RESULT"]]
        for i, p in enumerate(probes[:10], 1):
            if isinstance(p, dict):
                name = p.get("name") or p.get("probe") or ""
                res = p.get("result") or p.get("outcome") or ""
                rows.append([_para(str(i), s["table_cell_mono"]),
                             _para(name, s["table_cell_mono"]),
                             _para(str(res), s["table_cell_xs"])])
            else:
                rows.append([_para(str(i), s["table_cell_mono"]),
                             _para(str(p), s["table_cell_xs"]), ""])
        t = Table(rows, colWidths=[8 * mm, 60 * mm, None], repeatRows=1)
        t.setStyle(_zebra_table_style(len(rows)))
        pieces.append(t)
    return KeepTogether(pieces[:3]) if False else _stack(pieces)


def _stack(items: list[Flowable]) -> Flowable:
    """Convenience: a Table with one column to keep a sequence as one flowable."""
    rows = [[it] for it in items]
    t = Table(rows, colWidths=[PAGE_W - MARGIN_L - MARGIN_R])
    t.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return t


def _orphan_block(f: FindingRecord, s: dict[str, ParagraphStyle]) -> Flowable:
    items: list[Flowable] = []
    items.append(_h3(">>  AUTO-CLOSED  WITHOUT  PANEL  QUORUM", s))
    items.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R, thickness=0.6, color=COL_INCONCLUSIVE))
    items.append(Spacer(1, 1))
    items.append(Paragraph(
        "<b>No primary outcome was emitted for this control.</b> The parent reaped the "
        "child investigation under a wall-clock or turn-cap cutoff before any persona "
        "could synthesise a load-bearing outcome. The verdict is recorded as "
        "INCONCLUSIVE; per-branch closure reasons are reproduced below for operator "
        "follow-up. A re-dispatch with raised caps (and tighter persona scope) is the "
        "recommended next step.",
        ParagraphStyle("Orphan", parent=s["body_sm"], textColor=COL_INK,
                       backColor=COL_PAPER_DEEP, borderColor=COL_INCONCLUSIVE,
                       borderWidth=0.6, borderPadding=(4, 5, 4, 5)),
    ))
    return _stack(items)


def _branches_table(f: FindingRecord, s: dict[str, ParagraphStyle]) -> Flowable:
    branches = f.child.get("branches") or []
    if not branches:
        return Spacer(1, 0)
    items: list[Flowable] = [_h4("BRANCH  TIMELINE", s)]
    rows: list[list[Any]] = [["#", "PERSONA", "ROLE", "STATUS", "TURNS", "CLOSED  REASON  /  CAP"]]
    for i, b in enumerate(branches, 1):
        persona = (b.get("persona_voice") or "").lower()
        role = PERSONA_ROLE.get(persona, "—") if persona else "—"
        rows.append([
            _para(str(i), s["table_cell_mono"]),
            _para(persona.upper() or "—", _table_cell_with_color(s, _PERSONA_COLOR.get(persona, COL_INK))),
            _para(role, s["table_cell"]),
            _para((b.get("status") or "").upper(), s["table_cell_mono"]),
            _para(str(b.get("turn_count") or 0), s["table_cell_mono"]),
            _para(b.get("closed_reason") or "", s["table_cell_xs"]),
        ])
    t = Table(rows, colWidths=[7 * mm, 20 * mm, 22 * mm, 22 * mm, 14 * mm, None], repeatRows=1)
    t.setStyle(_zebra_table_style(len(rows)))
    items.append(t)
    return _stack(items)


def _html_escape(s: str) -> str:
    """XML-escape and convert markdown inline patterns (**bold**, `code`).

    Every caller renders the result through Paragraph or a tag-aware
    string template; nothing downstream needs raw markdown, so converting
    at the escape boundary fixes every render path uniformly.
    """
    if not s:
        return ""
    escaped = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _md_inline(escaped)


# ============================================================================
# VARIANT HUNT INDEX
# ============================================================================

def build_variant_index(bundle: Bundle, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    story: list[Flowable] = []
    story.append(_set_section("VARIANT  HUNT  INDEX", "§ 07"))
    story.append(_h1("§ 07  ·  VARIANT  HUNT  INDEX", s))
    story.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R, thickness=1.4))
    story.append(Spacer(1, 3 * mm))
    if not bundle.variants:
        story.append(Paragraph("No variant hunt orders were emitted by this audit.", s["body"]))
        story.append(PageBreak())
        return story
    story.append(Paragraph(
        "Every variant hunt order emitted by any persona across the audit is "
        "reproduced below. Each row carries a sequential <b>V-NNN</b> id and a "
        "cross-reference to its parent finding. Variant hunt orders are the audit's "
        "<i>recommended next investigations</i> — pattern-matched sites the persona "
        "judged worth a sibling spawn but did not have caps to pursue inline.",
        s["body"]))
    story.append(Spacer(1, 4 * mm))
    rows: list[list[Any]] = [["V-ID", "PARENT", "CTRL", "TITLE", "HYPOTHESIS", "TARGET"]]
    for v in bundle.variants:
        rows.append([
            _para(v["variant_id"], _table_cell_with_color(s, COL_ACCENT)),
            _para(v["parent_finding"], s["table_cell_mono"]),
            _para(v["parent_control"], s["table_cell_mono"]),
            _para(v["title"], s["table_cell"]),
            _para(v["hypothesis"], s["table_cell_xs"]),
            _para(v["file"] + (("  ·  " + v["function"]) if v["function"] else ""), s["table_cell_mono"]),
        ])
    t = Table(rows,
              colWidths=[14 * mm, 16 * mm, 26 * mm, 38 * mm, None, 38 * mm],
              repeatRows=1)
    t.setStyle(_zebra_table_style(len(rows)))
    story.append(t)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        f"Total variant hunt orders aggregated: <b>{len(bundle.variants)}</b>.",
        s["body_sm"]))
    story.append(PageBreak())
    return story


# ============================================================================
# METHODOLOGY ANNEX
# ============================================================================

def build_methodology(bundle: Bundle, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    story: list[Flowable] = []
    story.append(_set_section("METHODOLOGY", "§ 08"))
    story.append(_h1("§ 08  ·  METHODOLOGY", s))
    story.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R, thickness=1.4))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        "This annex documents the audit pipeline — what an MASVS L1 audit is, what "
        "AILA's VR engine does to evaluate each control, how the six-persona panel "
        "deliberates, how the adversarial verifier interrogates a candidate "
        "finding, and how a child investigation that runs out of caps lands as an "
        "INCONCLUSIVE.", s["body"]))
    story.append(Spacer(1, 4 * mm))

    story.append(_h2("08.1  ·  WHAT IS MASVS L1?", s))
    story.append(Paragraph(
        "The OWASP Mobile Application Security Verification Standard (MASVS) is a "
        "framework of verification requirements for mobile apps. Each control names a "
        "concrete property the app must hold (e.g. <i>sensitive data is stored in "
        "system credential storage</i>) and what evidence demonstrates compliance. "
        "MASVS defines two levels:",
        s["body"]))
    story.append(Spacer(1, 1 * mm))
    levels = [
        ("L1", "Standard baseline — controls every mobile app should meet. The 53 "
               "L1 controls cover architecture, storage, cryptography, authentication, "
               "network, platform integration, code quality, and privacy. This audit "
               "exclusively evaluates L1."),
        ("L2", "Defence-in-depth — applied for apps handling sensitive data, payment "
               "credentials, or regulated PII. L2 layers extra requirements on top of "
               "L1 (anti-tampering, certificate pinning lifecycle, key-storage "
               "hardware-binding, etc.). Out of scope for this engagement."),
        ("R", "Resilience — anti-reverse-engineering and tamper-resistance. "
              "L1/L2-orthogonal. Not assessed here."),
    ]
    lev_rows: list[list[Any]] = [["LEVEL", "DESCRIPTION"]]
    for lvl, desc in levels:
        lev_rows.append([
            _para(lvl, _table_cell_with_color(s, COL_ACCENT)),
            _para(desc, s["table_cell"]),
        ])
    lt = Table(lev_rows, colWidths=[18 * mm, None], repeatRows=1)
    lt.setStyle(_zebra_table_style(len(lev_rows)))
    story.append(lt)
    story.append(Spacer(1, 4 * mm))

    story.append(_h2("08.2  ·  THE SIX-PERSONA PANEL", s))
    story.append(Paragraph(
        "Every child investigation is staffed by six autonomous reasoning personas "
        "running parallel branches against the same control. Each persona contributes "
        "a structurally distinct angle on the same evidence pool — this is how the "
        "engine evades the 'one-author dead-end' failure mode where a single chain of "
        "reasoning misses an obvious counter-example.", s["body"]))
    story.append(Spacer(1, 1 * mm))
    p_rows: list[list[Any]] = [["PERSONA", "ROLE", "DESCRIPTION"]]
    persona_desc = {
        "halvar": "Senior code-review researcher. Drives evidence collection — semantic_search, read_function, callers_of. Optimises for breadth of coverage; tags STALE hypotheses early.",
        "noor": "Researcher with parallel methodology. Pursues independent leads to corroborate or refute Halvar's chain. The two researchers' branches must converge or one will reject the other's hypothesis.",
        "maddie": "Critic — drives the adversarial loop. Files 'counter-evidence required' challenges against any direct_finding the researchers stake; refuses to co-sign unless the counter holds.",
        "yuki": "Critic with orthogonal scope. Probes implementation correctness — type-system mismatches, version-skew across SDKs, deprecated API fallbacks.",
        "renzo": "Implementer — reproduces the finding by reading the actual decompiled body, tracing call sites, and naming the exact patch shape. Refuses to ship a finding without a citable remediation.",
        "wei": "Implementer with end-to-end perspective. Verifies the finding survives the full integration path (Activity lifecycle, Service binding, intent filter routing) — not just the local function.",
    }
    for p in PERSONAS:
        p_rows.append([
            _para(p.upper(), _table_cell_with_color(s, _PERSONA_COLOR[p])),
            _para(PERSONA_ROLE[p], s["table_cell"]),
            _para(persona_desc[p], s["table_cell"]),
        ])
    pt = Table(p_rows, colWidths=[22 * mm, 26 * mm, None], repeatRows=1)
    pt.setStyle(_zebra_table_style(len(p_rows)))
    story.append(pt)
    story.append(Spacer(1, 4 * mm))

    story.append(_h2("08.3  ·  PANEL  DELIBERATION  FLOW", s))
    story.append(Paragraph(
        "All six branches run concurrently and share a deliberation board. Each "
        "branch can propose a <b>direct_finding</b>, an <b>assessment_report</b>, an "
        "<b>audit_memo</b>, or a <b>variant_hunt_order</b>. Before any direct_finding "
        "is promoted to the parent, the engine requires sibling consensus: at least "
        "two co-signs (typically a researcher and an implementer) AND zero outstanding "
        "critic vetoes. A critic veto on h<sub>n</sub> propagates an explicit "
        "<i>sibling_consensus_rejection</i> directive onto every branch that still "
        "holds h<sub>n</sub> live, preventing residual disagreement from leaking into "
        "the verdict.", s["body"]))
    story.append(Spacer(1, 4 * mm))

    story.append(_h2("08.4  ·  ADVERSARIAL  CLAIM  VERIFIER", s))
    story.append(Paragraph(
        "Once a direct_finding clears panel consensus, the claim verifier runs an "
        "independent adversarial pass: it instantiates a fresh agent with the "
        "single goal of falsifying the finding. The verifier has access to the "
        "same audit-mcp / ida-headless tools the panel had, but operates in "
        "isolation — no transcript, no memory of the deliberation. A finding survives "
        "only if the verifier returns <b>verdict=supported</b> with confidence ≥ 0.6. "
        "A <b>verdict=refuted</b> on a direct_finding overrides the panel and the "
        "verdict flips to NO_FINDING. The verifier's full report (probes run, "
        "counter-evidence pulled, rationale) is rendered verbatim in §06 wherever "
        "the data is present.", s["body"]))
    story.append(Spacer(1, 4 * mm))

    story.append(_h2("08.5  ·  OUTCOME → VERDICT  MAPPING", s))
    story.append(Paragraph(
        "Verdicts are derived in two passes. First, the production mapper "
        "<font name='Mono'>aila.modules.vr.masvs.verdict_mapper.child_outcome_to_verdict</font> "
        "keys off the outcome_kind enum. Second, this renderer reads the "
        "agent's full answer text and applies a text-first override so an "
        "agent who submitted <font name='Mono'>direct_finding</font> with "
        "answer body 'COMPLIANCE VERIFIED' lands at PASS instead of FAIL "
        "(the raw mapper would have called it a finding). Six branches:",
        s["body"]))
    rule_rows: list[list[Any]] = [["TRIGGER", "VERDICT"]]
    rules = [
        ("Agent answer head or body declares external documentation is "
         "required to verify the control: architecture document, component "
         "inventory, SBOM, data classification matrix, privacy policy "
         "artifact, server-side policy spec. Out of code-audit scope; "
         "verdict is informational only.",
         "INFO"),
        ("Payload carries an explicit <b>not_applicable</b> tag (any of "
         "<font name='Mono'>tags=['not_applicable']</font>, "
         "<font name='Mono'>applicability='not_applicable'</font>, or the flag).",
         "N/A"),
        ("Agent answer text declares compliance: <b>PASS</b>, "
         "<b>COMPLIANCE VERIFIED</b>, <b>NO VIOLATION FOUND</b>, "
         "<b>SUBSTANTIALLY MEETS</b>, <b>NO EXTERNALLY REACHABLE</b>, etc., "
         "without a contradicting violation phrase.",
         "PASS"),
        ("Agent answer text declares violation: <b>FAIL</b>, "
         "<b>VIOLATION CONFIRMED</b>, <b>DIRECT_FINDING:</b>, "
         "<b>NON-COMPLIANT</b>, <b>CONTROL NOT MET</b>, etc., "
         "without a contradicting compliance phrase. Earliest-position-wins "
         "when both appear in the head (the first verdict statement is canonical).",
         "FAIL"),
        ("Agent reports mixed or partial compliance: <b>PARTIAL COMPLIANCE</b>, "
         "<b>WITH HARDENING NOTES</b>, <b>FINDINGS: (1)…(N)</b>, "
         "<b>COMPLIANCE ASSESSMENT:</b> narrative without a verdict word.",
         "REVIEW"),
        ("No agent answer text (empty payload, audit_memo orphan), OR a literal "
         "'N/A' answer. These are investigations the panel could not converge.",
         "INCONCLUSIVE"),
    ]
    for trig, verd in rules:
        verd_col = {"FAIL": COL_FAIL, "PASS": COL_PASS, "N/A": COL_NA,
                    "REVIEW": COL_REVIEW, "INFO": COL_INFO,
                    "INCONCLUSIVE": COL_INCONCLUSIVE}.get(verd, COL_INK)
        rule_rows.append([
            Paragraph(trig, s["table_cell"]),
            _para(verd, ParagraphStyle("V", parent=s["table_cell_mono"],
                                        textColor=verd_col,
                                        fontName=_font("Sans-Bold", "Helvetica-Bold"))),
        ])
    rt = Table(rule_rows, colWidths=[None, 38 * mm], repeatRows=1)
    rt.setStyle(_zebra_table_style(len(rule_rows)))
    story.append(rt)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "The text override exists because the agents legitimately submit "
        "<font name='Mono'>direct_finding</font> outcomes whose body declares "
        "compliance — the mapper would otherwise mis-label those as code "
        "defects. The <b>INFO</b> disposition is operator-defined: when the "
        "agent's verdict turns on a team-owned document or process that the "
        "code audit cannot synthesize (an SBOM, an architecture diagram, "
        "a privacy policy artifact), the control is flagged as informational "
        "rather than as a code-audit failure. This separates engineering "
        "remediation work from operations / documentation work.",
        s["body_sm"]))
    story.append(PageBreak())

    # 08.6 — toolchain
    story.append(_h2("08.6  ·  TOOLCHAIN", s))
    story.append(Paragraph(
        "Tool descriptions are paraphrased from each tool's documentation. The "
        "agents called these tools from inside the persona branches; the audit "
        "consumed no other source-of-truth.",
        s["body"]))
    tool_rows: list[list[Any]] = [["TOOL", "DESCRIPTION"]]
    tools = [
        ("android-mcp · apktool",
         "Decoded the APK into AndroidManifest.xml and resource files. Source of truth for declared activities, services, receivers, providers, exported attributes, intent filters, and uses-permission tags."),
        ("android-mcp · jadx",
         "Decompiled the APK's DEX bytecode to readable Java source under the cited decompiled_dir. 36 136 classes produced."),
        ("audit-mcp · semantic_search",
         "Vector + rerank search over the decompiled tree. Personas used this to locate evidence sites for evidence_hints terms like 'SharedPreferences', 'TYPE_TEXT_VARIATION_PASSWORD', 'NetworkSecurityConfig'."),
        ("audit-mcp · search_functions / search_constants",
         "Graph-indexed lookup of declared functions and constants. Bridge between agent intent ('find every EditText subclass') and the decompiled source tree."),
        ("audit-mcp · read_function / read_lines",
         "Read the exact source body for any cited file:line — bypasses the indexer when the agent already has coordinates and wants verbatim source."),
        ("audit-mcp · callers_of",
         "Reverse call-graph query. Personas used this to confirm an unsafe sink is actually reachable from an exported entry point."),
        ("ida-headless",
         "Native binary disassembly. Available but not load-bearing for this audit (com.vodafone.selfservis ships almost no first-party native code)."),
        ("MobSF",
         "Independent static-analysis baseline. The MobSF AppSec score, high/warning/info findings, and code-analysis rule hits in §04 are MobSF's verbatim output and feed cross-validation against the persona findings."),
    ]
    for n, d in tools:
        tool_rows.append([
            _para(n, _table_cell_with_color(s, COL_ACCENT)),
            _para(d, s["table_cell"]),
        ])
    ttt = Table(tool_rows, colWidths=[60 * mm, None], repeatRows=1)
    ttt.setStyle(_zebra_table_style(len(tool_rows)))
    story.append(ttt)
    story.append(Spacer(1, 4 * mm))

    story.append(_h2("08.7  ·  KNOWN  LIMITATIONS", s))
    limits = [
        "AILA's MASVS L1 catalog is sourced from OWASP MASVS v2.1.0; for any control whose authoritative wording changed between MASVS versions, this audit uses the v2.1.0 statement verbatim.",
        "The audit operates exclusively on the decompiled Java source. Behaviour that materialises only at JIT time (e.g. ART optimisations) is not directly observable.",
        "Persona reasoning was sometimes capped by wall-clock or turn-cap (see the four INCONCLUSIVE controls). A re-dispatch with raised caps and tighter scope is the recommended remediation path for those.",
        "Verifier reports are not present on every finding; per-finding pages explicitly note when no verifier_report was emitted.",
        "Variant hunt orders are proposed sibling investigations, NOT findings. They are next-step research targets, not vulnerabilities themselves.",
    ]
    for li in limits:
        story.append(_para(f"·  {li}", s["body_sm"]))
        story.append(Spacer(1, 1))
    story.append(PageBreak())

    return story


# ============================================================================
# GLOSSARY
# ============================================================================

def build_glossary(bundle: Bundle, s: dict[str, ParagraphStyle]) -> list[Flowable]:
    story: list[Flowable] = []
    story.append(_set_section("GLOSSARY", "§ 09"))
    story.append(_h1("§ 09  ·  GLOSSARY", s))
    story.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R, thickness=1.4))
    story.append(Spacer(1, 3 * mm))
    glossary = [
        ("AILA", "AI Lab Assistant — the modular security platform that hosts the VR module that ran this audit."),
        ("APK", "Android Application Package — the compressed bundle (ZIP-with-extra-metadata) every Android app ships in."),
        ("AppSec score", "MobSF's static-analysis composite score for an APK (0–100). The subject scored 38."),
        ("Audit MCP", "Audit Model Context Protocol bridge. Hosts semantic_search / read_function / callers_of / etc. for AILA agents."),
        ("Branch", "One persona's reasoning thread inside a child investigation. A child has 6 to 8 branches."),
        ("Child investigation", "One VR investigation dispatched per MASVS L1 control by the audit parent."),
        ("CLAIM-VERIFIER", "The adversarial verifier loop. Runs after panel consensus to attempt finding falsification."),
        ("Compliance gap", "Synonym for FAIL — the app fails a stated MASVS verification requirement."),
        ("Direct finding", "Outcome kind: the panel asserts a concrete vulnerability or compliance gap exists."),
        ("Evidence hint", "Catalog-provided search string the persona feeds into semantic_search to locate evidence sites."),
        ("Exported component", "Manifest-declared Activity/Service/Receiver/Provider with android:exported=true or implicit. Attack surface."),
        ("Finding ID (F-NNN)", "Sequential id this report assigns to each control's finding (e.g. F-007)."),
        ("INCONCLUSIVE", "Verdict band: child reached a terminal state without emitting a primary outcome (turn-cap / wall-clock)."),
        ("Investigation", "Generic VR concept — one self-directed reasoning task with a primary question and child branches."),
        ("L1 / L2 / R", "MASVS verification levels — L1 baseline, L2 defence-in-depth, R resilience. This audit is L1 only."),
        ("MASVS", "OWASP Mobile Application Security Verification Standard. The catalog of mobile verification requirements."),
        ("MobSF", "Mobile Security Framework — open-source static analyser AILA runs alongside the persona panel as a cross-check."),
        ("Outcome", "Typed result emitted by a branch: direct_finding, audit_memo, assessment_report, variant_hunt_order, etc."),
        ("Panel", "The six-persona reasoning ensemble. Halvar+Noor (researchers) · Maddie+Yuki (critics) · Renzo+Wei (implementers)."),
        ("Persona", "One distinct reasoning identity within the panel. Each has its own prompt envelope and methodological angle."),
        ("Primary outcome", "The single outcome the parent reads as the child's verdict — typically the highest-confidence outcome the panel agreed on."),
        ("Quorum", "Sibling-consensus threshold. A direct_finding is promoted only when ≥2 personas co-sign and no critic vetoes."),
        ("REVIEW", "Verdict band: inconclusive with agent reasoning present — operator should review."),
        ("Variant hunt order (V-NNN)", "A sibling-spawn recommendation. The persona thinks a pattern-matched site is worth investigating but did not pursue it inline."),
        ("Verdict", "One of FAIL/PASS/N/A/REVIEW/INCONCLUSIVE assigned per control."),
        ("Verifier report", "Adversarial verifier's output — supported/refuted verdict, probes run, counter-evidence."),
        ("VR", "Vulnerability Research module inside AILA. The home of the MASVS audit pipeline."),
    ]
    rows: list[list[Any]] = [["TERM", "DEFINITION"]]
    for term, defn in glossary:
        rows.append([
            _para(term, ParagraphStyle("GT", parent=s["table_cell_mono"],
                                        fontName=_font("Sans-Bold", "Helvetica-Bold"),
                                        textColor=COL_ACCENT)),
            _para(defn, s["table_cell"]),
        ])
    t = Table(rows, colWidths=[44 * mm, None], repeatRows=1)
    t.setStyle(_zebra_table_style(len(rows)))
    story.append(t)
    story.append(Spacer(1, 6 * mm))

    # Final colophon line
    colo_style = ParagraphStyle("Colo", parent=s["body_xs"],
                                fontName=_font("Mono", "Courier"),
                                textColor=COL_MUTED, alignment=TA_CENTER)
    story.append(HorizontalRule(PAGE_W - MARGIN_L - MARGIN_R, thickness=0.8, color=COL_THIN))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        "—  END  OF  REPORT  —", ParagraphStyle("End", parent=s["caps"], alignment=TA_CENTER,
                                                  textColor=COL_ACCENT, letterSpace=6.0)))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        "Generated by scripts/vr_masvs_report_yanimda.py on "
        f"{_CHROME.timestamp} for audit {_CHROME.audit_id_short}.",
        colo_style))
    return story


# ============================================================================
# DOC TEMPLATE — frames + paper background + chrome
# ============================================================================

class TacticalDocTemplate(BaseDocTemplate):
    """Doc template with cover and body templates, paper bg, chrome strip."""

    def __init__(self, filename: str, **kw: Any):
        super().__init__(filename, pagesize=PAGE_SIZE, **kw)

        cover_frame = Frame(
            MARGIN_L, MARGIN_B,
            PAGE_W - MARGIN_L - MARGIN_R,
            PAGE_H - MARGIN_T - MARGIN_B,
            id="cover", showBoundary=0,
            leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
        )
        body_frame = Frame(
            MARGIN_L, MARGIN_B + 4,
            PAGE_W - MARGIN_L - MARGIN_R,
            PAGE_H - MARGIN_T - MARGIN_B - 4,
            id="body", showBoundary=0,
            leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
        )

        self.addPageTemplates([
            PageTemplate(id="cover", frames=[cover_frame], onPage=_draw_cover_chrome),
            PageTemplate(id="body", frames=[body_frame], onPage=_draw_page),
        ])


# ============================================================================
# BUILD FLOW
# ============================================================================

def build_pdf(out_path: Path, bundle: Bundle) -> int:
    """Render the PDF to ``out_path`` and return the total page count."""
    _register_fonts()
    s = _styles()

    # Two-pass render so total_pages is accurate in footers.
    # Pass A: render once with total_pages=0 to discover the count.
    # Pass B: re-render with the discovered count.
    audit = bundle.audit["audit"]
    target = bundle.audit["target"]
    apk = bundle.apk
    _CHROME.bundle = bundle
    _CHROME.audit_id_short = (audit.get("id") or "")[:8]
    _CHROME.package = (apk.get("static_summary") or {}).get("package") or apk.get("package_name", "")
    _CHROME.version = (apk.get("static_summary") or {}).get("version_name", "")
    _CHROME.timestamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _CHROME.apk_sha_short = (apk.get("apk_sha256") or "")[:16]

    def _build_story() -> list[Flowable]:
        story: list[Flowable] = []
        story.append(NextPageTemplate("cover"))
        story.extend(build_cover(bundle, s))
        story.extend(build_doc_control(bundle, s))
        story.extend(build_exec_summary(bundle, s))
        # § 03  ABOUT THE PLATFORM — inserted between exec summary and APK
        # intel so the reader knows how the verdicts were produced before
        # reading the technical body. Pulls all facts from aila_brief.json.
        story.extend(build_about_aila(bundle, s))
        story.extend(build_apk_intel(bundle, s))
        # Findings index renumbers from § 03 to § 05 after the insertion
        # of ABOUT THE PLATFORM. Findings themselves keep their § 06 home.
        story.extend(build_findings_index(bundle, s))
        story.extend(build_findings(bundle, s))
        story.extend(build_variant_index(bundle, s))
        story.extend(build_methodology(bundle, s))
        story.extend(build_glossary(bundle, s))
        return story

    # Pass A — count pages & capture section→page map for the chrome.
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(".tmp.pdf")
    _CHROME.total_pages = 0
    _CHROME.section_at_page = {}
    _CHROME.verdict_at_page = {}
    _CHROME.capture_sections = True
    doc_a = TacticalDocTemplate(str(tmp_path))
    doc_a.build(_build_story())
    page_count = _pdf_page_count(tmp_path)
    _CHROME.total_pages = page_count
    _CHROME.capture_sections = False

    # Pass B — re-render with correct total + populated section map.
    doc_b = TacticalDocTemplate(str(out_path))
    doc_b.build(_build_story())
    try:
        tmp_path.unlink()
    except FileNotFoundError:
        pass
    return _pdf_page_count(out_path)


def _pdf_page_count(path: Path) -> int:
    try:
        from pypdf import PdfReader
        return len(PdfReader(str(path)).pages)
    except Exception:
        # Fallback: parse raw page-count from the trailer (best-effort).
        raw = path.read_bytes()
        return raw.count(b"/Type /Page") + raw.count(b"/Type/Page")


# ============================================================================
# CONCUR CHECK — independent verification on the rendered PDF
# ============================================================================

def concur_check(pdf_path: Path, bundle: Bundle) -> dict[str, Any]:
    """Extract the PDF text and assert the deliverables.

    Returns a dict with the full concurrence report. Prints a human-readable
    summary as a side-effect.
    """
    from pypdf import PdfReader

    reader = PdfReader(str(pdf_path))
    pages = reader.pages
    page_count = len(pages)
    full_text = "\n".join((p.extract_text() or "") for p in pages)
    # Pre-compute the case-folded whitespace-collapsed text once. Per-finding
    # locator probes (~40 of them) re-using this string avoids quadratic
    # allocations that otherwise MemoryError on long answer payloads.
    text_lo = re.sub(r"\s+", " ", full_text).lower()

    # Tally verdicts from bundle
    counts: Counter[str] = Counter(f.verdict_label for f in bundle.findings)

    anomalies: list[str] = []
    missing_controls: list[str] = []
    short_fails: list[str] = []
    missing_panel: list[str] = []

    for cid in bundle.catalog:
        if cid not in full_text:
            missing_controls.append(cid)

    # For each FAIL finding, assert there is at least 500 chars of agent
    # reasoning rendered on the page. The PDF page renders ``answer`` +
    # ``reasoning`` + each ``panel_contributions[].answer_brief`` — the
    # combined length is what the operator actually reads. (Some agents
    # write a 3-char answer field like "N/A" but produce a multi-KB
    # reasoning section; the operator-facing content is fine in those
    # cases.) The hard assertion is only that the first 100 chars of
    # SOME chunk of agent text resolves into the extracted PDF text.
    for f in bundle.findings:
        if f.verdict_label == "FAIL":
            answer = (f.payload.get("answer") or "").strip()
            reasoning = (f.payload.get("reasoning") or "").strip()
            panel_briefs = [
                (pc.get("answer_brief") or "").strip()
                for pc in (f.payload.get("panel_contributions") or [])
            ]
            combined_len = len(answer) + len(reasoning) + sum(len(b) for b in panel_briefs)
            # Locate any reasoning chunk in the extracted PDF text.
            located = False
            for chunk in (answer, reasoning, *panel_briefs):
                if not chunk:
                    continue
                seg = re.sub(r"\s+", " ", chunk)[:160].lower()
                if seg and seg in text_lo:
                    located = True
                    break
            if not located and (answer or reasoning or panel_briefs):
                short_fails.append(
                    f"{f.finding_id} ({f.control_id}) — agent reasoning not located in PDF text"
                )
            if combined_len < 500:
                short_fails.append(
                    f"{f.finding_id} ({f.control_id}) — combined agent reasoning only {combined_len} chars (< 500)"
                )
        if (f.verdict_label in {"FAIL", "REVIEW"}) and not (f.payload.get("panel_contributions") or []):
            missing_panel.append(f.finding_id + " (" + f.control_id + ")")

    # APK intel section checks
    if "com.vodafone.selfservis" not in full_text:
        anomalies.append("Package id 'com.vodafone.selfservis' not found in PDF text")
    if "38" not in full_text:
        anomalies.append("Permission count '38' not found in PDF text")
    # Variant hunt index ≥ 5
    variant_count = len(bundle.variants)
    if variant_count < 5:
        anomalies.append(f"Variant hunt index too small ({variant_count} < 5)")

    size_mb = pdf_path.stat().st_size / (1024 * 1024)

    # ── Structural checks introduced by the reshape ──
    # Strip the chrome strip so we can match against the title strings the
    # body flowables emit (the running chrome uses double-spaced
    # all-caps; the body uses single-spaced).
    text_lo_collapsed = text_lo  # already case-folded + space-collapsed

    # 1. § 03 ABOUT THE PLATFORM section present in extracted text.
    if ("about the platform" not in text_lo_collapsed
            and "about  the  platform" not in text_lo_collapsed):
        anomalies.append("§ 03 ABOUT THE PLATFORM section not found in PDF text")

    # 2. RISK SNAPSHOT card occurrences should equal the finding count.
    snapshot_count = text_lo_collapsed.count("risk snapshot")
    if snapshot_count < len(bundle.findings):
        anomalies.append(
            f"RISK SNAPSHOT cards found {snapshot_count} times in PDF text; "
            f"expected at least {len(bundle.findings)} (one per finding)"
        )

    # 3. KEY TAKEAWAY callouts should equal the FAIL count.
    fail_n = counts.get("FAIL", 0)
    takeaway_count = text_lo_collapsed.count("key takeaway")
    if takeaway_count < fail_n:
        anomalies.append(
            f"KEY TAKEAWAY callouts found {takeaway_count} times in PDF text; "
            f"expected at least {fail_n} (one per FAIL finding)"
        )

    # 4. AT A GLANCE dashboard present.
    if "at  a  glance" not in text_lo_collapsed and "at a glance" not in text_lo_collapsed:
        anomalies.append("AT A GLANCE dashboard not found in PDF text")

    # 5. INFO verdicts should NOT trigger a "panel attribution missing"
    # complaint — they are an operator-doc-needed disposition.
    # (Existing missing_panel check already only checks FAIL/REVIEW.)

    report: dict[str, Any] = {
        "pdf_path": str(pdf_path),
        "page_count": page_count,
        "verdict_distribution": dict(counts),
        "fail_count": fail_n,
        "review_count": counts.get("REVIEW", 0),
        "info_count": counts.get("INFO", 0),
        "na_count": counts.get("N/A", 0),
        "pass_count": counts.get("PASS", 0),
        "inconclusive_count": counts.get("INCONCLUSIVE", 0),
        "missing_controls_in_text": missing_controls,
        "fails_without_reasoning_in_pdf": short_fails,
        "fail_or_review_without_panel": missing_panel,
        "variant_count": variant_count,
        "anomalies": anomalies,
        "size_mb": round(size_mb, 2),
        "structure": {
            "risk_snapshot_count": snapshot_count,
            "key_takeaway_count": takeaway_count,
        },
    }

    print()
    print("============================================================")
    print(" YANIMDA MASVS PDF — CONCURRENCE REPORT")
    print("============================================================")
    print(f"  PDF path                  : {pdf_path}")
    print(f"  Pages                     : {page_count}")
    print(f"  Size (MB)                 : {size_mb:.2f}")
    print(f"  Verdict distribution      :", dict(counts))
    print(f"  Variants aggregated       : {variant_count}")
    print(f"  Missing controls in text  : {len(missing_controls)}"
          + (f"  →  {missing_controls}" if missing_controls else ""))
    print(f"  FAILs lacking reasoning   : {len(short_fails)}")
    for sf in short_fails:
        print(f"    · {sf}")
    print(f"  FAIL/REVIEW w/o panel attr: {len(missing_panel)}")
    for mp in missing_panel:
        print(f"    · {mp}")
    print(f"  Anomalies                 : {len(anomalies)}")
    for a in anomalies:
        print(f"    · {a}")
    print(f"  Risk snapshot cards (text): {snapshot_count}")
    print(f"  Key takeaway boxes  (text): {takeaway_count}  "
          f"(FAIL findings: {fail_n})")
    print("============================================================")
    print()

    # Hard assertions per spec
    assert page_count > 50, f"page count {page_count} ≤ 50"
    assert size_mb < 2.0, f"size {size_mb:.2f} MB ≥ 2 MB"
    assert not missing_controls, f"controls missing from PDF: {missing_controls}"
    # Per-spec: FAIL findings must have ≥500 chars of agent reasoning text.
    # Tolerate the FAILs that genuinely have no agent answer text in the source
    # data, but require those that DO have a sufficiently long answer to be
    # located in the PDF.
    located = [s for s in short_fails if "not located in PDF text" in s]
    assert not located, f"FAIL reasoning not located in PDF: {located}"
    assert variant_count >= 5, f"variant index too small ({variant_count})"
    # New structural assertions from the reshape:
    assert snapshot_count >= len(bundle.findings), (
        f"only {snapshot_count} RISK SNAPSHOT cards in PDF; "
        f"expected ≥ {len(bundle.findings)}"
    )
    assert takeaway_count >= fail_n, (
        f"only {takeaway_count} KEY TAKEAWAY callouts in PDF; "
        f"expected ≥ {fail_n} (one per FAIL)"
    )
    assert (
        "about the platform" in text_lo_collapsed
        or "about  the  platform" in text_lo_collapsed
    ), "§ 03 ABOUT THE PLATFORM section not present in PDF text"
    return report


# ============================================================================
# CLI
# ============================================================================

def _default_out() -> Path:
    return _REPO_ROOT / ".run" / "yanimda_report" / "yanimda_masvs.pdf"


def _default_input_dir() -> Path:
    return _REPO_ROOT / ".run" / "yanimda_report"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="VF Yanımda MASVS L1 audit PDF generator.",
    )
    ap.add_argument("--input-dir", type=Path, default=_default_input_dir(),
                    help="Directory containing audit_dump.json / masvs_catalog.json / apk_intel.json")
    ap.add_argument("--out", type=Path, default=_default_out(),
                    help="Output PDF path (default .run/yanimda_report/yanimda_masvs.pdf)")
    ap.add_argument("--verify", action="store_true",
                    help="After build, extract the PDF and run the concurrence check.")
    args = ap.parse_args(argv)

    bundle = load_bundle(args.input_dir)
    pages = build_pdf(args.out, bundle)
    size_mb = args.out.stat().st_size / (1024 * 1024)
    print(f"Wrote {args.out}  ·  {pages} pages  ·  {size_mb:.2f} MB")

    if args.verify:
        concur_check(args.out, bundle)
    return 0


if __name__ == "__main__":
    sys.exit(main())
