"""MASVS audit aggregation + PDF rendering for the vr module.

R-1 — :func:`collect_findings`. Walks every child
investigation under a MASVS audit parent, projects each child's primary
outcome through the S-4 mapping rule
(:func:`aila.modules.vr.masvs.verdict_mapper.child_outcome_to_verdict`),
groups verdicts by MASVS control group, and assembles the per-verdict
summary counts. The output is the
:class:`~aila.modules.vr.contracts.masvs.MasvsAuditAggregate` consumed by
the PDF renderer (R-2) and the
``GET /vr/targets/{id}/masvs-report`` payload (R-3).

R-2a (this commit) — :func:`build_pdf`. Renders a
:class:`MasvsAuditAggregate` as a self-contained PDF document:
cover page (APK identity + audit metadata), executive-summary
count table, and one section per MASVS group with PDF outline
bookmarks driving the TOC. R-2b lands the per-control
subsection bodies (evidence excerpts + remediation prose); R-3
wires the download endpoint; R-4 adds the operator button.

Design notes
------------

* The aggregator is read-only. It commits no rows, never invents a
  verdict, and never imports from :mod:`aila.modules.vr.api_router`.
  Operator-visible verdicts trace through the mapper to a real child
  outcome row.
* Catalog version pinned on the parent's
  ``secondary_target_refs_json`` is preserved verbatim so a historical
  audit always reports the version it was dispatched under, even when
  the catalog has since moved on.
* Children whose ``masvs_control_id`` ref is missing or whose control id
  is not in the current catalog are skipped with a log line. The
  parent's pinned version is the audit trail — surfacing a partial
  aggregate beats fabricating a synthetic verdict from a missing
  control entry.
* Partial aggregates are valid: a child still in flight has no
  ``primary_outcome_id`` and lands as
  :attr:`MasvsVerdict.INCONCLUSIVE` with
  ``reason='no_primary_outcome'`` (the mapper's standard rendering for
  a ``None`` outcome). R-2's renderer reads child status when it needs
  to distinguish "still running" from "terminal without an outcome".
"""
from __future__ import annotations

import io
import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from sqlmodel import select

from aila.modules.vr.contracts import InvestigationKind
from aila.modules.vr.contracts.masvs import (
    MasvsAuditAggregate,
    MasvsControlVerdict,
    MasvsVerdict,
)
from aila.modules.vr.contracts.outcome import (
    OutcomeConfidence,
    OutcomeDispatchStatus,
    OutcomeKind,
    VROutcomeSummary,
)
from aila.modules.vr.contracts.target import VRTargetSummary
from aila.modules.vr.db_models import (
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.modules.vr.masvs.catalog import CATALOG_VERSION, MASVS_CONTROLS
from aila.modules.vr.masvs.models import MasvsControl, MasvsGroup
from aila.modules.vr.masvs.verdict_mapper import child_outcome_to_verdict
from aila.modules.vr.reporting.pdf_report import (
    _BG_BORDER,
    _BG_SURFACE,
    _FG_MUTED,
    _FG_TEXT,
    _FONT_BODY,
    _FONT_BODY_BOLD,
    _FONT_MONO,
    _append_section_h1,
    _build_styles,
    _draw_footer,
    _escape_for_paragraph,
)
from aila.platform.uow import UnitOfWork

__all__ = ["build_pdf", "collect_findings"]

_log = logging.getLogger(__name__)


def _outcome_record_to_summary(
    record: VRInvestigationOutcomeRecord,
) -> VROutcomeSummary:
    """Project a row to the read-only summary the mapper consumes.

    Mirrors the private ``_outcome_summary`` helper in
    :mod:`aila.modules.vr.api_router` so the reporting module never
    imports the FastAPI router. The shape is identical; the legacy NULL
    ``state`` fallback is preserved for outcome rows that pre-date the
    draft-outcome lifecycle (migration 062).
    """
    return VROutcomeSummary(
        id=record.id,
        investigation_id=record.investigation_id,
        branch_id=record.branch_id,
        outcome_kind=OutcomeKind(record.outcome_kind),
        payload=json.loads(record.payload_json or "{}"),
        confidence=OutcomeConfidence(record.confidence),
        evidence_refs=json.loads(record.evidence_refs_json or "[]"),
        accepted_by_operator=record.accepted_by_operator,
        accepted_at=record.accepted_at,
        dispatch_status=OutcomeDispatchStatus(record.dispatch_status),
        dispatch_target=record.dispatch_target,
        created_at=record.created_at,
        state=record.state or "dispatched",
    )


def _extract_spec_version(parent: VRInvestigationRecord) -> str:
    """Parse the catalog version pinned on the parent's secondary refs.

    Falls back to the current :data:`CATALOG_VERSION` when the parent
    row predates the version-pinning convention or carries a malformed
    refs blob. The fallback is logged at WARNING so an upstream schema
    drift surfaces without breaking the aggregate build.
    """
    try:
        refs = json.loads(parent.secondary_target_refs_json or "[]")
    except (ValueError, TypeError):
        _log.warning(
            "MASVS parent %s has unparseable secondary_target_refs_json; "
            "falling back to catalog version %s.",
            parent.id, CATALOG_VERSION,
        )
        return CATALOG_VERSION
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict):
                version = ref.get("masvs_spec_version")
                if isinstance(version, str) and version:
                    return version
    _log.warning(
        "MASVS parent %s missing masvs_spec_version ref; falling back to "
        "catalog version %s.", parent.id, CATALOG_VERSION,
    )
    return CATALOG_VERSION


def _extract_child_control_id(child: VRInvestigationRecord) -> str | None:
    """Read ``masvs_control_id`` from the child's secondary refs JSON.

    Returns ``None`` when the column is malformed or carries no
    ``masvs_control_id`` entry. A parse failure is logged at WARNING so
    upstream schema drift (e.g. a dispatcher regression writing a list
    of strings instead of dicts) surfaces without breaking the
    aggregate build — the caller still drops the verdict for the
    affected child.
    """
    try:
        refs = json.loads(child.secondary_target_refs_json or "[]")
    except (ValueError, TypeError):
        _log.warning(
            "MASVS child %s has unparseable secondary_target_refs_json; "
            "no masvs_control_id resolvable.", child.id,
        )
        return None
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict):
                cid = ref.get("masvs_control_id")
                if isinstance(cid, str) and cid:
                    return cid
    return None


async def collect_findings(parent_id: str) -> MasvsAuditAggregate:
    """Aggregate every child investigation under a MASVS audit parent.

    Steps:

    1. Load the parent row, validate its ``kind == masvs_audit``, and
       extract the catalog version pinned at dispatch time.
    2. Load every child ``VRInvestigationRecord`` linked via
       ``parent_investigation_id``.
    3. Fetch every referenced primary outcome row in one ``IN`` query
       (avoids N+1 SELECT on a ~46-child batch).
    4. Per child: resolve the catalog entry, build a
       :class:`VROutcomeSummary` from the primary outcome row (or
       ``None`` when the child has no ``primary_outcome_id``), and call
       :func:`child_outcome_to_verdict` with the resolved control + the
       child's id.
    5. Group verdicts by :class:`MasvsGroup` (in first-seen order, which
       matches catalog order since children are dispatched in catalog
       order) and tally per-verdict counts.

    :param parent_id: VRInvestigationRecord id of the MASVS audit parent
        (must have ``kind == 'masvs_audit'``).
    :returns: A :class:`MasvsAuditAggregate` carrying one verdict per
        catalogued child investigation, the per-group projection, and
        the per-verdict summary counters.
    :raises ValueError: when ``parent_id`` does not resolve, or the row
        exists but is not a MASVS audit batch root.
    """
    catalog_by_id: dict[str, MasvsControl] = {
        control.id: control for control in MASVS_CONTROLS
    }

    async with UnitOfWork() as uow:
        parent = (
            await uow.session.exec(
                select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == parent_id,
                ),
            )
        ).first()
        if parent is None:
            raise ValueError(
                f"MASVS audit parent {parent_id!r} not found",
            )
        if parent.kind != InvestigationKind.MASVS_AUDIT.value:
            raise ValueError(
                f"Investigation {parent_id!r} kind={parent.kind!r}; "
                "expected 'masvs_audit'.",
            )

        spec_version = _extract_spec_version(parent)
        target_id = parent.target_id

        children: list[VRInvestigationRecord] = list((
            await uow.session.exec(
                select(VRInvestigationRecord)
                .where(
                    VRInvestigationRecord.parent_investigation_id == parent_id,
                )
                .order_by(VRInvestigationRecord.created_at.asc()),
            )
        ).all())

        primary_ids: list[str] = [
            child.primary_outcome_id
            for child in children
            if child.primary_outcome_id
        ]
        outcome_rows: dict[str, VRInvestigationOutcomeRecord] = {}
        if primary_ids:
            for outcome_record in (
                await uow.session.exec(
                    select(VRInvestigationOutcomeRecord).where(
                        VRInvestigationOutcomeRecord.id.in_(primary_ids),
                    ),
                )
            ).all():
                outcome_rows[outcome_record.id] = outcome_record

    verdicts: list[MasvsControlVerdict] = []
    by_group: dict[MasvsGroup, list[MasvsControlVerdict]] = {}

    for child in children:
        control_id = _extract_child_control_id(child)
        if control_id is None:
            _log.warning(
                "MASVS aggregate %s: child %s missing masvs_control_id "
                "ref; skipping (no verdict emitted).",
                parent_id, child.id,
            )
            continue
        control = catalog_by_id.get(control_id)
        if control is None:
            _log.warning(
                "MASVS aggregate %s: child %s references control %r not "
                "in catalog version %s; skipping (no verdict emitted).",
                parent_id, child.id, control_id, spec_version,
            )
            continue
        outcome_summary: VROutcomeSummary | None = None
        if child.primary_outcome_id:
            outcome_record = outcome_rows.get(child.primary_outcome_id)
            if outcome_record is not None:
                outcome_summary = _outcome_record_to_summary(outcome_record)
        verdict = child_outcome_to_verdict(
            outcome_summary,
            control,
            child_investigation_id=child.id,
        )
        verdicts.append(verdict)
        by_group.setdefault(control.group, []).append(verdict)

    summary_counts: dict[MasvsVerdict, int] = {}
    for verdict in verdicts:
        summary_counts[verdict.verdict] = (
            summary_counts.get(verdict.verdict, 0) + 1
        )

    return MasvsAuditAggregate(
        parent_id=parent.id,
        target_id=target_id,
        masvs_spec_version=spec_version,
        generated_at=datetime.now(UTC),
        verdicts=verdicts,
        by_group=by_group,
        summary_counts=summary_counts,
    )

# ──────────────────────────────────────────────────────────────────────
# R-2a — PDF rendering
# ──────────────────────────────────────────────────────────────────────
#
# Visual identity (palette, fonts, page chrome) is shared with
# :mod:`aila.modules.vr.reporting.pdf_report` so a MASVS audit report
# sits next to a one-shot investigation report in the operator's
# downloads folder without looking like it came from a different
# product. The shared bits are imported privately at module top so
# the per-investigation renderer stays the canonical owner.
#
# Layout (R-2a scaffolding):
#
#   Page 1   Cover — title, overall posture badge, APK identity
#            table (package / version / SHA-256 / MASVS catalog /
#            audit window / generated date), bookmark "Cover".
#   Page 2+  Executive summary — interpretive paragraph + four-cell
#            count grid (FINDING / NO_FINDING / NOT_APPLICABLE /
#            INCONCLUSIVE). Bookmark "Executive summary".
#   Page 2+  One section per non-empty MASVS group, in canonical
#            :class:`MasvsGroup` order: heading + a per-control
#            row table (id, title, verdict badge, confidence).
#            Each section emits a PDF outline bookmark so the
#            viewer renders a TOC sidebar. R-2b will append the
#            per-control subsection bodies inside each group.


# Verdict → pastel cell color (placed on the dark page surface, with
# black text on the cell so badge contrast holds up even when the
# reader prints the PDF on a monochrome printer — the text reads
# either way).
# Verdict colors: red for vulnerabilities, green for compliant, grey
# for inapplicable, amber for not-yet-conclusive. Picked so a tired
# reviewer skimming the report at 3am can't confuse "we found a
# vulnerability" with "we found that this is fine" — the older labels
# both contained the word "finding" and read the same on a similar-
# toned badge.
_VERDICT_COLOR: dict[MasvsVerdict, colors.Color] = {
    MasvsVerdict.FINDING: colors.HexColor("#d83b3b"),         # hard red
    MasvsVerdict.NO_FINDING: colors.HexColor("#2e9b5a"),      # solid green
    MasvsVerdict.NOT_APPLICABLE: colors.HexColor("#7c7c8a"),  # neutral grey
    MasvsVerdict.INCONCLUSIVE: colors.HexColor("#d99a2c"),    # amber
}

# Verdict → uppercase label used on badges and in count headers. The
# words must read unambiguously at a glance. "FINDING" and "NO FINDING"
# both contained the word "finding" and were visually indistinguishable
# from each other when a reviewer scanned a long report. Switching to
# the security-audit standard PASS / FAIL / N/A / REVIEW so the badge
# verbatim tells the reviewer "this control is good", "this control is
# broken", "doesn't apply to this APK", or "we couldn't determine".
_VERDICT_LABEL: dict[MasvsVerdict, str] = {
    MasvsVerdict.FINDING: "FAIL",
    MasvsVerdict.NO_FINDING: "PASS",
    MasvsVerdict.NOT_APPLICABLE: "N/A",
    MasvsVerdict.INCONCLUSIVE: "REVIEW",
}

# Display order for the executive-summary count grid and the per-row
# legend. FINDING leads — the report's job is to surface compliance
# gaps first, then everything else in decreasing audit signal.
_VERDICT_DISPLAY_ORDER: tuple[MasvsVerdict, ...] = (
    MasvsVerdict.FINDING,
    MasvsVerdict.NO_FINDING,
    MasvsVerdict.NOT_APPLICABLE,
    MasvsVerdict.INCONCLUSIVE,
)

# Group → human-readable section heading. The enum value is the wire
# token (e.g. "STORAGE"); the spec-facing heading is "MASVS-STORAGE".
_GROUP_HEADING: dict[MasvsGroup, str] = {
    group: f"MASVS-{group.value}" for group in MasvsGroup
}


# Catalog lookup keyed by control id. The aggregator only emits verdicts
# whose ``control_id`` was already resolved from this catalog, so a
# missing id at render time means the catalog moved on after the audit
# was dispatched. The renderer falls back to a minimal subsection
# (id-only header, no description, no verification steps) rather than
# raising — partial fidelity beats refusing to render.
_CATALOG_BY_ID: dict[str, MasvsControl] = {
    control.id: control for control in MASVS_CONTROLS
}


# Path template the per-control footer prints so an operator can paste
# the child investigation page into their AILA host. The renderer is
# host-agnostic (the PDF travels off-host); the path mirrors the
# frontend route at :file:`src/aila/modules/vr/frontend/routes.tsx`
# (``id: vr.investigation-detail``).
_INVESTIGATION_PATH_TEMPLATE: str = "/vr/investigations/{investigation_id}"


class _BookmarkFlowable(Flowable):
    """Zero-height flowable that emits a PDF outline entry at its
    paint location.

    ReportLab's outline / bookmark API is canvas-level, not story-level.
    To anchor a TOC entry to "the point a section heading lands on a
    page" we drop one of these into the flow right before the heading.
    PDF viewers (Acrobat, Preview, Edge, Firefox) render the resulting
    outline as a TOC sidebar — operators jump from "Executive summary"
    to "MASVS-CRYPTO" without scrolling 30 pages.
    """

    def __init__(self, key: str, title: str, level: int = 0) -> None:
        super().__init__()
        self._key = key
        self._title = title
        self._level = level

    def wrap(self, _avail_w: float, _avail_h: float) -> tuple[float, float]:
        return (0.0, 0.0)

    def draw(self) -> None:
        canv = self.canv
        canv.bookmarkPage(self._key)
        canv.addOutlineEntry(self._title, self._key, level=self._level, closed=False)


def _coerce_str(value: Any) -> str:
    """Render an arbitrary cell from ``apk_overview.static_summary`` as
    a plain trimmed string. Used by the cover-page identity table so
    integer SDK versions / list-shaped certificates / None values all
    render predictably without raising.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _format_sha256(value: Any) -> str:
    """Render an APK SHA-256 in groups of 8 hex chars for readability
    on the cover page. Falls back to the raw stringification when the
    input is not a 64-char hex string.
    """
    text = _coerce_str(value).lower()
    if len(text) == 64 and all(c in "0123456789abcdef" for c in text):
        return " ".join(text[i : i + 8] for i in range(0, 64, 8))
    return text


def _overall_posture(
    summary_counts: Mapping[MasvsVerdict, int],
) -> tuple[str, colors.Color]:
    """Pick the cover-page posture badge from the summary counts.

    Priority is FINDING (any) → INCONCLUSIVE (any, no findings) → CLEAN
    (everything resolved without findings). The label is what the
    operator sees in inch-tall text on page 1; the color matches the
    dominant verdict's pastel cell color so the cover ties visually to
    the per-group sections.
    """
    findings = summary_counts.get(MasvsVerdict.FINDING, 0)
    if findings > 0:
        word = "FAILING CONTROL" if findings == 1 else "FAILING CONTROLS"
        return (f"{findings} {word}", _VERDICT_COLOR[MasvsVerdict.FINDING])
    inconclusive = summary_counts.get(MasvsVerdict.INCONCLUSIVE, 0)
    if inconclusive > 0:
        return (
            "AUDIT IN PROGRESS"
            if summary_counts.get(MasvsVerdict.NO_FINDING, 0) == 0
            and summary_counts.get(MasvsVerdict.NOT_APPLICABLE, 0) == 0
            else f"{inconclusive} CONTROLS NEED REVIEW",
            _VERDICT_COLOR[MasvsVerdict.INCONCLUSIVE],
        )
    return ("ALL CONTROLS PASS", _VERDICT_COLOR[MasvsVerdict.NO_FINDING])


def _append_cover(
    story: list[Any],
    aggregate: MasvsAuditAggregate,
    target: VRTargetSummary,
    static_summary: Mapping[str, Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    """Cover page — title, posture badge, APK identity meta-table.

    Mirrors the per-investigation cover layout in :mod:`pdf_report` so
    the two reports share visual identity. The posture badge collapses
    the full per-verdict count down to a single operator-facing word
    ("4 FINDINGS" / "NO COMPLIANCE GAPS DETECTED" / etc.); the count
    grid lives in the executive summary one page later.
    """
    apk_overview = target.apk_overview or {}

    title_text = "OWASP MASVS Audit Report"
    subtitle_text = target.display_name or (
        target.android_package_name or "Android APK"
    )

    story.append(_BookmarkFlowable("masvs-cover", "Cover", level=0))
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(_escape_for_paragraph(title_text), styles["cover_title"]))
    story.append(Paragraph(_escape_for_paragraph(subtitle_text), styles["cover_subtitle"]))
    story.append(Spacer(1, 0.25 * inch))

    posture_label, posture_color = _overall_posture(aggregate.summary_counts)
    posture_table = Table(
        [[Paragraph(
            f"<para alignment='center' leading='28'>"
            f"<font color='#121212' size='10'><b>OVERALL POSTURE</b></font><br/>"
            f"<font color='#121212' size='22'><b>"
            f"{_escape_for_paragraph(posture_label)}</b></font>"
            f"</para>",
            styles["body"],
        )]],
        colWidths=[4.4 * inch],
    )
    posture_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), posture_color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
    ]))
    posture_table.hAlign = "CENTER"
    story.append(posture_table)
    story.append(Spacer(1, 0.25 * inch))

    package_name = (
        _coerce_str(static_summary.get("package"))
        or _coerce_str(target.android_package_name)
        or "(unknown)"
    )
    version_name = _coerce_str(static_summary.get("version_name")) or "(unknown)"
    version_code = _coerce_str(static_summary.get("version_code"))
    if version_code:
        version_display = f"{version_name} (code {version_code})"
    else:
        version_display = version_name
    sha_display = _format_sha256(apk_overview.get("sha256")) or "(unknown)"
    audited_at = aggregate.generated_at.strftime("%Y-%m-%d %H:%M UTC")

    cover_meta: list[tuple[str, str]] = [
        ("APK display name", target.display_name or "(unknown)"),
        ("Package", package_name),
        ("Version", version_display),
        ("SHA-256", sha_display),
        ("MASVS catalog", aggregate.masvs_spec_version),
        ("Controls audited", str(len(aggregate.verdicts))),
        ("Parent investigation", aggregate.parent_id),
        ("Report generated", audited_at),
    ]
    min_sdk = _coerce_str(static_summary.get("min_sdk"))
    target_sdk = _coerce_str(static_summary.get("target_sdk"))
    if min_sdk or target_sdk:
        cover_meta.insert(
            4,
            ("SDK range", f"min {min_sdk or '?'} → target {target_sdk or '?'}"),
        )

    body_style = styles["body"]
    meta_rows = [
        [
            Paragraph(
                f"<font color='#808080'>{_escape_for_paragraph(label)}</font>",
                body_style,
            ),
            Paragraph(_escape_for_paragraph(value), body_style),
        ]
        for label, value in cover_meta
    ]
    meta_table = Table(meta_rows, colWidths=[1.7 * inch, 4.5 * inch])
    meta_table.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), _FONT_BODY, 9),
        ("TEXTCOLOR", (0, 0), (0, -1), _FG_MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), _FG_TEXT),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("ALIGN", (1, 0), (1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("BACKGROUND", (0, 0), (-1, -1), _BG_SURFACE),
        ("LINEAFTER", (0, 0), (0, -1), 0.5, _BG_BORDER),
        ("BOX", (0, 0), (-1, -1), 0.5, _BG_BORDER),
    ]))
    meta_table.hAlign = "CENTER"
    story.append(meta_table)


def _append_executive_summary(
    story: list[Any],
    aggregate: MasvsAuditAggregate,
    styles: dict[str, ParagraphStyle],
) -> None:
    """Executive summary — interpretive sentence + four-cell count grid.

    The sentence reads naturally so the lead can paste it into an email
    without polishing ("3 findings, 2 inconclusive across 46 controls
    audited under MASVS 1.4.2-aila."). The grid below restates the
    same numbers in a denser visual that survives black-and-white
    printing.
    """
    story.append(_BookmarkFlowable("masvs-executive-summary", "Executive summary", level=0))
    _append_section_h1(story, "Executive Summary", styles)

    counts = aggregate.summary_counts
    total = len(aggregate.verdicts)
    findings = counts.get(MasvsVerdict.FINDING, 0)
    no_finding = counts.get(MasvsVerdict.NO_FINDING, 0)
    not_applicable = counts.get(MasvsVerdict.NOT_APPLICABLE, 0)
    inconclusive = counts.get(MasvsVerdict.INCONCLUSIVE, 0)

    if total == 0:
        opening = (
            "No controls have terminal verdicts yet — every child "
            "investigation is still in flight or has produced no "
            "primary outcome."
        )
    else:
        opening = (
            f"<b>{findings}</b> fail, "
            f"<b>{no_finding}</b> pass, "
            f"<b>{not_applicable}</b> not applicable, "
            f"<b>{inconclusive}</b> needs review, across "
            f"<b>{total}</b> controls audited under "
            f"MASVS {_escape_for_paragraph(aggregate.masvs_spec_version)}."
        )
    story.append(Paragraph(opening, styles["body"]))
    story.append(Spacer(1, 0.1 * inch))

    header_cells = [
        Paragraph(
            f"<font color='#121212' size='9'><b>"
            f"{_VERDICT_LABEL[v]}</b></font>",
            styles["body"],
        )
        for v in _VERDICT_DISPLAY_ORDER
    ]
    body_cells = [
        Paragraph(
            f"<font color='#ffd7af'><b><font size='16'>"
            f"{counts.get(v, 0)}</font></b></font>",
            styles["body"],
        )
        for v in _VERDICT_DISPLAY_ORDER
    ]
    grid = Table(
        [header_cells, body_cells],
        colWidths=[1.55 * inch] * len(_VERDICT_DISPLAY_ORDER),
    )
    style_cmds: list[tuple[Any, ...]] = [
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 1), (-1, 1), _BG_SURFACE),
        ("BOX", (0, 0), (-1, -1), 0.5, _BG_BORDER),
    ]
    for col_index, verdict in enumerate(_VERDICT_DISPLAY_ORDER):
        style_cmds.append((
            "BACKGROUND", (col_index, 0), (col_index, 0),
            _VERDICT_COLOR[verdict],
        ))
    grid.setStyle(TableStyle(style_cmds))
    grid.hAlign = "CENTER"
    story.append(grid)
    story.append(Spacer(1, 0.2 * inch))

def _append_findings_highlights(
    story: list[Any],
    aggregate: MasvsAuditAggregate,
    styles: dict[str, ParagraphStyle],
) -> None:
    """Page right after Executive Summary listing every FAIL + REVIEW
    verdict with a one-line title — so the reader sees what actually
    needs attention before scrolling through 88 per-control
    subsections. Skips silently when there are zero FAIL + REVIEW
    rows (clean audit, all-PASS).
    """
    fails = [v for v in aggregate.verdicts if v.verdict == MasvsVerdict.FINDING]
    reviews = [v for v in aggregate.verdicts if v.verdict == MasvsVerdict.INCONCLUSIVE]
    if not fails and not reviews:
        return

    story.append(PageBreak())
    story.append(_BookmarkFlowable("masvs-findings-highlights", "Findings & Open Reviews", level=0))
    _append_section_h1(story, "Findings & Open Reviews", styles)
    story.append(Paragraph(
        "Controls requiring operator attention, ranked by verdict severity. "
        "FAIL = the audit identified a compliance gap; REVIEW = the audit "
        "could not reach a conclusion and human follow-up is required.",
        styles["body"],
    ))
    story.append(Spacer(1, 0.15 * inch))

    def _row(v: MasvsControlVerdict) -> list[Any]:
        label = _VERDICT_LABEL[v.verdict]
        _VERDICT_COLOR[v.verdict]
        badge = Paragraph(
            f"<font color='#ffffff' size='9'><b>{label}</b></font>",
            styles["body"],
        )
        cid = Paragraph(f"<b>{_escape_for_paragraph(v.control_id)}</b>", styles["body"])
        reason_text = v.reason or ""
        if v.confidence:
            reason_text = f"confidence {int(v.confidence * 100)}%  {reason_text}".strip()
        evidence_count = len(v.evidence_locations) if v.evidence_locations else 0
        if evidence_count:
            reason_text = f"{evidence_count} evidence ref(s)  {reason_text}".strip()
        reason = Paragraph(
            f"<font size='8'>{_escape_for_paragraph(reason_text or '—')}</font>",
            styles["body"],
        )
        return [badge, cid, reason]

    rows: list[list[Any]] = []
    for v in fails:
        rows.append(_row(v))
    for v in reviews:
        rows.append(_row(v))

    tbl = Table(rows, colWidths=[0.65 * inch, 1.45 * inch, 4.6 * inch])
    style_cmds: list[tuple[Any, ...]] = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("BOX", (0, 0), (-1, -1), 0.4, _BG_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, _BG_BORDER),
    ]
    cursor = 0
    for verdict_group in (fails, reviews):
        verdict_color = (
            _VERDICT_COLOR[MasvsVerdict.FINDING] if verdict_group is fails
            else _VERDICT_COLOR[MasvsVerdict.INCONCLUSIVE]
        )
        for _ in verdict_group:
            style_cmds.append(("BACKGROUND", (0, cursor), (0, cursor), verdict_color))
            style_cmds.append(("BACKGROUND", (1, cursor), (-1, cursor), _BG_SURFACE))
            cursor += 1
    tbl.setStyle(TableStyle(style_cmds))
    tbl.hAlign = "LEFT"
    story.append(tbl)
    story.append(Spacer(1, 0.2 * inch))


def _append_apk_intelligence(
    story: list[Any],
    target: VRTargetSummary,
    static_summary: Mapping[str, Any],
    handles: Mapping[str, Any] | None,
    styles: dict[str, ParagraphStyle],
) -> None:
    """APK Intelligence page: package + build + signing + permissions
    + exported components + native libraries + trackers. The reader
    sees WHAT the audit looked at, not just per-control verdicts.

    Pulls the full ``android_mcp_static_summary`` from ``handles`` when
    available (passed in by the caller from ``_mcp_handles_json``).
    The ``static_summary`` digest on ``target.apk_overview`` only
    stores counts; the full inventory of permission names / native
    .so / exported class names lives in the raw handles blob.
    """
    story.append(PageBreak())
    story.append(_BookmarkFlowable("masvs-apk-intelligence", "APK Intelligence", level=0))
    _append_section_h1(story, "APK Intelligence", styles)
    story.append(Paragraph(
        "What the audit looked at: package identity, signing chain, "
        "manifest declarations, native code, third-party trackers.",
        styles["body"],
    ))
    story.append(Spacer(1, 0.15 * inch))

    full_static = (
        handles.get("android_mcp_static_summary") if isinstance(handles, Mapping) else None
    )
    if not isinstance(full_static, Mapping):
        full_static = static_summary if isinstance(static_summary, Mapping) else {}

    mobsf = (
        handles.get("android_mcp_mobsf_scan") if isinstance(handles, Mapping) else None
    )
    if not isinstance(mobsf, Mapping):
        mobsf = (
            (target.apk_overview or {}).get("mobsf_scan")
            if isinstance(target.apk_overview, Mapping)
            else None
        )
    if not isinstance(mobsf, Mapping):
        mobsf = {}

    def _kv_section(title_text: str, rows: list[tuple[str, str]]) -> None:
        if not rows:
            return
        story.append(Paragraph(
            f"<font color='#ffd7af'><b>{_escape_for_paragraph(title_text)}</b></font>",
            styles["body"],
        ))
        story.append(Spacer(1, 0.04 * inch))
        tbl = Table(
            [
                [
                    Paragraph(f"<font size='9'><b>{_escape_for_paragraph(k)}</b></font>", styles["body"]),
                    Paragraph(f"<font size='9'>{_escape_for_paragraph(v)}</font>", styles["body"]),
                ]
                for k, v in rows
            ],
            colWidths=[1.6 * inch, 5.0 * inch],
        )
        tbl.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("BACKGROUND", (0, 0), (-1, -1), _BG_SURFACE),
            ("BOX", (0, 0), (-1, -1), 0.4, _BG_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, _BG_BORDER),
        ]))
        tbl.hAlign = "LEFT"
        story.append(tbl)
        story.append(Spacer(1, 0.15 * inch))

    def _coerce_list(value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item) for item in value if item is not None]
        return []

    # PACKAGE + BUILD
    package_rows: list[tuple[str, str]] = []
    for label, key in (
        ("Package", "package"),
        ("Version (name)", "version_name"),
        ("Version (code)", "version_code"),
        ("Min SDK", "min_sdk"),
        ("Target SDK", "target_sdk"),
        ("Compile SDK", "compile_sdk"),
        ("Application class", "application_class"),
        ("Main activity", "main_activity"),
    ):
        v = full_static.get(key)
        if v is not None:
            package_rows.append((label, str(v)))
    _kv_section("Package & Build", package_rows)

    # SIGNING CHAIN
    signing_rows: list[tuple[str, str]] = []
    scheme = full_static.get("signing_scheme")
    if scheme is not None:
        signing_rows.append(("Signing scheme", str(scheme)))
    certs = _coerce_list(full_static.get("certificates"))
    if certs:
        signing_rows.append((f"Certificates ({len(certs)})", "\n".join(certs[:5]) + ("\n…" if len(certs) > 5 else "")))
    _kv_section("Signing", signing_rows)

    # PERMISSIONS
    perms = _coerce_list(full_static.get("permissions"))
    dangerous = _coerce_list(full_static.get("dangerous_permissions"))
    if perms:
        perm_rows = [(f"Declared ({len(perms)})", ", ".join(perms[:30]) + ("  …" if len(perms) > 30 else ""))]
        if dangerous:
            perm_rows.append((
                f"Dangerous-protection-level ({len(dangerous)})",
                ", ".join(dangerous),
            ))
        _kv_section("Permissions", perm_rows)

    # EXPORTED COMPONENTS
    exported_groups = [
        ("Activities", "exported_activities"),
        ("Services", "exported_services"),
        ("Receivers", "exported_receivers"),
        ("Providers", "exported_providers"),
    ]
    exp_rows: list[tuple[str, str]] = []
    for label, key in exported_groups:
        lst = _coerce_list(full_static.get(key))
        if lst:
            preview = "\n".join(lst[:8]) + (f"\n… ({len(lst) - 8} more)" if len(lst) > 8 else "")
            exp_rows.append((f"{label} ({len(lst)})", preview))
    if exp_rows:
        _kv_section("Exported Components", exp_rows)

    # NATIVE LIBRARIES (.so under lib/<abi>/)
    native = _coerce_list(full_static.get("native_libs"))
    if native:
        # Bucket by ABI when paths contain '/'.
        per_abi: dict[str, list[str]] = {}
        for path in native:
            parts = path.replace("\\", "/").split("/")
            abi = parts[-2] if len(parts) >= 2 else "?"
            per_abi.setdefault(abi, []).append(parts[-1])
        nat_rows: list[tuple[str, str]] = []
        for abi, libs in sorted(per_abi.items()):
            nat_rows.append((
                f"{abi} ({len(libs)})",
                ", ".join(sorted(set(libs))),
            ))
        _kv_section("Native Libraries", nat_rows)

    # MOBSF SCAN
    mobsf_rows: list[tuple[str, str]] = []
    if mobsf.get("security_score") is not None:
        mobsf_rows.append(("Security score", f"{mobsf['security_score']}/100"))
    trackers = mobsf.get("trackers_detected")
    if trackers is not None:
        mobsf_rows.append(("Trackers detected", str(trackers)))
    raw_trackers = (
        mobsf.get("trackers", {}).get("trackers")
        if isinstance(mobsf.get("trackers"), Mapping)
        else None
    )
    if isinstance(raw_trackers, list) and raw_trackers:
        names = [
            str(t.get("name") or t)
            for t in raw_trackers
            if t is not None
        ]
        if names:
            mobsf_rows.append((
                f"Tracker names ({len(names)})",
                ", ".join(sorted(set(names))[:20]) + ("  …" if len(set(names)) > 20 else ""),
            ))
    buckets = mobsf.get("findings_by_severity")
    if isinstance(buckets, Mapping):
        bucket_strs = [f"{k}: {v}" for k, v in buckets.items() if v]
        if bucket_strs:
            mobsf_rows.append(("MobSF findings", ", ".join(bucket_strs)))
    if mobsf_rows:
        _kv_section("MobSF Static Scan", mobsf_rows)



def _bookmark_key_for_group(group: MasvsGroup) -> str:
    """Stable bookmark id used both as the PDF outline anchor and as
    the named-destination string a future "click TOC entry" link
    would point at.
    """
    return f"masvs-group-{group.value.lower()}"


def _append_group_sections(
    story: list[Any],
    aggregate: MasvsAuditAggregate,
    styles: dict[str, ParagraphStyle],
) -> None:
    """One section per non-empty MASVS group, in canonical order.

    The section header (h1) is the spec-facing label (``MASVS-CRYPTO``)
    and emits a PDF outline bookmark so the viewer renders it as a TOC
    entry. Each row beneath is one control — id, title, verdict badge,
    confidence — enough scaffolding that R-2b can drop the per-control
    body (evidence excerpts + remediation prose) directly below this
    row without restructuring.
    """
    for group in MasvsGroup:
        verdicts = aggregate.by_group.get(group, [])
        if not verdicts:
            continue

        heading = _GROUP_HEADING[group]
        story.append(PageBreak())
        story.append(_BookmarkFlowable(
            _bookmark_key_for_group(group),
            heading,
            level=0,
        ))
        _append_section_h1(story, heading, styles)

        header_row: list[Any] = [
            Paragraph(
                "<font color='#97dbbe'><b>CONTROL</b></font>",
                styles["body"],
            ),
            Paragraph(
                "<font color='#97dbbe'><b>VERDICT</b></font>",
                styles["body"],
            ),
            Paragraph(
                "<font color='#97dbbe'><b>CONFIDENCE</b></font>",
                styles["body"],
            ),
        ]
        rows: list[list[Any]] = [header_row]
        for verdict in verdicts:
            verdict_label = _VERDICT_LABEL[verdict.verdict]
            confidence_pct = int(round(verdict.confidence * 100))
            rows.append([
                Paragraph(
                    f"<font name='{_FONT_BODY_BOLD}'>"
                    f"{_escape_for_paragraph(verdict.control_id)}"
                    f"</font>",
                    styles["body"],
                ),
                Paragraph(
                    f"<font color='#121212'><b>"
                    f"{_escape_for_paragraph(verdict_label)}</b></font>",
                    styles["body"],
                ),
                Paragraph(
                    f"{confidence_pct}%",
                    styles["body"],
                ),
            ])

        group_table = Table(rows, colWidths=[2.0 * inch, 2.2 * inch, 1.4 * inch])
        cmds: list[tuple[Any, ...]] = [
            ("FONT", (0, 0), (-1, -1), _FONT_BODY, 10),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (0, -1), "LEFT"),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("ALIGN", (2, 0), (2, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("BACKGROUND", (0, 0), (-1, 0), _BG_SURFACE),
            ("BOX", (0, 0), (-1, -1), 0.5, _BG_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, _BG_BORDER),
        ]
        for row_index, verdict in enumerate(verdicts, start=1):
            cmds.append((
                "BACKGROUND", (1, row_index), (1, row_index),
                _VERDICT_COLOR[verdict.verdict],
            ))
        group_table.setStyle(TableStyle(cmds))
        group_table.hAlign = "LEFT"
        story.append(KeepTogether(group_table))
        for verdict in verdicts:
            _append_control_subsection(
                story,
                verdict,
                _CATALOG_BY_ID.get(verdict.control_id),
                styles,
            )


def _render_report_section_block(
    story: list[Any],
    section: Mapping[str, Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    """Render the writer-agent's ``ReportSection`` dict as the per-
    control body. The dict mirrors :class:`ReportSection` from
    ``aila.modules.vr.reporting.section_writer`` — we don't import
    the model class here because the cached form on the outcome is
    raw JSON.
    """
    headline = section.get("headline")
    if headline:
        story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph(
            f"<font color='#ffd7af' size='11'><b>"
            f"{_escape_for_paragraph(str(headline))}</b></font>",
            styles["body"],
        ))
        story.append(Spacer(1, 0.05 * inch))

    evidence = section.get("evidence") or []
    if isinstance(evidence, list) and evidence:
        story.append(Paragraph(
            "<font color='#f0a8c7' size='8'><b>EVIDENCE</b></font>",
            styles["meta"],
        ))
        ev_rows: list[list[Any]] = []
        for item in evidence:
            if not isinstance(item, Mapping):
                continue
            loc = str(item.get("location") or "—")
            detail = str(item.get("detail") or "")
            ev_rows.append([
                Paragraph(
                    f"<font name='{_FONT_MONO}' size='8'>"
                    f"{_escape_for_paragraph(loc)}</font>",
                    styles["body"],
                ),
                Paragraph(
                    f"<font size='9'>{_escape_for_paragraph(detail)}</font>",
                    styles["body"],
                ),
            ])
        if ev_rows:
            ev_table = Table(ev_rows, colWidths=[2.6 * inch, 3.6 * inch])
            ev_table.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("BACKGROUND", (0, 0), (-1, -1), _BG_SURFACE),
                ("BOX", (0, 0), (-1, -1), 0.25, _BG_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, _BG_BORDER),
            ]))
            ev_table.hAlign = "LEFT"
            story.append(ev_table)

    risk = section.get("risk") or ""
    if isinstance(risk, str) and risk.strip():
        story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph(
            "<font color='#f0a8c7' size='8'><b>RISK</b></font>",
            styles["meta"],
        ))
        story.append(Paragraph(_escape_for_paragraph(risk), styles["body"]))

    remediation = section.get("remediation") or ""
    if isinstance(remediation, str) and remediation.strip():
        story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph(
            "<font color='#f0a8c7' size='8'><b>REMEDIATION</b></font>",
            styles["meta"],
        ))
        story.append(Paragraph(_escape_for_paragraph(remediation), styles["body"]))

    why = section.get("why_it_matters") or ""
    if isinstance(why, str) and why.strip():
        story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph(
            "<font color='#9c9c9c' size='8'><b>WHY IT MATTERS</b></font>",
            styles["meta"],
        ))
        story.append(Paragraph(
            f"<font color='#9c9c9c' size='9'><i>"
            f"{_escape_for_paragraph(why)}</i></font>",
            styles["body"],
        ))

    caveat = section.get("confidence_note")
    if isinstance(caveat, str) and caveat.strip():
        story.append(Spacer(1, 0.05 * inch))
        story.append(Paragraph(
            f"<font color='#d99a2c' size='8'><b>NOTE:</b> "
            f"{_escape_for_paragraph(caveat)}</font>",
            styles["body"],
        ))


def _append_control_subsection(
    story: list[Any],
    verdict: MasvsControlVerdict,
    control: MasvsControl | None,
    styles: dict[str, ParagraphStyle],
) -> None:
    """Per-control subsection body — title bar / description / evidence /
    verification steps / child investigation link.

    The title bar is a single-row colored table (verdict color
    background, control id + spec title on the left, verdict label
    badge + confidence on the right). The body reuses the standard
    :class:`ParagraphStyle` set so the section reads as a continuation
    of the executive summary's prose, not a separate report.

    Layout (one per control inside a group section):

    - **Title bar** — colored by verdict; one row carrying control id,
      control title, verdict label, confidence percent.
    - **Description** — the spec text the audit ran against (from
      :attr:`MasvsControl.description`).
    - **Affected components** — verbatim ``{file, function}`` list the
      auditor cited in its primary outcome's
      ``payload['affected_components']``. Empty for inconclusive
      verdicts where no primary outcome was emitted.
    - **Verification & remediation** — bulleted
      :attr:`MasvsControl.verification_steps`. The same steps describe
      both how a compliant app looks and what a non-compliant one
      needs to fix, so the section header doubles up on the wording.
    - **Footer** — child investigation id + the operator-facing path
      (matches :file:`src/aila/modules/vr/frontend/routes.tsx`
      ``vr.investigation-detail`` route) + inconclusive reason when
      :attr:`MasvsControlVerdict.reason` is set.

    When ``control`` is ``None`` (catalog moved on after dispatch),
    the renderer emits the title bar + a one-line note and skips the
    description / verification block — partial fidelity beats refusing
    to render the verdict.
    """
    verdict_color = _VERDICT_COLOR[verdict.verdict]
    verdict_label = _VERDICT_LABEL[verdict.verdict]
    confidence_pct = int(round(verdict.confidence * 100))
    title_text = (
        control.title if control is not None else "(not in current catalog)"
    )

    title_cell = Paragraph(
        f"<font color='#121212' size='9'><b>"
        f"{_escape_for_paragraph(verdict.control_id)}</b></font>"
        f"<br/>"
        f"<font color='#121212' size='12'><b>"
        f"{_escape_for_paragraph(title_text)}</b></font>",
        styles["body"],
    )
    badge_cell = Paragraph(
        f"<para alignment='center'>"
        f"<font color='#121212' size='8'><b>VERDICT</b></font><br/>"
        f"<font color='#121212' size='11'><b>"
        f"{_escape_for_paragraph(verdict_label)}</b></font><br/>"
        f"<font color='#121212' size='8'>{confidence_pct}% confidence</font>"
        f"</para>",
        styles["body"],
    )
    title_table = Table(
        [[title_cell, badge_cell]],
        colWidths=[4.7 * inch, 1.5 * inch],
    )
    title_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LINEAFTER", (0, 0), (0, 0), 0.5, colors.HexColor("#121212")),
    ]))
    title_table.hAlign = "LEFT"
    story.append(KeepTogether([Spacer(1, 0.18 * inch), title_table]))

    # 1. CATALOG DESCRIPTION — faded grey, italic, small. Context only.
    if control is not None and control.description.strip():
        story.append(Paragraph(
            "<font color='#9c9c9c' size='8'><i>"
            f"{_escape_for_paragraph(control.description)}</i></font>",
            styles["body"],
        ))

    # 2a. STRUCTURED REPORT SECTION — preferred. Renders the
    #     section-writer agent's headline / evidence / risk /
    #     remediation / why-it-matters fields with proper visual
    #     hierarchy. When the section-writer hasn't run yet (cache
    #     miss + LLM down) we fall back to 2b.
    if verdict.report_section:
        _render_report_section_block(story, verdict.report_section, styles)
    elif verdict.agent_summary:
        # 2b. RAW AGENT SUMMARY fallback — only when the writer agent
        #     didn't run. Less polished but still APK-specific.
        story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph(
            "<font color='#ffd7af'><b>AUDIT FINDINGS</b></font>",
            styles["meta"],
        ))
        for paragraph in verdict.agent_summary.split("\n\n"):
            paragraph = paragraph.strip()
            if paragraph:
                story.append(Paragraph(
                    _escape_for_paragraph(paragraph).replace("\n", "<br/>"),
                    styles["body"],
                ))
                story.append(Spacer(1, 0.04 * inch))

    # 3. AFFECTED COMPONENTS — file:method evidence the agent cited.
    if verdict.evidence_locations:
        story.append(Spacer(1, 0.04 * inch))
        story.append(Paragraph(
            "<font color='#f0a8c7'><b>AFFECTED COMPONENTS</b></font>",
            styles["meta"],
        ))
        ev_rows: list[list[Any]] = [
            [
                Paragraph(
                    f"<font name='{_FONT_MONO}' size='8'>"
                    f"{_escape_for_paragraph(loc.file)}</font>",
                    styles["body"],
                ),
                Paragraph(
                    f"<font name='{_FONT_MONO}' size='8'>"
                    f"{_escape_for_paragraph(loc.function)}</font>",
                    styles["body"],
                ),
            ]
            for loc in verdict.evidence_locations
        ]
        ev_table = Table(ev_rows, colWidths=[4.8 * inch, 1.4 * inch])
        ev_table.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, -1), _FONT_MONO, 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("BACKGROUND", (0, 0), (-1, -1), _BG_SURFACE),
            ("BOX", (0, 0), (-1, -1), 0.25, _BG_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, _BG_BORDER),
        ]))
        ev_table.hAlign = "LEFT"
        story.append(ev_table)

    # 4. GENERIC VERIFICATION STEPS — only rendered when the agent
    #    didn't produce a summary AND there's no evidence either.
    #    Otherwise the catalog's generic "Run apkanalyzer + grep for X"
    #    instructions just add noise to a report a real auditor reads.
    no_agent_content = not verdict.agent_summary and not verdict.evidence_locations
    if no_agent_content and control is not None and control.verification_steps:
        story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph(
            "<font color='#9c9c9c' size='8'><b>VERIFICATION CHECKLIST "
            "(catalog default — agent produced no specific findings)</b></font>",
            styles["meta"],
        ))
        for step in control.verification_steps:
            story.append(Paragraph(
                f"<font size='8'>&bull;&nbsp; {_escape_for_paragraph(step)}</font>",
                styles["body"],
            ))

    path_str = _INVESTIGATION_PATH_TEMPLATE.format(
        investigation_id=verdict.child_investigation_id,
    )
    footer_parts: list[str] = [
        f"Child investigation: <font name='{_FONT_MONO}'>"
        f"{_escape_for_paragraph(verdict.child_investigation_id)}</font>",
        f"Path: <font name='{_FONT_MONO}'>"
        f"{_escape_for_paragraph(path_str)}</font>",
    ]
    if verdict.reason:
        footer_parts.append(
            f"Reason: <font name='{_FONT_MONO}'>"
            f"{_escape_for_paragraph(verdict.reason)}</font>",
        )
    story.append(Spacer(1, 0.05 * inch))
    story.append(Paragraph(
        " &nbsp;|&nbsp; ".join(footer_parts),
        styles["meta"],
    ))


def build_pdf(
    aggregate: MasvsAuditAggregate,
    target: VRTargetSummary,
    handles: Mapping[str, Any] | None = None,
) -> bytes:
    """Render a :class:`MasvsAuditAggregate` as a PDF byte string.

    R-2a scaffolding — cover page, executive summary count grid, and
    one section per non-empty MASVS group with PDF outline bookmarks
    driving the TOC sidebar. R-2b appends per-control subsection bodies
    (verdict badge + evidence excerpts + remediation prose) inside each
    group section without restructuring the existing scaffolding.

    The render is purely structural — it never invents verdicts. Every
    table row and badge traces back to a real
    :class:`MasvsControlVerdict` in ``aggregate.verdicts``, which itself
    cites a real child investigation outcome.

    :param aggregate: Output of :func:`collect_findings` for a MASVS
        audit parent. Partial aggregates (children still in flight) are
        valid — the renderer reports whatever verdicts are resolvable.
    :param target: Read-only target projection supplying the cover
        page's APK identity (display name, package, version, SHA-256).
    :returns: Bytes of a self-contained PDF document. Caller streams
        them directly to the operator via the R-3 download endpoint.
    """
    apk_overview = target.apk_overview or {}
    static_summary: Mapping[str, Any] = {}
    if isinstance(apk_overview, Mapping):
        maybe_static = apk_overview.get("static_summary")
        if isinstance(maybe_static, Mapping):
            static_summary = maybe_static

    buf = io.BytesIO()
    margin = 0.75 * inch
    frame = Frame(
        margin, margin,
        LETTER[0] - 2 * margin, LETTER[1] - 2 * margin,
        id="body",
        leftPadding=0, rightPadding=0,
        topPadding=12, bottomPadding=6,
    )

    # ``_draw_footer`` paints the dark page background as its first
    # action (see ``aila.modules.vr.reporting.pdf_report``), so a plain
    # ``PageTemplate`` with ``onPage=_draw_footer`` produces the same
    # dark canvas + cream footer chrome without subclassing — the
    # ``beforeDrawPage`` override only matters when the background is
    # not also painted by ``onPage``.
    package_for_title = (
        _coerce_str(static_summary.get("package"))
        or _coerce_str(target.android_package_name)
        or target.display_name
        or "android-apk"
    )
    doc = BaseDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=margin,
        rightMargin=margin,
        topMargin=margin,
        bottomMargin=margin,
        title=f"MASVS audit — {package_for_title}",
        author="AILA Vulnerability Research",
        subject=f"OWASP MASVS audit report (catalog {aggregate.masvs_spec_version})",
    )
    doc.addPageTemplates([
        PageTemplate(id="dark", frames=[frame], onPage=_draw_footer),
    ])

    styles = _build_styles()
    story: list[Any] = []

    _append_cover(story, aggregate, target, static_summary, styles)
    _append_findings_highlights(story, aggregate, styles)
    _append_apk_intelligence(story, target, static_summary, handles, styles)
    story.append(PageBreak())
    _append_executive_summary(story, aggregate, styles)
    _append_group_sections(story, aggregate, styles)

    doc.build(story)
    return buf.getvalue()
