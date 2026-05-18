"""Enterprise-grade PDF report renderer for VR investigations.

Architecture:

    DB → ``_collect_facts``  → dict of structured facts
    dict → ``ReportWriter``  → polished prose per section (LLM)
    ReportContent → ``_render_pdf`` → BytesIO of a real PDF (ReportLab)

The PDF layout mirrors enterprise vuln reports (Fortify, Invicti,
Veracode):

  Page 1: Cover (title, target, severity, date, AILA branding)
  Page 2: Executive summary + severity assessment + affected components
  Page 3+: Technical summary, root cause analysis, reproduction
            conditions, remediation, variants, references

ReportLab was chosen over WeasyPrint because WeasyPrint needs GTK
runtime on Windows; ReportLab is pure-python and ships in the
default install. Trade-off: ReportLab is programmatic (no HTML
templates), so styling lives in this module.
"""
from __future__ import annotations

import io
import json
import logging
from datetime import UTC, datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlmodel import select as _select

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
)
from aila.modules.vr.reporting.writer_agent import ReportContent, ReportWriter
from aila.platform.uow import UnitOfWork

__all__ = ["render_investigation_pdf"]

_log = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------


async def render_investigation_pdf(investigation_id: str) -> bytes:
    """Build a PDF report for one investigation.

    Returns the PDF as bytes ready to write to a Response. Raises
    ``ValueError`` when the investigation is missing, ``RuntimeError``
    when the writer agent can't produce content. Caller wraps in a
    FastAPI Response with the right Content-Type / Disposition.
    """
    facts = await _collect_facts(investigation_id)
    if facts is None:
        raise ValueError(f"Investigation {investigation_id} not found")

    writer = ReportWriter()
    content = await writer.write(facts)

    return _render_pdf(facts=facts, content=content)


# ----------------------------------------------------------------------
# Fact collection
# ----------------------------------------------------------------------


async def _collect_facts(investigation_id: str) -> dict[str, Any] | None:
    """Pull every datum the writer needs from the DB in one read pass.

    Reads investigation + primary branch + final outcome + last 40
    tool calls. Returns ``None`` if the investigation row is missing
    so the caller can 404.
    """
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            _select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            ),
        )).first()
        if inv is None:
            return None

        target = (await uow.session.exec(
            _select(VRTargetRecord).where(VRTargetRecord.id == inv.target_id),
        )).first()

        # Primary branch carries case_state with hypotheses + observables
        branch = (await uow.session.exec(
            _select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.investigation_id == investigation_id)
            .order_by(VRInvestigationBranchRecord.created_at.asc()),
        )).first()

        # Final submitted outcome (most recent terminal)
        outcomes = (await uow.session.exec(
            _select(VRInvestigationOutcomeRecord)
            .where(VRInvestigationOutcomeRecord.investigation_id == investigation_id)
            .order_by(VRInvestigationOutcomeRecord.created_at.desc()),
        )).all()
        terminal = outcomes[0] if outcomes else None

        # Tool call summary: last 40 calls, distinct (tool, key_arg) pairs
        msgs = (await uow.session.exec(
            _select(VRInvestigationMessageRecord)
            .where(VRInvestigationMessageRecord.investigation_id == investigation_id)
            .where(VRInvestigationMessageRecord.payload_kind == "tool_call")
            .order_by(VRInvestigationMessageRecord.created_at.desc())
            .limit(80),
        )).all()

    case = json.loads(branch.case_state_json or "{}") if branch else {}
    hypotheses = case.get("hypotheses") or []
    rejected = case.get("rejected") or []
    observables = case.get("observables") or {}
    # Promote any string observable that looks like a captured insight
    # (the agent's own ``key_insight`` / ``current_insight`` keys) to
    # the insights list the writer will reference.
    insights: list[str] = []
    for k, v in observables.items():
        if "insight" in k.lower() and isinstance(v, str) and v.strip():
            insights.append(f"{k}: {v}")
    # Add 'key_insight' first if it exists
    if "key_insight" in observables and isinstance(observables["key_insight"], str):
        kv = observables["key_insight"]
        if not any(kv in i for i in insights):
            insights.insert(0, kv)

    tool_call_summary = _summarize_tool_calls(msgs)

    descriptor = json.loads(target.descriptor_json or "{}") if target else {}

    facts: dict[str, Any] = {
        "investigation_id": investigation_id,
        "investigation_title": inv.title,
        "investigation_kind": inv.kind,
        "investigation_question": inv.initial_question,
        "investigation_status": inv.status,
        "investigation_created": inv.created_at.isoformat() if inv.created_at else None,
        "investigation_stopped": inv.stopped_at.isoformat() if inv.stopped_at else None,
        "cve_id": _extract_cve_id(inv.initial_question or inv.title or ""),
        "target_kind": target.kind if target else "unknown",
        "target_display": target.display_name if target else "(unknown)",
        "target_repo": descriptor.get("repo_url"),
        "target_ref": descriptor.get("vulnerable_ref") or descriptor.get("ref"),
        "hypotheses": hypotheses,
        "rejected_hypotheses": rejected,
        "key_insights": insights,
        "tool_call_summary": tool_call_summary,
        "branch_turn_count": branch.turn_count if branch else 0,
    }

    if terminal is not None:
        payload = json.loads(terminal.payload_json or "{}")
        facts["final_answer"] = payload.get("answer") or ""
        facts["final_reasoning"] = payload.get("reasoning") or ""
        facts["confidence"] = terminal.confidence
        facts["outcome_kind"] = terminal.outcome_kind
        facts["outcome_dispatch_status"] = terminal.dispatch_status
    return facts


def _summarize_tool_calls(
    msgs: list[VRInvestigationMessageRecord],
) -> list[str]:
    """One-liner per significant tool call.

    Format: ``T<turn> <tool>(<key_arg>=<value>)``. Pagination args
    (limit, offset) and noise keys (index_id, binary_id) are dropped
    so each line stays under ~120 chars and reads at a glance.
    """
    noise_keys = {"index_id", "binary_id", "limit", "offset"}
    out: list[str] = []
    # Reverse so chronological (oldest first)
    for m in reversed(msgs):
        try:
            payload = json.loads(m.payload_json or "{}")
            cmd_raw = payload.get("command") or ""
            if not cmd_raw:
                continue
            cmd = json.loads(cmd_raw)
            tool = cmd.get("tool", "?")
            args = cmd.get("args") or {}
            kv = [
                f"{k}={str(v)[:60]}"
                for k, v in args.items()
                if k not in noise_keys
            ]
            arg_str = ", ".join(kv) if kv else ""
            out.append(f"T{m.at_turn or '?'} {tool}({arg_str})")
        except (ValueError, TypeError):
            continue
    return out


def _extract_cve_id(text: str) -> str | None:
    """Pull a CVE id (CVE-YYYY-NNNN) out of arbitrary text.

    Used to surface the CVE on the cover page when the investigation
    title or question references one. Returns ``None`` when no match.
    """
    import re  # noqa: PLC0415
    match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None


# ----------------------------------------------------------------------
# PDF rendering
# ----------------------------------------------------------------------


_SEVERITY_COLOR = {
    "Critical": colors.HexColor("#7f1d1d"),
    "High":     colors.HexColor("#b91c1c"),
    "Medium":   colors.HexColor("#c2410c"),
    "Low":      colors.HexColor("#65a30d"),
    "Informational": colors.HexColor("#2563eb"),
}


def _build_styles() -> dict[str, ParagraphStyle]:
    """ParagraphStyle dictionary used across the report.

    All styles inherit from the sample stylesheet then override
    specifics. Kept in one place so the look stays consistent.
    """
    base = getSampleStyleSheet()
    styles: dict[str, ParagraphStyle] = {}
    styles["cover_title"] = ParagraphStyle(
        "CoverTitle",
        parent=base["Title"],
        fontSize=28,
        leading=34,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=24,
    )
    styles["cover_subtitle"] = ParagraphStyle(
        "CoverSubtitle",
        parent=base["Title"],
        fontSize=16,
        leading=20,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#475569"),
        spaceAfter=12,
    )
    styles["section_h1"] = ParagraphStyle(
        "SectionH1",
        parent=base["Heading1"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=8,
        borderColor=colors.HexColor("#cbd5e1"),
        borderWidth=0,
        borderPadding=0,
    )
    styles["section_h2"] = ParagraphStyle(
        "SectionH2",
        parent=base["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=4,
    )
    styles["body"] = ParagraphStyle(
        "Body",
        parent=base["BodyText"],
        fontSize=10.5,
        leading=15,
        textColor=colors.HexColor("#1f2937"),
        alignment=TA_LEFT,
        spaceAfter=6,
    )
    styles["mono"] = ParagraphStyle(
        "Mono",
        parent=base["Code"],
        fontName="Courier",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderColor=colors.HexColor("#e2e8f0"),
        borderWidth=0.5,
        borderPadding=6,
        leftIndent=8,
        rightIndent=8,
        spaceAfter=8,
    )
    styles["meta"] = ParagraphStyle(
        "Meta",
        parent=base["BodyText"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=2,
    )
    return styles


def _render_pdf(*, facts: dict[str, Any], content: ReportContent) -> bytes:
    """Render the final PDF and return the bytes.

    Layout is intentionally fixed — enterprise reports value
    predictability over per-run customization. The narrative variance
    lives in the writer agent's prose, not in the renderer.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title=content.title,
        author="AILA Vulnerability Research",
        subject=facts.get("cve_id") or "Vulnerability report",
    )
    styles = _build_styles()
    story: list[Any] = []

    # ---- Cover page --------------------------------------------------
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph(content.title, styles["cover_title"]))
    if facts.get("cve_id"):
        story.append(Paragraph(facts["cve_id"], styles["cover_subtitle"]))
    story.append(Spacer(1, 0.5 * inch))

    # Severity callout box
    sev_color = _SEVERITY_COLOR.get(content.severity_label, colors.grey)
    sev_table = Table(
        [[Paragraph(
            f"<font color='white'><b>SEVERITY</b><br/><font size='20'>"
            f"{content.severity_label.upper()}</font></font>",
            styles["body"],
        )]],
        colWidths=[3 * inch],
    )
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), sev_color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    sev_table.hAlign = "CENTER"
    story.append(sev_table)
    story.append(Spacer(1, 0.4 * inch))

    # Cover metadata table
    cover_meta = [
        ["Target", facts.get("target_display") or "(unknown)"],
        ["Target kind", facts.get("target_kind") or "unknown"],
    ]
    if facts.get("target_repo"):
        cover_meta.append(["Repository", facts["target_repo"]])
    if facts.get("target_ref"):
        cover_meta.append(["Ref", facts["target_ref"]])
    cover_meta.append([
        "Report generated",
        datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC"),
    ])
    cover_meta.append(["Investigation id", facts.get("investigation_id", "?")])
    cover_meta.append(["Turns executed", str(facts.get("branch_turn_count", 0))])
    if facts.get("confidence"):
        cover_meta.append(["Audit confidence", str(facts["confidence"])])

    meta_table = Table(cover_meta, colWidths=[1.6 * inch, 4.4 * inch])
    meta_table.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), "Helvetica", 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#475569")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#0f172a")),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("ALIGN", (1, 0), (1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    meta_table.hAlign = "CENTER"
    story.append(meta_table)
    story.append(Spacer(1, 0.6 * inch))
    story.append(Paragraph(
        "Generated by AILA Vulnerability Research",
        styles["meta"],
    ))
    story.append(PageBreak())

    # ---- Executive summary ------------------------------------------
    story.append(Paragraph("Executive summary", styles["section_h1"]))
    story.append(Paragraph(
        _escape_for_paragraph(content.executive_summary),
        styles["body"],
    ))
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("Severity rationale", styles["section_h2"]))
    story.append(Paragraph(
        f"<b>{content.severity_label}.</b> "
        f"{_escape_for_paragraph(content.severity_rationale)}",
        styles["body"],
    ))
    story.append(Spacer(1, 0.15 * inch))

    if content.affected_components:
        story.append(Paragraph("Affected components", styles["section_h2"]))
        for comp in content.affected_components:
            story.append(Paragraph(
                f"&bull;&nbsp; <font name='Courier'>{_escape_for_paragraph(comp)}</font>",
                styles["body"],
            ))
        story.append(Spacer(1, 0.15 * inch))

    story.append(PageBreak())

    # ---- Technical sections -----------------------------------------
    story.append(Paragraph("Technical summary", styles["section_h1"]))
    story.append(Paragraph(
        _escape_for_paragraph(content.technical_summary),
        styles["body"],
    ))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph(
        content.root_cause_analysis.heading or "Root cause analysis",
        styles["section_h1"],
    ))
    _render_markdown_body(content.root_cause_analysis.body_markdown, styles, story)

    story.append(Paragraph("Reproduction conditions", styles["section_h1"]))
    _render_markdown_body(content.reproduction_conditions, styles, story)

    story.append(Paragraph(
        content.remediation.heading or "Remediation",
        styles["section_h1"],
    ))
    _render_markdown_body(content.remediation.body_markdown, styles, story)

    if content.variant_surface:
        story.append(Paragraph("Variant surface to re-audit", styles["section_h1"]))
        _render_markdown_body(content.variant_surface, styles, story)

    if content.references:
        story.append(Paragraph("References", styles["section_h1"]))
        for ref in content.references:
            story.append(Paragraph(
                f"&bull;&nbsp; <font color='#2563eb'>{_escape_for_paragraph(ref)}</font>",
                styles["body"],
            ))

    doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
    return buf.getvalue()


def _render_markdown_body(
    text: str,
    styles: dict[str, ParagraphStyle],
    story: list[Any],
) -> None:
    """Render a markdown-ish body into ReportLab flowables.

    Handles three constructs to keep the renderer pragmatic without
    pulling a full markdown parser:
      - fenced code blocks (``` ... ```) → mono style box
      - bullet lines (- foo / * foo) → bulleted paragraph
      - everything else → body paragraph with inline `code` →
        <font name='Courier'>code</font> substitution
    """
    if not text:
        story.append(Paragraph(
            "<i>Not established by this investigation.</i>",
            styles["body"],
        ))
        return

    in_code = False
    code_buffer: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line.strip().startswith("```"):
            if in_code:
                # close code block
                code_text = "\n".join(code_buffer)
                story.append(Paragraph(
                    _escape_for_paragraph(code_text).replace("\n", "<br/>"),
                    styles["mono"],
                ))
                code_buffer = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_buffer.append(line)
            continue
        if not line:
            story.append(Spacer(1, 0.08 * inch))
            continue
        stripped = line.lstrip()
        if stripped.startswith(("- ", "* ")):
            text_part = stripped[2:]
            story.append(Paragraph(
                f"&bull;&nbsp; {_inline_markdown(text_part)}",
                styles["body"],
            ))
        else:
            story.append(Paragraph(_inline_markdown(line), styles["body"]))

    if in_code and code_buffer:
        story.append(Paragraph(
            _escape_for_paragraph("\n".join(code_buffer)).replace("\n", "<br/>"),
            styles["mono"],
        ))


def _inline_markdown(text: str) -> str:
    """Map inline ``code`` to <font name='Courier'> + escape XML chars.

    Order matters: escape first, then substitute, because escaping
    would mangle the <font> tag we insert.
    """
    escaped = _escape_for_paragraph(text)
    # Replace `code` with monospaced font. Use a simple non-greedy
    # regex; this is presentation, not security-critical parsing.
    import re  # noqa: PLC0415
    return re.sub(
        r"`([^`]+)`",
        lambda m: f"<font name='Courier' color='#0f172a'>{m.group(1)}</font>",
        escaped,
    )


def _escape_for_paragraph(text: str) -> str:
    """ReportLab Paragraph treats input as XML-ish markup.

    Escape the three characters that would otherwise tear it: ``&``,
    ``<``, ``>``. Newlines stay as-is — Paragraph collapses them to
    spaces unless we substitute ``<br/>`` (callers do that when they
    need preservation).
    """
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _draw_footer(canvas: Any, doc: Any) -> None:
    """Page footer: page number left, AILA branding right.

    Drawn on every page via SimpleDocTemplate's onFirstPage /
    onLaterPages hooks. Keeps the footer consistent without
    bloating the story list.
    """
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#94a3b8"))
    page_num = canvas.getPageNumber()
    canvas.drawString(0.75 * inch, 0.4 * inch, f"Page {page_num}")
    canvas.drawRightString(
        LETTER[0] - 0.75 * inch,
        0.4 * inch,
        "AILA Vulnerability Research — confidential",
    )
    canvas.restoreState()
