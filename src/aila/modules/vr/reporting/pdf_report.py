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
import os
import re
from datetime import UTC, datetime
from pathlib import Path
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

        # Every outcome the agent emitted (chronological asc), not
        # just the terminal one. Earlier outcomes (AssessmentReport
        # mid-investigation, intermediate triage) carry context the
        # writer needs to describe the audit progression. The DESC
        # query is for picking ``terminal`` only.
        outcomes = (await uow.session.exec(
            _select(VRInvestigationOutcomeRecord)
            .where(VRInvestigationOutcomeRecord.investigation_id == investigation_id)
            .order_by(VRInvestigationOutcomeRecord.created_at.asc()),
        )).all()
        terminal = outcomes[-1] if outcomes else None

        # Tool call summary: last 40 calls, distinct (tool, key_arg) pairs
        msgs = (await uow.session.exec(
            _select(VRInvestigationMessageRecord)
            .where(VRInvestigationMessageRecord.investigation_id == investigation_id)
            .where(VRInvestigationMessageRecord.payload_kind == "tool_call")
            .order_by(VRInvestigationMessageRecord.created_at.desc())
            .limit(80),
        )).all()

        # Variant-hunt children spawned by this investigation, with
        # their findings + PoC drafts. When the user exports the
        # PARENT, the report should describe every variant the system
        # has explored — including PoC status. When the user exports
        # a child, this list is empty (children don't spawn variants).
        from aila.modules.vr.db_models import VRFindingRecord  # noqa: PLC0415
        children = (await uow.session.exec(
            _select(VRInvestigationRecord)
            .where(VRInvestigationRecord.parent_investigation_id == investigation_id)
            .order_by(VRInvestigationRecord.created_at.asc()),
        )).all()
        variants: list[dict[str, Any]] = []
        for c in children:
            c_findings = (await uow.session.exec(
                _select(VRFindingRecord)
                .where(VRFindingRecord.target_id == c.target_id)
                .order_by(VRFindingRecord.created_at.desc())
                .limit(3),
            )).all()
            # Pull the child's terminal outcome too — full answer,
            # reasoning, structured payload (affected_components,
            # etc). The finding row only stores the projected fields;
            # the outcome row carries the agent's full submit text.
            c_outcome = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord)
                .where(VRInvestigationOutcomeRecord.investigation_id == c.id)
                .order_by(VRInvestigationOutcomeRecord.created_at.desc())
                .limit(1),
            )).first()
            child_branch = (await uow.session.exec(
                _select(VRInvestigationBranchRecord)
                .where(VRInvestigationBranchRecord.investigation_id == c.id)
                .order_by(VRInvestigationBranchRecord.created_at.asc()),
            )).first()
            try:
                c_payload = json.loads(c_outcome.payload_json or "{}") if c_outcome else {}
            except (ValueError, TypeError):
                c_payload = {}
            variant_entry: dict[str, Any] = {
                "child_id": c.id,
                "title": c.title,
                "status": c.status,
                "question": c.initial_question or "",
                "turn_count": child_branch.turn_count if child_branch else 0,
                "terminal_answer": c_payload.get("answer") or "",
                "terminal_reasoning": c_payload.get("reasoning") or "",
                "terminal_confidence": c_outcome.confidence if c_outcome else None,
                "terminal_kind": c_outcome.outcome_kind if c_outcome else None,
                "affected_components": c_payload.get("affected_components") or [],
                "findings": [],
            }
            for f in c_findings:
                # Pull PoC draft metadata for this finding (matches
                # _resolve_poc_drafts shape so the renderer can render
                # uniformly).
                meta: dict[str, Any] = {}
                try:
                    f_refs = json.loads(f.evidence_refs_json or "[]")
                    for r in f_refs:
                        if isinstance(r, dict) and r.get("kind") == "poc_draft_metadata":
                            meta = r
                            break
                except (ValueError, TypeError):
                    meta = {}
                variant_entry["findings"].append({
                    "finding_id": f.id,
                    "crash_type": f.crash_type,
                    "vulnerable_function": f.vulnerable_function,
                    "root_cause": f.root_cause or "",
                    "crash_signature": f.crash_signature,
                    "poc_code": f.poc_code or "",
                    "poc_language": f.poc_language,
                    "poc_title": meta.get("title", ""),
                    "poc_build_command": meta.get("build_command", ""),
                    "poc_run_command": meta.get("run_command", ""),
                    "poc_expected_outcome": meta.get("expected_outcome", ""),
                    "poc_can_run": meta.get("can_run", False),
                    "poc_caveats": meta.get("caveats") or [],
                })
            variants.append(variant_entry)

        # Findings on THIS investigation's own target — if a PoC was
        # auto-drafted (variant-child path) or operator-triggered,
        # surface the PoC code + metadata so the writer mentions it
        # in remediation / reproduction.
        own_findings = (await uow.session.exec(
            _select(VRFindingRecord)
            .where(VRFindingRecord.target_id == inv.target_id)
            .order_by(VRFindingRecord.created_at.desc())
            .limit(3),
        )).all()
        poc_drafts: list[dict[str, Any]] = []
        for f in own_findings:
            if not f.poc_code:
                continue
            meta: dict[str, Any] = {}
            try:
                refs = json.loads(f.evidence_refs_json or "[]")
                for r in refs:
                    if isinstance(r, dict) and r.get("kind") == "poc_draft_metadata":
                        meta = r
                        break
            except (ValueError, TypeError):
                meta = {}
            poc_drafts.append({
                "finding_id": f.id,
                "language": f.poc_language,
                "code": f.poc_code,
                "title": meta.get("title", ""),
                "build_command": meta.get("build_command", ""),
                "run_command": meta.get("run_command", ""),
                "expected_outcome": meta.get("expected_outcome", ""),
                "can_run": meta.get("can_run", False),
                "caveats": meta.get("caveats") or [],
            })

    case = json.loads(branch.case_state_json or "{}") if branch else {}
    hypotheses = case.get("hypotheses") or []
    rejected = case.get("rejected") or []
    observables = case.get("observables") or {}
    insights: list[str] = []
    for k, v in observables.items():
        if "insight" in k.lower() and isinstance(v, str) and v.strip():
            insights.append(f"{k}: {v}")
    if "key_insight" in observables and isinstance(observables["key_insight"], str):
        kv = observables["key_insight"]
        if not any(kv in i for i in insights):
            insights.insert(0, kv)

    tool_call_summary = _summarize_tool_calls(msgs)

    descriptor = json.loads(target.descriptor_json or "{}") if target else {}

    # Render every outcome (not just terminal) into a short trail so
    # the writer can reference earlier conclusions when narrating the
    # audit progression.
    outcome_trail: list[dict[str, Any]] = []
    for o in outcomes:
        try:
            p = json.loads(o.payload_json or "{}")
        except (ValueError, TypeError):
            p = {}
        outcome_trail.append({
            "kind": o.outcome_kind,
            "confidence": o.confidence,
            "answer": (p.get("answer") or "")[:400],
            "created_at": o.created_at.isoformat() if o.created_at else None,
        })

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
        "outcome_trail": outcome_trail,
        "variants_hunted": variants,
        "poc_drafts": poc_drafts,
        "audit_metadata": _resolve_audit_metadata(inv, descriptor),
        "vulnerable_code_excerpts": await _resolve_code_excerpts(
            descriptor=descriptor,
            affected_components=(
                json.loads(terminal.payload_json or "{}").get("affected_components") or []
                if terminal else []
            ),
        ),
    }

    if terminal is not None:
        payload = json.loads(terminal.payload_json or "{}")
        facts["final_answer"] = payload.get("answer") or ""
        facts["final_reasoning"] = payload.get("reasoning") or ""
        facts["confidence"] = terminal.confidence
        facts["outcome_kind"] = terminal.outcome_kind
        facts["outcome_dispatch_status"] = terminal.dispatch_status
    return facts


_AUDIT_MCP_CLONE_DIR = (
    Path(os.environ.get("AUDIT_MCP_CLONE_DIR"))
    if os.environ.get("AUDIT_MCP_CLONE_DIR")
    else Path.home() / ".cache" / "audit-mcp" / "clones"
)


def _resolve_audit_metadata(
    inv: VRInvestigationRecord,
    descriptor: dict[str, Any],
) -> dict[str, Any]:
    """Pin the report to a specific commit + audit window.

    Returns commit SHA from the cached clone (so the reader knows
    EXACTLY what got audited, not just the symbolic ref the
    investigation was opened against), the audit start/stop window
    + duration, and the symbolic ref. Best-effort: when the clone
    is gone or git fails, returns ``commit_hash=None`` and the PDF
    falls back to showing just the ref.
    """
    import subprocess  # noqa: PLC0415
    from urllib.parse import urlparse  # noqa: PLC0415

    started = inv.created_at
    stopped = inv.stopped_at or inv.updated_at
    duration_seconds: int | None = None
    if started and stopped:
        duration_seconds = int((stopped - started).total_seconds())

    repo_url = descriptor.get("repo_url") or ""
    ref = descriptor.get("vulnerable_ref") or descriptor.get("ref") or "HEAD"

    commit_hash: str | None = None
    clone_path: str | None = None
    if repo_url:
        parsed = urlparse(repo_url)
        host = parsed.hostname or "unknown"
        path = (parsed.path or "").lstrip("/").replace("/", "_").replace(".git", "")
        clone_dirname = f"{host}_{path}@{ref}"
        candidate = _AUDIT_MCP_CLONE_DIR / clone_dirname
        if candidate.is_dir():
            try:
                result = subprocess.run(  # noqa: S603, S607
                    ["git", "-C", str(candidate), "rev-parse", "HEAD"],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                if result.returncode == 0:
                    commit_hash = result.stdout.strip()
                    clone_path = str(candidate)
            except (OSError, subprocess.SubprocessError):
                commit_hash = None

    return {
        "audit_started_at": started.isoformat() if started else None,
        "audit_completed_at": stopped.isoformat() if stopped else None,
        "audit_duration_seconds": duration_seconds,
        "commit_hash": commit_hash,
        "commit_short": commit_hash[:12] if commit_hash else None,
        "ref": ref,
        "repo_url": repo_url or None,
        "clone_path": clone_path,
    }


async def _resolve_code_excerpts(
    *,
    descriptor: dict[str, Any],
    affected_components: list[Any],
) -> list[dict[str, Any]]:
    """Fetch real source for each entry the agent listed in
    ``affected_components``.

    The agent's DIRECT_FINDING / ASSESSMENT_REPORT submit payload
    carries an explicit ``affected_components`` list — the agent
    saw these locations during its own tool calls, so it knows
    them concretely. We render the actual function bodies via
    audit-mcp; no regex mining of prose, no guessing.

    Each entry is expected to be::

        {"file": "src/http/ngx_http_script.c",
         "function": "ngx_http_script_regex_start_code"}

    String entries (legacy submit shape) are also parsed:
    ``"src/http/ngx_http_script.c:1038 ngx_http_script_regex_start_code"``

    Best-effort: missing index, audit-mcp down, or unparseable
    entry → that entry is skipped, not raised.
    """
    if not affected_components:
        return []

    index_id = (
        descriptor.get("audit_mcp_index_id")
        or (descriptor.get("mcp_handles") or {}).get("audit_mcp_index_id")
    )
    if not index_id:
        return []

    normalized: list[tuple[str, str]] = []
    for raw in affected_components[:8]:
        if isinstance(raw, dict):
            fp = str(raw.get("file") or "").strip()
            fn = str(raw.get("function") or "").strip()
            if fp and fn:
                normalized.append((fp, fn))
            continue
        if isinstance(raw, str):
            parts = raw.strip().split()
            if len(parts) < 2:
                continue
            loc = parts[0]
            fn = parts[1]
            fp = loc.partition(":")[0]
            if fp and fn:
                normalized.append((fp, fn))

    from aila.modules.vr.tools.audit_mcp_bridge import AuditMcpBridgeTool  # noqa: PLC0415
    bridge = AuditMcpBridgeTool()
    excerpts: list[dict[str, Any]] = []
    for fp, fn in normalized:
        try:
            result = await bridge.forward(
                action="read_function",
                index_id=index_id,
                file_path=fp,
                name=fn,
            )
        except (OSError, RuntimeError, ValueError):
            continue
        if not isinstance(result, dict) or result.get("status") == "error":
            continue
        body = result.get("body") or []
        code = "\n".join(str(b) for b in body) if isinstance(body, list) else str(body)
        if not code.strip():
            continue
        excerpts.append({
            "file": fp,
            "function": fn,
            "start_line": result.get("start_line"),
            "end_line": result.get("end_line"),
            "language": _guess_language(fp),
            "code": code[:6000],
            "truncated": len(code) > 6000,
        })
    return excerpts


def _guess_language(file_path: str) -> str:
    """Map file extensions → syntax labels for the PDF code blocks."""
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    return {
        "c": "c", "h": "c",
        "cc": "cpp", "cpp": "cpp", "cxx": "cpp", "hpp": "cpp",
        "py": "python", "rs": "rust", "go": "go",
        "js": "javascript", "ts": "typescript", "java": "java",
    }.get(ext, "text")


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
    meta = facts.get("audit_metadata") or {}
    cover_meta = [
        ["Target", facts.get("target_display") or "(unknown)"],
        ["Target kind", facts.get("target_kind") or "unknown"],
    ]
    if meta.get("repo_url") or facts.get("target_repo"):
        cover_meta.append(["Repository", meta.get("repo_url") or facts["target_repo"]])
    if meta.get("ref") or facts.get("target_ref"):
        cover_meta.append(["Ref", meta.get("ref") or facts["target_ref"]])
    if meta.get("commit_hash"):
        cover_meta.append(["Commit (audited)", meta["commit_hash"]])
    if meta.get("audit_started_at"):
        cover_meta.append(["Audit started", meta["audit_started_at"][:16].replace("T", " ") + " UTC"])
    if meta.get("audit_completed_at"):
        cover_meta.append(["Audit completed", meta["audit_completed_at"][:16].replace("T", " ") + " UTC"])
    if meta.get("audit_duration_seconds") is not None:
        secs = meta["audit_duration_seconds"]
        if secs >= 60:
            cover_meta.append(["Audit duration", f"{secs // 60}m {secs % 60}s"])
        else:
            cover_meta.append(["Audit duration", f"{secs}s"])
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

    excerpts = facts.get("vulnerable_code_excerpts") or []
    if excerpts:
        story.append(Paragraph("Vulnerable code", styles["section_h1"]))
        story.append(Paragraph(
            "The following excerpts were resolved from the audited commit "
            f"<font name='Courier'>{_escape_for_paragraph((facts.get('audit_metadata') or {}).get('commit_short') or '(commit unavailable)')}</font>. "
            "Line numbers reflect the file as it existed at audit time; "
            "diff against your tree before patching.",
            styles["body"],
        ))
        for ex in excerpts:
            header = (
                f"<b>{_escape_for_paragraph(ex.get('function', '?'))}</b>  "
                f"<font color='#64748b'>{_escape_for_paragraph(ex.get('file', '?'))}"
                f":{ex.get('start_line', '?')}-{ex.get('end_line', '?')}"
                f"  [{_escape_for_paragraph(ex.get('language', 'text'))}]</font>"
            )
            story.append(Paragraph(header, styles["section_h2"]))
            code_text = ex.get("code", "")
            if ex.get("truncated"):
                code_text += "\n... [excerpt truncated for PDF; full body in audit-mcp index]"
            story.append(Paragraph(
                _escape_for_paragraph(code_text).replace("\n", "<br/>"),
                styles["mono"],
            ))

    pocs = facts.get("poc_drafts") or []
    if pocs:
        story.append(Paragraph(
            "Reproduction scripts (replayable PoCs)",
            styles["section_h1"],
        ))
        story.append(Paragraph(
            "Each PoC below was drafted by the writer agent against the "
            "audited commit. Treat <font name='Courier'>RUNNABLE</font> "
            "entries as ready-to-execute on an isolated test instance; "
            "<font name='Courier'>SKELETON</font> entries need the listed "
            "missing inputs filled in before they trigger the bug.",
            styles["body"],
        ))
        for poc in pocs:
            runnable_tag = "RUNNABLE" if poc.get("can_run") else "SKELETON"
            badge_color = "#65a30d" if poc.get("can_run") else "#c2410c"
            story.append(Paragraph(
                f"<b>{_escape_for_paragraph(poc.get('title') or '(untitled PoC)')}</b>  "
                f"<font color='{badge_color}'>[{runnable_tag}]</font>  "
                f"<font color='#64748b'>language: {_escape_for_paragraph(poc.get('language', '?'))}</font>",
                styles["section_h2"],
            ))
            if poc.get("expected_outcome"):
                story.append(Paragraph(
                    f"<b>Expected outcome:</b> {_escape_for_paragraph(poc['expected_outcome'])}",
                    styles["body"],
                ))
            if poc.get("build_command"):
                story.append(Paragraph("<b>Build:</b>", styles["body"]))
                story.append(Paragraph(
                    _escape_for_paragraph(poc["build_command"]),
                    styles["mono"],
                ))
            if poc.get("run_command"):
                story.append(Paragraph("<b>Run:</b>", styles["body"]))
                story.append(Paragraph(
                    _escape_for_paragraph(poc["run_command"]),
                    styles["mono"],
                ))
            if poc.get("code"):
                story.append(Paragraph("<b>Source:</b>", styles["body"]))
                story.append(Paragraph(
                    _escape_for_paragraph(poc["code"][:8000]).replace("\n", "<br/>"),
                    styles["mono"],
                ))
            for caveat in poc.get("caveats") or []:
                story.append(Paragraph(
                    f"&#9888;&nbsp; <i>{_escape_for_paragraph(str(caveat))}</i>",
                    styles["body"],
                ))

    story.append(Paragraph(
        content.remediation.heading or "Remediation",
        styles["section_h1"],
    ))
    _render_markdown_body(content.remediation.body_markdown, styles, story)

    variants_full = facts.get("variants_hunted") or []
    if variants_full:
        story.append(PageBreak())
        story.append(Paragraph(
            f"Variant investigations ({len(variants_full)} children)",
            styles["section_h1"],
        ))
        story.append(Paragraph(
            "Each variant below is rendered in full from the raw "
            "investigation record — no LLM summary, no truncation. "
            "Per variant: the child investigation's question, status, "
            "every confirmed finding (root cause, crash signature, "
            "vulnerable function), and any PoC drafted for it (full "
            "source + build/run commands).",
            styles["body"],
        ))
        for i, v in enumerate(variants_full):
            story.append(Spacer(1, 0.2 * inch))
            story.append(Paragraph(
                f"Variant {i + 1}: {_escape_for_paragraph(v.get('title') or '(untitled)')}",
                styles["section_h1"],
            ))
            status_line = (
                f"<b>Status:</b> {_escape_for_paragraph(v.get('status') or '?')}"
                f"  <b>Turns:</b> {v.get('turn_count', 0)}"
                f"  <b>Child id:</b> <font name='Courier'>{_escape_for_paragraph(v.get('child_id') or '?')}</font>"
            )
            story.append(Paragraph(status_line, styles["body"]))
            if v.get("question"):
                story.append(Paragraph("<b>Hypothesis under investigation:</b>", styles["body"]))
                story.append(Paragraph(
                    _escape_for_paragraph(v["question"]),
                    styles["body"],
                ))
            if v.get("terminal_kind") and v.get("terminal_answer"):
                story.append(Paragraph(
                    f"<b>Outcome:</b> {_escape_for_paragraph(v['terminal_kind'])} "
                    f"(confidence {_escape_for_paragraph(v.get('terminal_confidence') or 'unknown')})",
                    styles["body"],
                ))
                story.append(Paragraph(
                    _escape_for_paragraph(v["terminal_answer"])[:4000],
                    styles["body"],
                ))
            v_findings = v.get("findings") or []
            if not v_findings:
                story.append(Paragraph(
                    "<i>No confirmed findings on this variant.</i>",
                    styles["body"],
                ))
                continue
            for j, f in enumerate(v_findings):
                story.append(Paragraph(
                    f"<b>Finding {j + 1}.</b> "
                    f"<font name='Courier'>{_escape_for_paragraph(f.get('crash_type') or '(no crash type)')}</font> "
                    f"in <font name='Courier'>{_escape_for_paragraph(f.get('vulnerable_function') or '?')}</font>",
                    styles["section_h2"],
                ))
                if f.get("crash_signature"):
                    story.append(Paragraph(
                        f"<b>Crash signature:</b> "
                        f"<font name='Courier'>{_escape_for_paragraph(f['crash_signature'])}</font>",
                        styles["body"],
                    ))
                if f.get("root_cause"):
                    story.append(Paragraph("<b>Root cause:</b>", styles["body"]))
                    story.append(Paragraph(
                        _escape_for_paragraph(f["root_cause"]),
                        styles["body"],
                    ))
                if f.get("poc_code"):
                    runnable = "RUNNABLE" if f.get("poc_can_run") else "SKELETON"
                    badge = "#65a30d" if f.get("poc_can_run") else "#c2410c"
                    story.append(Paragraph(
                        f"<b>PoC:</b> {_escape_for_paragraph(f.get('poc_title') or '(untitled)')}  "
                        f"<font color='{badge}'>[{runnable}]</font>  "
                        f"<font color='#64748b'>{_escape_for_paragraph(f.get('poc_language') or 'text')}</font>",
                        styles["body"],
                    ))
                    if f.get("poc_expected_outcome"):
                        story.append(Paragraph(
                            f"<b>Expected:</b> {_escape_for_paragraph(f['poc_expected_outcome'])}",
                            styles["body"],
                        ))
                    if f.get("poc_build_command"):
                        story.append(Paragraph("<b>Build:</b>", styles["body"]))
                        story.append(Paragraph(
                            _escape_for_paragraph(f["poc_build_command"]),
                            styles["mono"],
                        ))
                    if f.get("poc_run_command"):
                        story.append(Paragraph("<b>Run:</b>", styles["body"]))
                        story.append(Paragraph(
                            _escape_for_paragraph(f["poc_run_command"]),
                            styles["mono"],
                        ))
                    story.append(Paragraph("<b>Source:</b>", styles["body"]))
                    story.append(Paragraph(
                        _escape_for_paragraph(f["poc_code"][:8000]).replace("\n", "<br/>"),
                        styles["mono"],
                    ))
                    for caveat in f.get("poc_caveats") or []:
                        story.append(Paragraph(
                            f"&#9888;&nbsp; <i>{_escape_for_paragraph(str(caveat))}</i>",
                            styles["body"],
                        ))

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
