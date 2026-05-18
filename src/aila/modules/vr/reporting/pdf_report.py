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

    When the investigation has a confirmed finding (terminal
    DIRECT_FINDING) but NO PoC has been drafted yet, we run the
    PocWriter inline here so the PDF always includes a reproduction
    script. Cost: one extra LLM round-trip (~10-30s). Without this,
    operator-triggered PDF export of any investigation that never
    went through the variant-child auto-PoC pipeline would silently
    drop the Reproduction scripts section.
    """
    facts = await _collect_facts(investigation_id)
    if facts is None:
        raise ValueError(f"Investigation {investigation_id} not found")

    # On-demand PoC: only when the agent submitted a real finding
    # (terminal exists) AND no PoC is attached yet. The drafted PoC
    # is added to facts in-memory for THIS render only — persistence
    # to VRFindingRecord requires a finding row, which standalone
    # investigations (no project_id) don't have. Operator who wants
    # the PoC persisted should hit POST /vr/findings/{id}/draft-poc
    # on a finding-backed investigation.
    if facts.get("final_answer") and not facts.get("poc_drafts"):
        inline_poc = await _draft_poc_inline(facts)
        if inline_poc is not None:
            facts["poc_drafts"] = [inline_poc]

    writer = ReportWriter()
    content = await writer.write(facts)

    return _render_pdf(facts=facts, content=content)


async def _draft_poc_inline(facts: dict[str, Any]) -> dict[str, Any] | None:
    """Run PocWriter against the investigation facts and return a
    poc_drafts-shaped dict for in-memory inclusion in the PDF.

    Returns None when the writer fails — the report renders without
    the Reproduction section rather than aborting the whole PDF.
    """
    from aila.modules.vr.reporting.poc_writer import PocWriter  # noqa: PLC0415

    poc_facts = {
        **facts,
        "vulnerability_class": (facts.get("final_answer") or "")[:120],
        "root_cause_summary": (facts.get("final_reasoning") or "")[:2000],
    }
    try:
        draft = await PocWriter().write(poc_facts)
    except (RuntimeError, ValueError) as exc:
        _log.warning("inline PocWriter failed for export: %s", exc)
        return None
    return {
        "finding_id": "inline-draft",
        "language": draft.language,
        "code": draft.code,
        "title": draft.title,
        "build_command": draft.build_command,
        "run_command": draft.run_command,
        "expected_outcome": draft.expected_outcome,
        "can_run": draft.can_run,
        "caveats": draft.caveats,
    }


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
        # Total message count across all kinds (tool_call + executor
        # responses + operator messages) — surfaced on the cover so
        # the reader sees both turn count + total messages and isn't
        # confused when total >> turns (each turn writes ~2 messages).
        from sqlalchemy import text as _sql_text  # noqa: PLC0415
        msg_count_row = (await uow.session.exec(
            _sql_text(
                "SELECT COUNT(*) FROM vr_investigation_messages "
                "WHERE investigation_id = :inv",
            ).bindparams(inv=investigation_id),
        )).first()
        message_count = int(msg_count_row[0]) if msg_count_row else 0

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
        "message_count": message_count,
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
    commit_date: str | None = None
    git_describe: str | None = None
    tags_containing: list[str] = []
    clone_path: str | None = None

    def _git(args: list[str], cwd: str, timeout: int = 5) -> str | None:
        """Run a git subcommand in ``cwd`` and return stripped stdout
        (or None on failure). Used so this helper degrades to a
        partial result when individual git queries fail instead of
        aborting the whole audit_metadata block.
        """
        try:
            result = subprocess.run(  # noqa: S603, S607
                ["git", "-C", cwd, *args],
                capture_output=True, text=True,
                timeout=timeout, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        return result.stdout.strip() or None

    if repo_url:
        parsed = urlparse(repo_url)
        host = parsed.hostname or "unknown"
        path = (parsed.path or "").lstrip("/").replace("/", "_").replace(".git", "")
        clone_dirname = f"{host}_{path}@{ref}"
        candidate = _AUDIT_MCP_CLONE_DIR / clone_dirname
        if candidate.is_dir():
            clone = str(candidate)
            commit_hash = _git(["rev-parse", "HEAD"], clone)
            if commit_hash:
                clone_path = clone
                # audit-mcp typically clones shallow (--depth=1) so
                # 'git describe' can't walk ancestry to find any tag.
                # Lazy-upgrade the clone to full history + all tags
                # on first report — subsequent reports are instant.
                # ``--unshallow`` is a no-op when the clone is
                # already full-history. 60s timeout covers a typical
                # 30MB fetch on a residential connection.
                _git(["fetch", "--unshallow", "--tags", "origin"], clone, timeout=60)
                _git(["fetch", "--tags", "origin"], clone, timeout=30)
                # Closest tag, falling back to a short SHA when no
                # tags exist (--always). For nginx this resolves to
                # 'release-1.27.3-83-geff1108854' or similar — the
                # tag plus distance plus SHA tail.
                git_describe = _git(["describe", "--tags", "--always", commit_hash], clone, timeout=10)
                # Every tag that CONTAINS this commit — tells the
                # reader which named releases are affected. Sorted
                # by version under git's tag-sort heuristic.
                tags_raw = _git(["tag", "--contains", commit_hash], clone, timeout=15)
                if tags_raw:
                    tags_containing = [
                        line.strip()
                        for line in tags_raw.splitlines()
                        if line.strip()
                    ][:25]  # cap for cover page readability
                # ISO-8601 commit date. Useful when the reader needs
                # to correlate with CVE publish date.
                commit_date = _git(
                    ["log", "-1", "--format=%cI", commit_hash], clone,
                )

    return {
        "audit_started_at": started.isoformat() if started else None,
        "audit_completed_at": stopped.isoformat() if stopped else None,
        "audit_duration_seconds": duration_seconds,
        "commit_hash": commit_hash,
        "commit_short": commit_hash[:12] if commit_hash else None,
        "commit_date": commit_date,
        "git_describe": git_describe,
        "tags_containing": tags_containing,
        "vulnerable_versions": tags_containing,  # alias for prompt clarity
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


# Midnight Cloud 8 palette — dark page, cream foreground text,
# pastel accents for severity / headings / syntax highlighting.
# Sourced from the operator's neovim theme so the report visual
# matches the editor they live in.
_BG_PAGE        = colors.HexColor("#121212")  # main page background
_BG_SURFACE     = colors.HexColor("#1f1d1d")  # table / mono block bg (slight lift)
_BG_BORDER      = colors.HexColor("#3c3836")  # subtle separators
_FG_TEXT        = colors.HexColor("#ffd7af")  # body cream
_FG_MUTED       = colors.HexColor("#808080")  # comments / meta
_FG_HEADING     = colors.HexColor("#97dbbe")  # mint — section_h1
_FG_SUBHEAD     = colors.HexColor("#f0a8c7")  # peach — section_h2
_FG_ACCENT      = colors.HexColor("#d7afd7")  # orchid — table headers
_FG_LINK        = colors.HexColor("#af87d7")  # lavender

# Severity badges — sit on _BG_PAGE; bright enough to stay legible.
_SEVERITY_COLOR = {
    "CRITICAL":      colors.HexColor("#ff5f87"),  # pink-red, alert
    "HIGH":          colors.HexColor("#f0a8c7"),  # peach pink
    "MEDIUM":        colors.HexColor("#d7afd7"),  # orchid
    "LOW":           colors.HexColor("#b092ff"),  # violet
    "INFORMATIONAL": colors.HexColor("#97dbbe"),  # mint
    # Lowercase aliases for callers that still pass title-case.
    "Critical": colors.HexColor("#ff5f87"),
    "High":     colors.HexColor("#f0a8c7"),
    "Medium":   colors.HexColor("#d7afd7"),
    "Low":      colors.HexColor("#b092ff"),
    "Informational": colors.HexColor("#97dbbe"),
}


def _build_styles() -> dict[str, ParagraphStyle]:
    """ParagraphStyle dictionary used across the report.

    All styles target the dark Midnight Cloud 8 surface — cream
    body text on the dark page, mint headings, peach subheads,
    pastel mono blocks for code excerpts.
    """
    base = getSampleStyleSheet()
    styles: dict[str, ParagraphStyle] = {}
    styles["cover_title"] = ParagraphStyle(
        "CoverTitle",
        parent=base["Title"],
        fontSize=28,
        leading=34,
        alignment=TA_CENTER,
        textColor=_FG_HEADING,
        spaceAfter=24,
    )
    styles["cover_subtitle"] = ParagraphStyle(
        "CoverSubtitle",
        parent=base["Title"],
        fontSize=16,
        leading=20,
        alignment=TA_CENTER,
        textColor=_FG_SUBHEAD,
        spaceAfter=12,
    )
    styles["section_h1"] = ParagraphStyle(
        "SectionH1",
        parent=base["Heading1"],
        fontSize=18,
        leading=22,
        textColor=_FG_HEADING,
        spaceBefore=14,
        spaceAfter=8,
        borderColor=_BG_BORDER,
        borderWidth=0,
        borderPadding=0,
    )
    styles["section_h2"] = ParagraphStyle(
        "SectionH2",
        parent=base["Heading2"],
        fontSize=13,
        leading=16,
        textColor=_FG_SUBHEAD,
        spaceBefore=10,
        spaceAfter=4,
    )
    styles["body"] = ParagraphStyle(
        "Body",
        parent=base["BodyText"],
        fontSize=10.5,
        leading=15,
        textColor=_FG_TEXT,
        alignment=TA_LEFT,
        spaceAfter=6,
    )
    styles["mono"] = ParagraphStyle(
        "Mono",
        parent=base["Code"],
        fontName="Courier",
        fontSize=9,
        leading=12,
        textColor=_FG_TEXT,
        backColor=_BG_SURFACE,
        borderColor=_BG_BORDER,
        borderWidth=0.5,
        borderPadding=8,
        leftIndent=8,
        rightIndent=8,
        spaceAfter=8,
    )
    styles["meta"] = ParagraphStyle(
        "Meta",
        parent=base["BodyText"],
        fontSize=9,
        leading=12,
        textColor=_FG_MUTED,
        spaceAfter=2,
    )
    return styles


def _render_pdf(*, facts: dict[str, Any], content: ReportContent) -> bytes:
    """Render the final PDF.

    Layout walks ``ReportContent`` fields in this fixed order so
    every report from this writer has identical visual structure:

        Cover (title, severity overview, audit pinning)
        Introduction
        Audit Summary
        Test Approach
        Risk Methodology       (static)
        Scope                  (component list)
        Assessment Overview    (severity-count table)
        Findings & Tech Details
          per FindingSection:  [VR-NN] TITLE — SEVERITY
                               Description
                               Risk Level (likelihood, impact)
                               Proof of Concept   (optional)
                               Code Location
                               Recommendation
        References
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
        author=content.auditor,
        subject=facts.get("cve_id") or "Vulnerability report",
    )
    styles = _build_styles()
    story: list[Any] = []

    # ── Cover page ────────────────────────────────────────────────
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph(content.title, styles["cover_title"]))
    if facts.get("cve_id"):
        story.append(Paragraph(facts["cve_id"], styles["cover_subtitle"]))
    story.append(Paragraph(content.auditor, styles["cover_subtitle"]))
    story.append(Spacer(1, 0.5 * inch))

    # Dominant severity callout — pick the highest severity among
    # findings (CRITICAL > HIGH > ... > INFORMATIONAL). When there
    # are no findings, render an INFORMATIONAL badge with the
    # "no confirmed bugs" copy.
    dominant = _dominant_severity(content.findings)
    sev_color = _SEVERITY_COLOR.get(dominant, colors.HexColor("#aac8e0"))
    sev_table = Table(
        [[Paragraph(
            f"<font color='white'><b>OVERALL RISK</b><br/>"
            f"<font size='20'>{dominant}</font></font>",
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
    ]))
    sev_table.hAlign = "CENTER"
    story.append(sev_table)
    story.append(Spacer(1, 0.4 * inch))

    _append_cover_meta_table(story, facts, styles)

    story.append(Spacer(1, 0.6 * inch))
    story.append(Paragraph(
        f"Generated by {content.auditor}",
        styles["meta"],
    ))
    story.append(PageBreak())

    # ── Introduction ─────────────────────────────────────────────
    story.append(Paragraph("Introduction", styles["section_h1"]))
    story.append(Paragraph(_escape_for_paragraph(content.introduction), styles["body"]))
    story.append(Spacer(1, 0.15 * inch))

    # ── Audit Summary ────────────────────────────────────────────
    story.append(Paragraph("Audit Summary", styles["section_h1"]))
    story.append(Paragraph(_escape_for_paragraph(content.audit_summary), styles["body"]))
    story.append(Spacer(1, 0.15 * inch))

    # ── Test Approach ────────────────────────────────────────────
    story.append(Paragraph("Test Approach", styles["section_h1"]))
    story.append(Paragraph(_escape_for_paragraph(content.test_approach), styles["body"]))
    story.append(Spacer(1, 0.15 * inch))

    # ── Risk Methodology (static block) ──────────────────────────
    story.append(Paragraph("Risk Methodology", styles["section_h1"]))
    story.append(Paragraph(
        "Findings are scored on a 5-point likelihood × impact "
        "matrix. Likelihood (L) measures how plausible an incident "
        "is, impact (I) measures the damage one would cause. The "
        "sum L+I drives the severity label:",
        styles["body"],
    ))
    story.append(Paragraph(
        "&bull;&nbsp; <b>10</b> &mdash; CRITICAL<br/>"
        "&bull;&nbsp; <b>8&ndash;9</b> &mdash; HIGH<br/>"
        "&bull;&nbsp; <b>6&ndash;7</b> &mdash; MEDIUM<br/>"
        "&bull;&nbsp; <b>4&ndash;5</b> &mdash; LOW<br/>"
        "&bull;&nbsp; <b>1&ndash;3</b> &mdash; INFORMATIONAL",
        styles["body"],
    ))
    story.append(Spacer(1, 0.15 * inch))

    # ── Scope ────────────────────────────────────────────────────
    story.append(Paragraph("Scope", styles["section_h1"]))
    if content.scope:
        for c in content.scope:
            line = (
                f"&bull;&nbsp; <font name='Courier'>"
                f"{_escape_for_paragraph(c.name)}</font>"
            )
            if c.note:
                line += f" &mdash; {_escape_for_paragraph(c.note)}"
            story.append(Paragraph(line, styles["body"]))
    else:
        story.append(Paragraph(
            "<i>Not established by this investigation.</i>",
            styles["body"],
        ))
    story.append(Spacer(1, 0.15 * inch))

    # ── Assessment Summary & Findings Overview ───────────────────
    story.append(PageBreak())
    story.append(Paragraph(
        "Assessment Summary &amp; Findings Overview",
        styles["section_h1"],
    ))
    story.append(Paragraph(
        _escape_for_paragraph(content.assessment_overview),
        styles["body"],
    ))
    story.append(Spacer(1, 0.1 * inch))
    _append_severity_count_table(story, content.findings, styles)
    story.append(Spacer(1, 0.15 * inch))
    if content.findings:
        _append_findings_index_table(story, content.findings, styles)

    # ── Findings & Tech Details ──────────────────────────────────
    if content.findings:
        story.append(PageBreak())
        story.append(Paragraph("Findings &amp; Tech Details", styles["section_h1"]))
        for finding in content.findings:
            _append_finding_block(story, finding, styles)

    # ── References ───────────────────────────────────────────────
    if content.references:
        story.append(Spacer(1, 0.25 * inch))
        story.append(Paragraph("References", styles["section_h1"]))
        for ref in content.references:
            story.append(Paragraph(
                f"&bull;&nbsp; <font color='#7a6f9e'>"
                f"{_escape_for_paragraph(ref)}</font>",
                styles["body"],
            ))

    doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
    return buf.getvalue()


# ── Renderer helpers ───────────────────────────────────────────────


_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def _dominant_severity(findings: list[Any]) -> str:
    """Highest severity present in the findings list. Returns
    ``INFORMATIONAL`` when no findings exist — the cover badge
    still needs SOMETHING to render.
    """
    if not findings:
        return "INFORMATIONAL"
    found = {f.severity.upper() for f in findings if getattr(f, "severity", None)}
    for label in _SEVERITY_ORDER:
        if label in found:
            return label
    return "INFORMATIONAL"


def _append_cover_meta_table(
    story: list[Any],
    facts: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    """Cover-page metadata block (target / commit / audit window)."""
    meta = facts.get("audit_metadata") or {}
    cover_meta: list[list[str]] = [
        ["Target", facts.get("target_display") or "(unknown)"],
        ["Target kind", facts.get("target_kind") or "unknown"],
    ]
    if meta.get("repo_url") or facts.get("target_repo"):
        cover_meta.append(["Repository", meta.get("repo_url") or facts["target_repo"]])
    if meta.get("ref") or facts.get("target_ref"):
        cover_meta.append(["Ref", meta.get("ref") or facts["target_ref"]])
    if meta.get("commit_hash"):
        cover_meta.append(["Commit (audited)", meta["commit_hash"]])
    if meta.get("commit_date"):
        cover_meta.append(["Commit date", meta["commit_date"][:10]])
    if meta.get("git_describe"):
        cover_meta.append(["Version (describe)", meta["git_describe"]])
    tags_containing = meta.get("tags_containing") or []
    if tags_containing:
        shown = tags_containing[:8]
        suffix = f" (+ {len(tags_containing) - 8} more)" if len(tags_containing) > 8 else ""
        cover_meta.append(["Patched in releases", ", ".join(shown) + suffix])
    elif meta.get("commit_hash"):
        cover_meta.append([
            "Patched in releases",
            "NONE — commit not included in any tagged release; every published version is unpatched",
        ])
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
    cover_meta.append([
        "Reasoning turns",
        f"{facts.get('branch_turn_count', 0)} (over {facts.get('message_count', 0)} total messages)",
    ])

    meta_table = Table(cover_meta, colWidths=[1.6 * inch, 4.4 * inch])
    meta_table.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), "Helvetica", 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#8a7a90")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#4a4458")),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("ALIGN", (1, 0), (1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#faf6fc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d8d0e0")),
    ]))
    meta_table.hAlign = "CENTER"
    story.append(meta_table)


def _append_severity_count_table(
    story: list[Any],
    findings: list[Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    """Compact severity-count summary row used at the head of the
    findings overview. One column per severity, count below the
    label, badge color as the cell background.
    """
    del styles
    counts = {label: 0 for label in _SEVERITY_ORDER}
    for f in findings:
        sev = (getattr(f, "severity", "") or "").upper()
        if sev in counts:
            counts[sev] += 1

    header = [Paragraph(
        f"<font color='white'><b>{label}</b></font>", _build_styles()["body"],
    ) for label in _SEVERITY_ORDER]
    body = [Paragraph(
        f"<b><font size='14'>{counts[label]}</font></b>", _build_styles()["body"],
    ) for label in _SEVERITY_ORDER]

    table = Table([header, body], colWidths=[1.2 * inch] * len(_SEVERITY_ORDER))
    style_cmds: list[tuple[Any, ...]] = [
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#faf6fc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d8d0e0")),
    ]
    for i, label in enumerate(_SEVERITY_ORDER):
        style_cmds.append((
            "BACKGROUND", (i, 0), (i, 0),
            _SEVERITY_COLOR.get(label, colors.HexColor("#aac8e0")),
        ))
    table.setStyle(TableStyle(style_cmds))
    table.hAlign = "CENTER"
    story.append(table)


def _append_findings_index_table(
    story: list[Any],
    findings: list[Any],
    styles: dict[str, ParagraphStyle],
) -> None:
    """Halborn-style 3-column finding overview table:
        SECURITY ANALYSIS | RISK LEVEL | RECOMMENDATION
    Each cell is a Paragraph so long titles wrap cleanly.
    """
    rows: list[list[Any]] = [[
        Paragraph("<b>SECURITY ANALYSIS</b>", styles["body"]),
        Paragraph("<b>RISK LEVEL</b>", styles["body"]),
        Paragraph("<b>RECOMMENDATION</b>", styles["body"]),
    ]]
    for f in findings:
        sev = (getattr(f, "severity", "") or "").upper()
        sev_color = _SEVERITY_COLOR.get(sev, colors.HexColor("#aac8e0"))
        rows.append([
            Paragraph(
                f"{_escape_for_paragraph(f.id)} {_escape_for_paragraph(f.title)}",
                styles["body"],
            ),
            Paragraph(
                f"<font color='#4a4458'><b>{sev}</b></font>",
                styles["body"],
            ),
            Paragraph("FIX AVAILABLE", styles["body"]),
        ])
        # Tint the risk-level cell with the pastel severity color.
        rows[-1][1] = Paragraph(
            f"<b>{sev}</b>",
            ParagraphStyle("sev_cell", parent=styles["body"], textColor=colors.HexColor("#4a4458")),
        )
        # we keep simple text; cell background is applied via style cmd below
        del sev_color

    table = Table(rows, colWidths=[3.5 * inch, 1.3 * inch, 1.7 * inch])
    style_cmds: list[tuple[Any, ...]] = [
        ("FONT", (0, 0), (-1, -1), "Helvetica", 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("ALIGN", (2, 0), (2, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ebe3f0")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d8d0e0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e8e0ee")),
    ]
    # Tint risk-level cell per row.
    for i, f in enumerate(findings, start=1):
        sev = (getattr(f, "severity", "") or "").upper()
        sev_color = _SEVERITY_COLOR.get(sev, colors.HexColor("#aac8e0"))
        style_cmds.append(("BACKGROUND", (1, i), (1, i), sev_color))
    table.setStyle(TableStyle(style_cmds))
    table.hAlign = "CENTER"
    story.append(table)


def _append_finding_block(
    story: list[Any],
    finding: Any,
    styles: dict[str, ParagraphStyle],
) -> None:
    """Render one FindingSection in the per-finding format.

    Layout (one per finding):
        [ID] TITLE — SEVERITY        section_h1
          Description                 section_h2 + body
          Risk Level                  section_h2 + body
          Proof of Concept (opt)      section_h2 + mono
          Code Location               section_h2 + mono
          Recommendation              section_h2 + body (optional inline code)
    """
    story.append(Spacer(1, 0.25 * inch))
    sev = (getattr(finding, "severity", "") or "").upper()
    story.append(Paragraph(
        f"[{_escape_for_paragraph(finding.id)}] "
        f"{_escape_for_paragraph(finding.title)} &mdash; "
        f"<font color='#4a4458'>{sev}</font>",
        styles["section_h1"],
    ))

    story.append(Paragraph("Description", styles["section_h2"]))
    story.append(Paragraph(
        _escape_for_paragraph(finding.description),
        styles["body"],
    ))

    story.append(Paragraph("Risk Level", styles["section_h2"]))
    story.append(Paragraph(
        f"<b>Likelihood &ndash; {finding.likelihood}</b><br/>"
        f"<b>Impact &ndash; {finding.impact}</b><br/>"
        f"<b>Severity:</b> {sev} (L+I = {finding.likelihood + finding.impact})",
        styles["body"],
    ))

    if finding.proof_of_concept and finding.proof_of_concept.strip():
        story.append(Paragraph("Proof of Concept", styles["section_h2"]))
        story.append(Paragraph(
            _escape_for_paragraph(finding.proof_of_concept[:8000]).replace("\n", "<br/>"),
            styles["mono"],
        ))

    story.append(Paragraph("Code Location", styles["section_h2"]))
    story.append(Paragraph(
        _escape_for_paragraph(finding.code_location[:8000]).replace("\n", "<br/>"),
        styles["mono"],
    ))

    story.append(Paragraph("Recommendation", styles["section_h2"]))
    _render_markdown_body(finding.recommendation, styles, story)


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
    """Per-page background + footer chrome.

    Drawn on every page via SimpleDocTemplate's onFirstPage /
    onLaterPages hooks. We paint the full-page dark background here
    FIRST (saveState → fill → restoreState), then the footer text
    on top in cream. The story flowables render between the bg
    fill and the footer text on the page, so they sit on the dark
    surface naturally.
    """
    del doc
    # Full-page dark background — Midnight Cloud 8 page color.
    canvas.saveState()
    canvas.setFillColor(_BG_PAGE)
    canvas.rect(0, 0, LETTER[0], LETTER[1], stroke=0, fill=1)
    canvas.restoreState()
    # Footer
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(_FG_MUTED)
    page_num = canvas.getPageNumber()
    canvas.drawString(0.75 * inch, 0.4 * inch, f"Page {page_num}")
    canvas.drawRightString(
        LETTER[0] - 0.75 * inch,
        0.4 * inch,
        "AILA Vulnerability Research — confidential",
    )
    canvas.restoreState()
