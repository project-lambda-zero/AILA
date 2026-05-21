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
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    XPreformatted,
)
from sqlmodel import func as _sa_func
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
        # Synthesis-aware terminal pick: when the multi-persona panel
        # ran, the SynthesisAgent sets ``inv.primary_outcome_id`` on the
        # consolidated verdict outcome. That IS the headline finding —
        # use it. Fall back to the latest outcome only when synthesis
        # didn't run (single-branch investigations or pre-panel data).
        terminal = None
        if inv.primary_outcome_id:
            terminal = next(
                (o for o in outcomes if o.id == inv.primary_outcome_id),
                None,
            )
        if terminal is None and outcomes:
            terminal = outcomes[-1]

        # Build a per-persona panel snapshot for the Deliberation Panel
        # section. Each entry pairs a sibling branch's persona with its
        # latest terminal outcome. Empty list when not a panel run.
        panel_branches = (await uow.session.exec(
            _select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.investigation_id == investigation_id)
            .order_by(VRInvestigationBranchRecord.created_at.asc()),
        )).all()
        panel_verdicts: list[dict[str, Any]] = []
        for pb in panel_branches:
            if not pb.persona_voice:
                continue
            pb_terminal = next(
                (
                    o for o in reversed(outcomes)
                    if o.branch_id == pb.id and o.id != (inv.primary_outcome_id or "")
                ),
                None,
            )
            if pb_terminal is None:
                continue
            try:
                pb_payload = json.loads(pb_terminal.payload_json or "{}")
            except (ValueError, TypeError):
                pb_payload = {}
            panel_verdicts.append({
                "branch_id": pb.id,
                "persona_voice": pb.persona_voice,
                "turn_count": pb.turn_count,
                "outcome_id": pb_terminal.id,
                "outcome_kind": pb_terminal.outcome_kind,
                "confidence": pb_terminal.confidence,
                "answer": (pb_payload.get("answer") or "")[:3000],
                "affected_components_count": len(pb_payload.get("affected_components") or []),
                "variant_hunt_orders_count": len(pb_payload.get("variant_hunt_orders") or []),
            })

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
        msg_count_row = (await uow.session.exec(
            _select(_sa_func.count())
            .select_from(VRInvestigationMessageRecord)
            .where(VRInvestigationMessageRecord.investigation_id == investigation_id)
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
            "answer": (p.get("answer") or ""),
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
        "panel_verdicts": panel_verdicts,
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
    # ACTIVE duration: sum of completed task-run intervals from
    # taskrecord (heartbeat - started). The wall-clock delta
    # between inv.created_at and inv.updated_at spans every idle
    # hour between re-enqueues which is misleading — the user
    # wants "how long was the agent actually working".
    duration_seconds = _sum_active_task_runtime(inv.id)

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


def _sum_active_task_runtime(investigation_id: str) -> int | None:
    """Return total seconds the agent was actively working —
    sum of (completed_at - started_at) (or heartbeat - started)
    across every taskrecord row whose kwargs reference this
    investigation.

    The wall-clock ``inv.updated_at - inv.created_at`` measure
    includes every idle hour between re-enqueues, which inflates
    the duration to days for an investigation that was only
    actively running for ~30min. This helper sums only the
    intervals where a worker was actually executing the task.

    Best-effort: returns ``None`` when the taskrecord table can't
    be read (so the report still renders without the field).
    """
    try:
        from urllib.parse import urlparse  # noqa: PLC0415

        import psycopg  # noqa: PLC0415

        from aila.config import get_settings  # noqa: PLC0415

        url = get_settings().database_url.replace("postgresql+asyncpg://", "postgresql://")
        parsed = urlparse(url)
        with psycopg.connect(
            host=parsed.hostname,
            port=parsed.port or 5432,
            user=parsed.username,
            password=parsed.password,
            dbname=(parsed.path or "/").lstrip("/"),
        ) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT COALESCE(SUM(EXTRACT(EPOCH FROM "
                "(COALESCE(completed_at, heartbeat_at) - started_at))), 0) "
                "FROM taskrecord "
                "WHERE started_at IS NOT NULL "
                "AND kwargs_json::text LIKE %s",
                (f"%{investigation_id}%",),
            )
            row = cur.fetchone()
            secs = int(row[0]) if row and row[0] else 0
            return secs if secs > 0 else None
    except (OSError, ValueError, RuntimeError, ImportError):
        return None


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


# ── Font registration ──────────────────────────────────────────────
#
# Tahoma for body / headings (clean, no serifs, ships everywhere)
# and a developer-grade mono (Cascadia Mono → Consolas → Courier)
# for code blocks — fits the security-research / editor aesthetic.
# Registration is best-effort: missing font files fall through to
# the next candidate and ultimately to ReportLab's built-in
# Helvetica / Courier so the report still renders on any host.

_FONT_BODY: str = "Helvetica"
_FONT_BODY_BOLD: str = "Helvetica-Bold"
_FONT_MONO: str = "Courier"


def _register_theme_fonts() -> None:
    """Walk known Windows + Linux font paths, register the first
    match per role, and update the module-level font aliases.
    """
    global _FONT_BODY, _FONT_BODY_BOLD, _FONT_MONO

    body_candidates = [
        ("Tahoma", "Tahoma-Bold",
         r"C:\Windows\Fonts\tahoma.ttf",
         r"C:\Windows\Fonts\tahomabd.ttf"),
        ("Tahoma", "Tahoma-Bold",
         "/usr/share/fonts/truetype/msttcorefonts/tahoma.ttf",
         "/usr/share/fonts/truetype/msttcorefonts/tahomabd.ttf"),
    ]
    mono_candidates = [
        ("CascadiaMono", r"C:\Windows\Fonts\CascadiaMono.ttf"),
        ("CascadiaCode", r"C:\Windows\Fonts\CascadiaCode.ttf"),
        ("Consolas",     r"C:\Windows\Fonts\consola.ttf"),
        ("JetBrainsMono",
         "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf"),
        ("FiraCode",
         "/usr/share/fonts/truetype/firacode/FiraCode-Regular.ttf"),
    ]

    for reg, bold, reg_path, bold_path in body_candidates:
        if os.path.isfile(reg_path):
            try:
                pdfmetrics.registerFont(TTFont(reg, reg_path))
                _FONT_BODY = reg
                if os.path.isfile(bold_path):
                    pdfmetrics.registerFont(TTFont(bold, bold_path))
                    _FONT_BODY_BOLD = bold
                else:
                    _FONT_BODY_BOLD = reg
                break
            except (OSError, RuntimeError):
                continue

    for name, path in mono_candidates:
        if os.path.isfile(path):
            try:
                pdfmetrics.registerFont(TTFont(name, path))
                _FONT_MONO = name
                break
            except (OSError, RuntimeError):
                continue


_register_theme_fonts()


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
        fontName=_FONT_BODY_BOLD,
        textColor=_FG_HEADING,
        spaceAfter=24,
    )
    styles["cover_subtitle"] = ParagraphStyle(
        "CoverSubtitle",
        parent=base["Title"],
        fontSize=16,
        leading=20,
        alignment=TA_CENTER,
        fontName=_FONT_BODY,
        textColor=_FG_SUBHEAD,
        spaceAfter=12,
    )
    styles["section_h1"] = ParagraphStyle(
        "SectionH1",
        parent=base["Heading1"],
        fontSize=18,
        leading=22,
        textColor=_FG_HEADING,
        fontName=_FONT_BODY_BOLD,
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
        leading=18,
        textColor=_FG_SUBHEAD,
        fontName=_FONT_BODY_BOLD,
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=1,
    )
    styles["body"] = ParagraphStyle(
        "Body",
        parent=base["BodyText"],
        fontSize=10.5,
        leading=15,
        textColor=_FG_TEXT,
        fontName=_FONT_BODY,
        alignment=TA_LEFT,
        spaceAfter=6,
    )
    styles["mono"] = ParagraphStyle(
        "Mono",
        parent=base["Code"],
        fontName=_FONT_MONO,
        fontSize=9,
        leading=12,
        textColor=_FG_TEXT,
        backColor=_BG_SURFACE,
        borderColor=_BG_BORDER,
        borderWidth=0,
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
        fontName=_FONT_BODY,
        spaceAfter=2,
    )
    return styles



# ── Pygments syntax highlighting → ReportLab Paragraph ──────────────

try:
    from pygments import lex as _pyg_lex
    from pygments.lexers import get_lexer_by_name as _pyg_get_lexer
    from pygments.token import Token as _PygToken
    from pygments.util import ClassNotFound as _PygClassNotFound
    _PYGMENTS_AVAILABLE = True
except ImportError:
    _PYGMENTS_AVAILABLE = False

_PYG_COLOR_MAP: dict[Any, str] = {}
if _PYGMENTS_AVAILABLE:
    _PYG_COLOR_MAP = {
        _PygToken.Keyword:                 "#ff5f87",
        _PygToken.Keyword.Constant:        "#b092ff",
        _PygToken.Keyword.Declaration:     "#ff5f87",
        _PygToken.Keyword.Namespace:       "#d7afd7",
        _PygToken.Keyword.Type:            "#f0a8c7",
        _PygToken.Name.Builtin:            "#f0a8c7",
        _PygToken.Name.Class:              "#f0a8c7",
        _PygToken.Name.Function:           "#97dbbe",
        _PygToken.Name.Decorator:          "#d7afd7",
        _PygToken.Name.Namespace:          "#d7afd7",
        _PygToken.Name.Tag:                "#ff5f87",
        _PygToken.Name.Attribute:          "#97dbbe",
        _PygToken.Literal.String:          "#97dbbe",
        _PygToken.Literal.String.Doc:      "#808080",
        _PygToken.Literal.String.Escape:   "#b092ff",
        _PygToken.Literal.Number:          "#b092ff",
        _PygToken.Literal:                 "#b092ff",
        _PygToken.Operator:                "#d7afd7",
        _PygToken.Operator.Word:           "#ff5f87",
        _PygToken.Punctuation:             "#ffd7af",
        _PygToken.Comment:                 "#808080",
        _PygToken.Comment.Single:          "#808080",
        _PygToken.Comment.Multiline:       "#808080",
        _PygToken.Comment.Preproc:         "#d7afd7",
    }


_MD_FENCE_RE = re.compile(r"^\s*```([\w+\-]*)\s*\n(.*?)\n\s*```\s*$", re.DOTALL)


def _strip_md_fence(text: str) -> tuple[str, str]:
    """If ``text`` is a single markdown fenced block, return (inner, language).

    Returns (text, "") when there's no fence — caller falls back to
    heuristic language detection. Tolerates leading/trailing whitespace
    around the fence markers.
    """
    if not text:
        return text, ""
    m = _MD_FENCE_RE.match(text.strip())
    if m:
        return m.group(2), m.group(1) or ""
    return text, ""


def _append_section_h1(story: list[Any], title: str, styles: dict[str, ParagraphStyle]) -> None:
    """Append a section h1 heading plus a thin accent rule.

    Mirrors the OZ/CS audit-report convention of headings with a
    horizontal accent line extending to the right margin — gives
    the eye a strong section break instead of floating colored text.
    """
    story.append(Paragraph(title, styles["section_h1"]))
    story.append(HRFlowable(
        width="100%",
        thickness=0.6,
        color=_FG_HEADING,
        spaceBefore=0,
        spaceAfter=6,
        lineCap="square",
    ))


def _format_code_block(
    code: str,
    language: str,
    styles: dict[str, ParagraphStyle],
) -> Any:
    """Render ``code`` as a syntax-highlighted code block in the dark
    Midnight Cloud palette.

    Uses XPreformatted (not Paragraph) so indentation, alignment,
    and runs of spaces are preserved verbatim — Paragraph collapses
    whitespace and breaks Python / shell layouts. Falls back to plain
    mono XPreformatted when pygments is missing or the language has
    no lexer.
    """
    if not code.strip():
        return XPreformatted("", styles["mono"])
    if not _PYGMENTS_AVAILABLE:
        return XPreformatted(_escape_for_paragraph(code), styles["mono"])
    try:
        lexer = _pyg_get_lexer(language or "text")
    except _PygClassNotFound:
        try:
            lexer = _pyg_get_lexer("text")
        except _PygClassNotFound:
            return XPreformatted(_escape_for_paragraph(code), styles["mono"])
    parts: list[str] = []
    for ttype, value in _pyg_lex(code, lexer):
        if not value:
            continue
        cur = ttype
        color = None
        while cur is not None:
            if cur in _PYG_COLOR_MAP:
                color = _PYG_COLOR_MAP[cur]
                break
            cur = cur.parent
        # XPreformatted keeps newlines verbatim, do NOT convert to <br/>.
        escaped = _escape_for_paragraph(value)
        parts.append(f'<font color="{color}">{escaped}</font>' if color else escaped)
    return XPreformatted("".join(parts), styles["mono"])


def _guess_lang_from_snippet(snippet: str) -> str:
    """Heuristic language guess for a code snippet that doesn't
    carry an explicit language tag. Looks at the first 400 chars
    for distinctive tokens. Defaults to ``text`` which gets a
    plain mono render with no highlighting.
    """
    head = snippet[:400].lower()
    # Python: shebang anywhere in head, import statement, or def/class
    if (
        "#!/usr/bin/env python" in head
        or "#!/usr/bin/python" in head
        or "#!python" in head
        or re.search(r"^(import |from \w+ import )", head, re.MULTILINE)
        or (("def " in head or "class " in head) and ":" in head)
    ):
        return "python"
    if "static ngx_" in head or "u_char" in head or "ngx_int_t" in head:
        return "c"
    if "fn " in head and "->" in head:
        return "rust"
    if "func " in head and "package " in head:
        return "go"
    if "function " in head and "{" in head:
        return "javascript"
    if "#include" in head or "void " in head or "int main" in head:
        return "c"
    if "#!/bin/bash" in head or "#!/bin/sh" in head:
        return "bash"
    return "text"

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
    # Custom doc template so we can paint the dark page background
    # BEFORE the content draws. SimpleDocTemplate's onFirstPage /
    # onLaterPages fire AFTER the frame, so painting bg there
    # covered all the text (manifested as "broken" pages with
    # ripped flowables). _DarkPageTemplate.beforeDrawPage paints
    # the rect first; _draw_footer keeps running as the
    # afterDrawPage hook for the page number + branding strip.
    margin = 0.75 * inch
    frame = Frame(
        margin, margin,
        LETTER[0] - 2 * margin, LETTER[1] - 2 * margin,
        id="body",
        leftPadding=0, rightPadding=0,
        topPadding=12, bottomPadding=6,
    )

    class _DarkPage(PageTemplate):
        def beforeDrawPage(self, canvas: Any, doc: Any) -> None:  # noqa: N802
            del doc
            canvas.saveState()
            canvas.setFillColor(_BG_PAGE)
            canvas.rect(0, 0, LETTER[0], LETTER[1], stroke=0, fill=1)
            canvas.restoreState()

    doc = BaseDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=margin,
        rightMargin=margin,
        topMargin=margin,
        bottomMargin=margin,
        title=content.title,
        author=content.auditor,
        subject=facts.get("cve_id") or "Vulnerability report",
    )
    doc.addPageTemplates([
        _DarkPage(id="dark", frames=[frame], onPage=_draw_footer),
    ])
    styles = _build_styles()
    story: list[Any] = []

    # ── Cover page ────────────────────────────────────────────────
    story.append(Spacer(1, 0.6 * inch))
    _cover_title = re.sub(r"\s*\(CVE-\d{4}-\d{4,7}\)\s*$", "", content.title) if facts.get("cve_id") else content.title
    story.append(Paragraph(_escape_for_paragraph(_cover_title), styles["cover_title"]))
    if facts.get("cve_id"):
        story.append(Paragraph(facts["cve_id"], styles["cover_subtitle"]))
    story.append(Paragraph(content.auditor, styles["cover_subtitle"]))
    story.append(Spacer(1, 0.3 * inch))

    # Dominant severity callout — pick the highest severity among
    # findings (CRITICAL > HIGH > ... > INFORMATIONAL). When there
    # are no findings, render an INFORMATIONAL badge with the
    # "no confirmed bugs" copy.
    dominant = _dominant_severity(content.findings)
    sev_color = _SEVERITY_COLOR.get(dominant, colors.HexColor("#aac8e0"))
    sev_table = Table(
        [[Paragraph(
            f"<para alignment='center' leading='28'>"
            f"<font color='#121212' size='10'><b>OVERALL RISK</b></font><br/>"
            f"<font color='#121212' size='22'><b>{dominant}</b></font>"
            f"</para>",
            styles["body"],
        )]],
        colWidths=[3.2 * inch],
    )
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), sev_color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
    ]))
    sev_table.hAlign = "CENTER"
    story.append(sev_table)
    story.append(Spacer(1, 0.15 * inch))

    _append_cover_meta_table(story, facts, styles)

    story.append(Spacer(1, 0.15 * inch))
    story.append(PageBreak())

    # ── Introduction ─────────────────────────────────────────────
    _append_section_h1(story, "Introduction", styles)
    _render_markdown_body(content.introduction, styles, story)
    story.append(Spacer(1, 0.15 * inch))

    # ── Audit Summary ────────────────────────────────────────────
    _append_section_h1(story, "Audit Summary", styles)
    _render_markdown_body(content.audit_summary, styles, story)
    story.append(Spacer(1, 0.15 * inch))

    # ── Test Approach ────────────────────────────────────────────
    _append_section_h1(story, "Test Approach", styles)
    _render_markdown_body(content.test_approach, styles, story)
    story.append(Spacer(1, 0.15 * inch))

    # ── Submission Timeline (collapse duplicates by root-cause cluster) ──
    outcome_trail = facts.get("outcome_trail") or []
    if len(outcome_trail) > 1:
        # Bucket outcomes by a normalized 240-char prose prefix.
        # Two outcomes that re-derive the same root cause in slightly
        # different wording land in the same bucket. Show ONE row per
        # bucket — repeating 6 near-identical rows is worse than no
        # timeline at all.
        def _bucket_key(text: str) -> str:
            return re.sub(r"\s+", " ", (text or "")[:240]).casefold().strip()
        buckets: dict[str, list[dict[str, Any]]] = {}
        for o in outcome_trail:
            if not isinstance(o, dict):
                continue
            buckets.setdefault(_bucket_key(o.get("answer") or ""), []).append(o)
        unique_count = len(buckets)
        total = len(outcome_trail)
        _append_section_h1(story, "Submission Timeline", styles)
        if unique_count == 1:
            (only_bucket,) = buckets.values()
            first = only_bucket[0]
            extras = len(only_bucket) - 1
            ts_list = ", ".join((o.get("created_at") or "")[:19].replace("T", " ") for o in only_bucket)
            story.append(Paragraph(
                f"The agent submitted <b>{total}</b> terminal outcomes during the audit, "
                f"all resolving to the <b>same root-cause cluster</b>. Re-derivations like "
                f"this indicate strong reproducibility, not separate findings.",
                styles["body"],
            ))
            story.append(Spacer(1, 0.08 * inch))
            story.append(Paragraph(
                f"<b>First submission:</b> {_escape_for_paragraph((first.get('created_at') or '')[:19].replace('T', ' '))} "
                f"({_escape_for_paragraph(first.get('kind') or '?')}, conf={_escape_for_paragraph(str(first.get('confidence') or '?'))})<br/>"
                f"<b>Re-confirmations:</b> {extras}<br/>"
                f"<b>All submission timestamps:</b> {_escape_for_paragraph(ts_list)}",
                styles["body"],
            ))
        else:
            story.append(Paragraph(
                f"The agent submitted <b>{total}</b> terminal outcomes across <b>{unique_count}</b> "
                f"distinct root-cause clusters. Each row below is one cluster with its "
                f"first-seen timestamp and re-confirmation count.",
                styles["body"],
            ))
            story.append(Spacer(1, 0.08 * inch))
            timeline_rows: list[list[Any]] = [[
                Paragraph("<font color='#97dbbe'><b>#</b></font>", styles["body"]),
                Paragraph("<font color='#97dbbe'><b>FIRST SEEN</b></font>", styles["body"]),
                Paragraph("<font color='#97dbbe'><b>RE-CONF</b></font>", styles["body"]),
                Paragraph("<font color='#97dbbe'><b>EXCERPT</b></font>", styles["body"]),
            ]]
            for i, (_, group) in enumerate(buckets.items(), 1):
                first = group[0]
                ts = (first.get("created_at") or "")[:19].replace("T", " ")
                excerpt = (first.get("answer") or "").strip().splitlines()[0][:180] if first.get("answer") else "(empty)"
                timeline_rows.append([
                    Paragraph(str(i), styles["body"]),
                    Paragraph(_escape_for_paragraph(ts), styles["mono"]),
                    Paragraph(str(len(group) - 1), styles["body"]),
                    Paragraph(_escape_for_paragraph(excerpt), styles["body"]),
                ])
            tl_table = Table(
                timeline_rows,
                colWidths=[0.3 * inch, 1.5 * inch, 0.9 * inch, 3.9 * inch],
            )
            tl_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), _BG_SURFACE),
                ("GRID", (0, 0), (-1, -1), 0.4, _BG_BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(tl_table)
        story.append(Spacer(1, 0.15 * inch))

    # ── Risk Methodology (static block) ──────────────────────────


    methodology_flow: list[Any] = [
        Paragraph("Risk Methodology", styles["section_h1"]),
        Paragraph(
            "Findings are scored on a 5-point likelihood × impact "
            "matrix. Likelihood (L) measures how plausible an incident "
            "is, impact (I) measures the damage one would cause. The "
            "sum L+I drives the severity label:",
            styles["body"],
        ),
        Paragraph(
            "&bull;&nbsp; <b>10</b> &mdash; CRITICAL<br/>"
            "&bull;&nbsp; <b>8&ndash;9</b> &mdash; HIGH<br/>"
            "&bull;&nbsp; <b>6&ndash;7</b> &mdash; MEDIUM<br/>"
            "&bull;&nbsp; <b>4&ndash;5</b> &mdash; LOW<br/>"
            "&bull;&nbsp; <b>1&ndash;3</b> &mdash; INFORMATIONAL",
            styles["body"],
        ),
    ]
    story.append(KeepTogether(methodology_flow))
    story.append(Spacer(1, 0.15 * inch))

    # ── Scope ────────────────────────────────────────────────────
    _append_section_h1(story, "Scope", styles)
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
    _append_section_h1(story, "Assessment Summary &amp; Findings Overview", styles)
    _render_markdown_body(content.assessment_overview, styles, story)
    story.append(Spacer(1, 0.1 * inch))
    _append_severity_count_table(story, content.findings, styles)
    story.append(Spacer(1, 0.15 * inch))
    if content.findings:
        _append_findings_index_table(story, content.findings, styles)

    # ── Findings & Tech Details ──────────────────────────────────
    if content.findings:
        story.append(PageBreak())
        _append_section_h1(story, "Findings &amp; Tech Details", styles)
        for finding in content.findings:
            _append_finding_block(story, finding, styles)

    # ── References ───────────────────────────────────────────────
    if content.references:
        story.append(Spacer(1, 0.25 * inch))
        _append_section_h1(story, "References", styles)
        for ref in content.references:
            story.append(Paragraph(
                f"&bull;&nbsp; <font color='#7a6f9e'>"
                f"{_escape_for_paragraph(ref)}</font>",
                styles["body"],
            ))

    doc.build(story)
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
    # Compact audit window: one row "2026-05-19 08:54 → 09:12 UTC (6m 54s)"
    # instead of three separate rows.
    started = (meta.get("audit_started_at") or "")[:16].replace("T", " ")
    completed = (meta.get("audit_completed_at") or "")[:16].replace("T", " ")
    duration_secs = meta.get("audit_duration_seconds")
    if started or completed:
        if duration_secs is not None:
            if duration_secs >= 60:
                dur_str = f"{duration_secs // 60}m {duration_secs % 60}s"
            else:
                dur_str = f"{duration_secs}s"
        else:
            dur_str = ""
        window = f"{started or '?'} → {completed or '?'} UTC"
        if dur_str:
            window += f"  ({dur_str})"
        cover_meta.append(["Audit window", window])
    cover_meta.append([
        "Report generated",
        datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC"),
    ])
    cover_meta.append(["Investigation id", facts.get("investigation_id", "?")])
    cover_meta.append([
        "Reasoning turns",
        f"{facts.get('branch_turn_count', 0)} (over {facts.get('message_count', 0)} total messages)",
    ])

    body_style = styles["body"]
    cover_meta = [
        [Paragraph(f"<font color='#808080'>{_escape_for_paragraph(k)}</font>", body_style),
         Paragraph(_escape_for_paragraph(v), body_style)]
        for k, v in cover_meta
    ]
    meta_table = Table(cover_meta, colWidths=[1.5 * inch, 4.7 * inch])
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
        f"<font color='#121212' size='9'><b>{label if len(label) <= 8 else 'INFO.'}</b></font>",
        _build_styles()["body"],
    ) for label in _SEVERITY_ORDER]
    body = [Paragraph(
        f"<font color='#ffd7af'><b><font size='16'>{counts[label]}</font></b></font>",
        _build_styles()["body"],
    ) for label in _SEVERITY_ORDER]

    table = Table([header, body], colWidths=[1.2 * inch] * len(_SEVERITY_ORDER))
    style_cmds: list[tuple[Any, ...]] = [
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 1), (-1, 1), _BG_SURFACE),
        ("BOX", (0, 0), (-1, -1), 0.5, _BG_BORDER),
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
        Paragraph("<font color='#97dbbe'><b>SECURITY ANALYSIS</b></font>", styles["body"]),
        Paragraph("<font color='#97dbbe'><b>RISK LEVEL</b></font>", styles["body"]),
        Paragraph("<font color='#97dbbe'><b>RECOMMENDATION</b></font>", styles["body"]),
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
                f"<font color='#121212'><b>{sev}</b></font>",
                styles["body"],
            ),
            Paragraph("FIX AVAILABLE", styles["body"]),
        ])
        # Tint the risk-level cell with the pastel severity color.
        rows[-1][1] = Paragraph(
            f"<b>{sev}</b>",
            ParagraphStyle("sev_cell", parent=styles["body"], textColor=colors.HexColor("#121212")),
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
    story.append(Spacer(1, 0.3 * inch))
    sev = (getattr(finding, "severity", "") or "").upper()
    sev_color = _SEVERITY_COLOR.get(sev, colors.HexColor("#aac8e0"))

    # Finding title bar: severity-tinted background, white-ish title,
    # uppercase severity badge on the right. Replaces the floating
    # section_h1 heading so the eye gets a strong containment cue
    # at the start of each finding.
    title_cell = Paragraph(
        f"<font color='#121212' size='8'><b>{_escape_for_paragraph(finding.id)}</b></font>"
        f"<br/>"
        f"<font color='#121212' size='13'><b>{_escape_for_paragraph(finding.title)}</b></font>",
        styles["body"],
    )
    sev_cell = Paragraph(
        f"<para alignment='center'>"
        f"<font color='#121212' size='8'><b>SEVERITY</b></font><br/>"
        f"<font color='#121212' size='13'><b>{sev}</b></font>"
        f"</para>",
        styles["body"],
    )
    title_table = Table([[title_cell, sev_cell]], colWidths=[5.2 * inch, 1.5 * inch])
    title_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), sev_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LINEAFTER", (0, 0), (0, 0), 0.5, colors.HexColor("#121212")),
    ]))
    story.append(title_table)
    story.append(Spacer(1, 0.12 * inch))

    # Description: route through markdown body so inline `code`
    # spans get monospace fontification and any fenced blocks
    # render with syntax highlighting.
    desc_flow: list[Any] = [Paragraph("DESCRIPTION", styles["section_h2"])]
    desc_buf: list[Any] = []
    _render_markdown_body(finding.description, styles, desc_buf)
    desc_flow.extend(desc_buf[:3])
    story.append(KeepTogether(desc_flow))
    for flow in desc_buf[3:]:
        story.append(flow)

    # Risk Level: horizontal 3-pill row instead of stacked text.
    risk_likelihood = Paragraph(
        f"<para alignment='center'>"
        f"<font color='#808080' size='8'><b>LIKELIHOOD</b></font><br/>"
        f"<font color='#ffd7af' size='18'><b>{finding.likelihood}</b></font>"
        f"<font color='#808080' size='10'> / 5</font>"
        f"</para>",
        styles["body"],
    )
    risk_impact = Paragraph(
        f"<para alignment='center'>"
        f"<font color='#808080' size='8'><b>IMPACT</b></font><br/>"
        f"<font color='#ffd7af' size='18'><b>{finding.impact}</b></font>"
        f"<font color='#808080' size='10'> / 5</font>"
        f"</para>",
        styles["body"],
    )
    risk_total = Paragraph(
        f"<para alignment='center'>"
        f"<font color='#808080' size='8'><b>SEVERITY (L+I={finding.likelihood + finding.impact})</b></font><br/>"
        f"<font color='#121212' size='14'><b>{sev}</b></font>"
        f"</para>",
        styles["body"],
    )
    risk_table = Table(
        [[risk_likelihood, risk_impact, risk_total]],
        colWidths=[2.0 * inch, 2.0 * inch, 2.7 * inch],
    )
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (1, 0), _BG_SURFACE),
        ("BACKGROUND", (2, 0), (2, 0), sev_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LINEAFTER", (0, 0), (1, 0), 0.5, _BG_BORDER),
    ]))
    story.append(KeepTogether([
        Paragraph("RISK LEVEL", styles["section_h2"]),
        risk_table,
    ]))

    if finding.proof_of_concept and finding.proof_of_concept.strip():
        # Writer often emits PoC as Python block + prose + bash invocation
        # block. _render_markdown_body handles the multi-block case;
        # _format_code_block would render the whole payload (fences and
        # all) as one literal text dump.
        poc_heading = Paragraph("Proof of Concept", styles["section_h2"])
        poc_buf: list[Any] = []
        _render_markdown_body(finding.proof_of_concept, styles, poc_buf)
        if poc_buf:
            story.append(KeepTogether([poc_heading, poc_buf[0]]))
            for flow in poc_buf[1:]:
                story.append(flow)
        else:
            story.append(poc_heading)

    # Code Location: writer often emits multiple fenced blocks
    # (fast-path code + value-pass code + slow-path code). Route
    # through _render_markdown_body so each fence renders as its
    # own highlighted block instead of being dumped as one
    # flat code page with literal ``` markers in the text.
    cl_heading = Paragraph("Code Location", styles["section_h2"])
    cl_buf: list[Any] = []
    _render_markdown_body(finding.code_location, styles, cl_buf)
    if cl_buf:
        story.append(KeepTogether([cl_heading, cl_buf[0]]))
        for flow in cl_buf[1:]:
            story.append(flow)
    else:
        story.append(cl_heading)

    story.append(KeepTogether([
        Paragraph("Recommendation", styles["section_h2"]),
    ]))
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
    code_lang = "text"
    code_buffer: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line.strip().startswith("```"):
            if in_code:
                code_text = "\n".join(code_buffer)
                story.append(_format_code_block(code_text, code_lang, styles))
                code_buffer = []
                code_lang = "text"
                in_code = False
            else:
                # capture language hint after the opening fence
                hint = line.strip().lstrip("`").strip()
                code_lang = hint if hint else "text"
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
        story.append(_format_code_block("\n".join(code_buffer), code_lang, styles))


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
        lambda m: f"<font name='Courier' color='#ffd7af'>{m.group(1)}</font>",
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
