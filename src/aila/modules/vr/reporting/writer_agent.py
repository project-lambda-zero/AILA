"""Enterprise audit report writer.

Output structure mirrors the industry-standard third-party audit
audit format the security industry expects:

    Introduction
    Audit Summary
    Test Approach
    Risk Methodology     (static 5-point scale)
    Scope                (components audited)
    Assessment Overview  (severity counts + finding table)
    Findings & Tech Details
      [VR-01] TITLE — SEVERITY
        Description
        Risk Level (Likelihood + Impact)
        Proof of Concept     (code block)
        Code Location        (code block + file:line)
        Recommendation       (prose + optional code block)

The writer is an LLM call that takes raw investigation facts (the
same dict ``_collect_facts`` produces) and emits a strict typed
schema. Hard rules enforced by the system prompt:

  - DO NOT invent facts not present in the inputs
  - Use the agent's affected_components verbatim for code locations
  - Each finding maps to one outcome / one variant — never collapse
  - Likelihood + Impact are integer 1-5; severity derives from them
    via the same matrix as the standard 5-point matrix:
        L+I=10  → CRITICAL
        L+I=9-8 → HIGH
        L+I=7-6 → MEDIUM
        L+I=5-4 → LOW
        L+I=3-1 → INFORMATIONAL
"""
from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import BaseModel, Field

from aila.platform.services.factory import ServiceFactory

__all__ = [
    "FindingSection",
    "ReportContent",
    "ReportWriter",
    "ScopeComponent",
]

_log = logging.getLogger(__name__)


# ── Severity matrix (5-point likelihood × impact) ────────────────────────────────


def _severity_from_score(likelihood: int, impact: int) -> str:
    """Map a (likelihood, impact) pair on a 1-5 scale to a severity
    label. Sum of the two values:

        10        → CRITICAL
         8-9      → HIGH
         6-7      → MEDIUM
         4-5      → LOW
         1-3      → INFORMATIONAL
    """
    total = max(2, min(10, likelihood + impact))
    if total >= 10:
        return "CRITICAL"
    if total >= 8:
        return "HIGH"
    if total >= 6:
        return "MEDIUM"
    if total >= 4:
        return "LOW"
    return "INFORMATIONAL"


# ── Schema ──────────────────────────────────────────────────────────


class ScopeComponent(BaseModel):
    """One component / module in the audit scope."""

    name: str = Field(description="Component name (file, module, contract, function).")
    note: str = Field(
        default="",
        description="Optional one-line note on WHY this component is in scope.",
    )


class FindingSection(BaseModel):
    """A single finding in the report, rendered in the standard finding block."""

    id: str = Field(
        description="Short finding id, e.g. 'VR-01', 'VR-02'. Sequentially assigned.",
    )
    title: str = Field(
        description=(
            "Short uppercase title naming the bug class + locus, "
            "e.g. 'MISSING ACCESS CONTROL' or 'INTEGER OVERFLOW IN "
            "PCRE CAPTURE LENGTH PASS'."
        ),
    )
    severity: str = Field(
        description=(
            "One of: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL. "
            "Derive from likelihood + impact via the standard 1-5 "
            "matrix; the writer fills this and the matrix verifies."
        ),
    )
    likelihood: int = Field(ge=1, le=5, description="1-5 risk likelihood.")
    impact: int = Field(ge=1, le=5, description="1-5 risk impact.")
    description: str = Field(
        description=(
            "1-3 paragraphs explaining what the bug is, in technical "
            "terms a senior engineer would read. State the mechanism "
            "(e.g. 'the length pass uses a fresh engine with is_args=0 "
            "while the value pass uses the shared engine with "
            "is_args=1'). No business / executive framing here — that "
            "lives in introduction / audit_summary."
        ),
    )
    proof_of_concept: str = Field(
        default="",
        description=(
            "Code or shell snippet that demonstrates the bug. "
            "Markdown-fenced is fine but not required — renderer "
            "treats it as a monospaced block. Leave empty when no "
            "PoC is available; the renderer will skip the section "
            "rather than show a placeholder."
        ),
    )
    code_location: str = Field(
        description=(
            "Verbatim code excerpt from the audited commit showing "
            "the buggy code. Include filename + line range in a "
            "comment header so the reader can grep for it. Use the "
            "actual function body from the affected_components, not "
            "a rewrite."
        ),
    )
    recommendation: str = Field(
        description=(
            "Concrete fix. Include a corrected code snippet inside "
            "the prose when the fix is small (1-30 lines). For "
            "larger fixes, describe the change + reference where it "
            "lives. Always end with one sentence stating the "
            "principle (e.g. 'Always validate inputs before any "
            "memory operation')."
        ),
    )


class ReportContent(BaseModel):
    """Top-level structured report content.

    Mirrors the standard enterprise audit layout 1:1. Renderer walks these
    fields in fixed order so every report from this writer has the
    same visual structure.
    """

    title: str = Field(description="Short report title — '<Target> Security Audit'.")
    auditor: str = Field(
        default="AILA Vulnerability Research",
        description="Auditor name shown on the cover page.",
    )
    introduction: str = Field(
        description=(
            "1-2 paragraphs. Who commissioned the audit, what the "
            "target is, what the scope of the engagement was. Reads "
            "like the opening of a third-party security report."
        ),
    )
    audit_summary: str = Field(
        description=(
            "2-4 sentences. What the auditor did, time spent, key "
            "outcomes at a high level. Mention the CVE if one was "
            "referenced. Do not preview specific findings — that's "
            "what assessment_overview is for."
        ),
    )
    test_approach: str = Field(
        description=(
            "1-2 paragraphs. Methodology used: source review, "
            "symbol-graph analysis (audit-mcp), binary analysis "
            "(IDA), fuzzing (when applicable), LLM-driven reasoning "
            "with hypothesis tracking. Cite the actual tools the "
            "agent used from the investigation's tool_call_summary."
        ),
    )
    scope: list[ScopeComponent] = Field(
        description=(
            "Concrete list of components audited. Pull from the "
            "investigation's affected_components and from "
            "variants_hunted — every file / module / function the "
            "agent touched belongs here, even if it ended up clean."
        ),
    )
    assessment_overview: str = Field(
        description=(
            "2-3 sentences summarizing the headline numbers (N "
            "findings total, broken down by severity). The renderer "
            "draws the severity-count table automatically from "
            "len(findings); this field is the prose intro to it."
        ),
    )
    findings: list[FindingSection] = Field(
        description=(
            "Every finding produced by the investigation, including "
            "variant-child findings. One FindingSection per bug. "
            "Sorted by severity descending (CRITICAL first). Empty "
            "list when no bugs were confirmed — that's an honest "
            "outcome too."
        ),
    )
    references: list[str] = Field(
        default_factory=list,
        description=(
            "External references — CVE pages, advisory URLs, "
            "research papers, related commits. URLs only."
        ),
    )


# ── Writer ──────────────────────────────────────────────────────────


class ReportWriter:
    """LLM-backed writer producing enterprise audit content.

    Stateless — one instance per call is fine. Underlying LLM is
    the platform's standard chat client with strict-schema mode
    (chat_structured).
    """

    _TASK_TYPE = "vulnerability_research.report_writer"

    def __init__(self, services: ServiceFactory | None = None) -> None:
        self._services = services or ServiceFactory()

    async def write(self, facts: dict[str, Any]) -> ReportContent:
        """Produce a ReportContent from a structured facts dict."""
        response = await self._services.llm_client.chat_structured(
            task_type=self._TASK_TYPE,
            messages=[
                {"role": "system", "content": self._system_prompt()},
                {"role": "user", "content": self._render_facts(facts)},
            ],
            model_class=ReportContent,
        )
        if response.disabled:
            raise RuntimeError("LLM kill-switch active — cannot generate report")
        content = ReportContent.model_validate(json.loads(response.content))
        # Server-side severity normalization — derive label from
        # (likelihood, impact) instead of trusting the LLM's pick.
        # Keeps the matrix consistent across all reports.
        normalized: list[FindingSection] = []
        for f in content.findings:
            f.severity = _severity_from_score(f.likelihood, f.impact)
            normalized.append(f)
        normalized.sort(
            key=lambda f: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}.get(
                    f.severity, 9,
                ),
                f.id,
            ),
        )
        content.findings = normalized
        return content

    @staticmethod
    def _system_prompt() -> str:
        return (
            "You are a senior security report writer producing a "
            "industry-standard third-party audit style audit "
            "report. Output is a strict JSON object matching the "
            "ReportContent schema. No prose outside the JSON.\n\n"
            "Structure discipline:\n"
            "- Each finding is its own FindingSection with id "
            "(VR-01, VR-02, ...), uppercase title, severity, "
            "likelihood + impact (1-5 each), description, optional "
            "proof_of_concept, code_location, and recommendation.\n"
            "- Sort findings by severity descending. Do not group "
            "or collapse findings; each variant child is a separate "
            "FindingSection.\n"
            "- code_location must be VERBATIM code from the "
            "affected_components / vulnerable_code_excerpts the "
            "agent already pulled. Do not rewrite. Include a "
            "comment line at the top of the snippet with the file "
            "path and line range.\n"
            "- proof_of_concept is a small runnable snippet (test "
            "function, curl command, Python script). When the agent "
            "supplied a PoC in poc_drafts, USE IT. When no PoC was "
            "supplied, leave proof_of_concept empty — the renderer "
            "will skip the section.\n"
            "- recommendation includes a corrected code snippet "
            "inline when the fix is small. End each recommendation "
            "with one sentence stating the underlying principle.\n"
            "- likelihood + impact are honest 1-5 scores. Severity "
            "derives from the sum (10=CRITICAL, 8-9=HIGH, "
            "6-7=MEDIUM, 4-5=LOW, 1-3=INFORMATIONAL). The server "
            "re-derives severity from your scores; if you get the "
            "label wrong but the scores right we'll fix it.\n\n"
            "Content discipline:\n"
            "- DO NOT invent functions, files, line numbers, or "
            "behaviour not present in the facts. If a section has "
            "no input, write 'Not established by this investigation' "
            "rather than fabricating.\n"
            "- Introduction + audit_summary stay non-technical "
            "(audit-committee level). Reserve all jargon for the "
            "per-finding sections.\n"
            "- test_approach must cite the actual tools used "
            "(audit-mcp, IDA, fuzzing, LLM reasoning) per the "
            "investigation's tool_call_summary.\n"
            "- Pull every confirmed finding into the findings "
            "list — primary + every variant_hunt child finding. "
            "Empty findings list is fine when nothing was confirmed."
        )

    @staticmethod
    def _render_facts(facts: dict[str, Any]) -> str:
        """Render the facts dict into the writer's user prompt.

        Sections are clearly labelled so the writer can map them
        onto the output schema without guessing.
        """
        out: list[str] = ["# Investigation facts\n"]
        out.append(f"Title: {facts.get('investigation_title') or '(untitled)'}")
        if facts.get("cve_id"):
            out.append(f"CVE: {facts['cve_id']}")
        out.append(f"Target kind: {facts.get('target_kind') or 'unknown'}")
        out.append(f"Target name: {facts.get('target_display') or '(unknown)'}")
        if facts.get("target_repo"):
            out.append(f"Target repo: {facts['target_repo']}")
        if facts.get("target_ref"):
            out.append(f"Target ref: {facts['target_ref']}")
        out.append(f"Final confidence: {facts.get('confidence') or 'unknown'}")
        out.append("")

        meta = facts.get("audit_metadata") or {}
        if meta.get("commit_hash"):
            out.append("# Audit pinning")
            out.append(f"Audited commit: {meta['commit_hash']}")
            if meta.get("git_describe"):
                out.append(f"Version (describe): {meta['git_describe']}")
            if meta.get("commit_date"):
                out.append(f"Commit date: {meta['commit_date']}")
            tags = meta.get("tags_containing") or []
            if tags:
                out.append(f"Tags containing this commit: {', '.join(tags[:10])}")
            if meta.get("audit_duration_seconds") is not None:
                out.append(f"Audit duration: {meta['audit_duration_seconds']}s")
            out.append("")

        cve_intel = facts.get("cve_intel") or []
        if cve_intel:
            out.append("# External CVE intel")
            for entry in cve_intel:
                if not isinstance(entry, dict):
                    continue
                out.append(f"- CVE: {entry.get('cve_id', '?')}")
                if entry.get("description"):
                    out.append(f"  Description: {entry['description'][:600]}")
                if entry.get("cvss_score"):
                    out.append(f"  CVSS: {entry.get('cvss_score')} ({entry.get('base_severity', '?')})")
                if entry.get("kev_listed"):
                    out.append("  KEV: listed (actively exploited per CISA)")
                if entry.get("nvd_url"):
                    out.append(f"  NVD: {entry['nvd_url']}")
            out.append("")

        excerpts = facts.get("vulnerable_code_excerpts") or []
        if excerpts:
            out.append("# Vulnerable code excerpts (verbatim from audit-mcp)")
            for ex in excerpts:
                if not isinstance(ex, dict):
                    continue
                out.append(
                    f"\n## {ex.get('function', '?')} "
                    f"@ {ex.get('file', '?')}:{ex.get('start_line', '?')}"
                    f"-{ex.get('end_line', '?')}",
                )
                out.append(f"```{ex.get('language', 'text')}")
                out.append(ex.get("code", "")[:4000])
                out.append("```")
            out.append("")

        hypotheses = facts.get("hypotheses") or []
        if hypotheses:
            out.append("# Active hypotheses at end of investigation")
            for h in hypotheses:
                if not isinstance(h, dict):
                    continue
                out.append(f"- [{h.get('id', '?')}] {h.get('claim', '')}")
                if h.get("why_plausible"):
                    out.append(f"  Why: {h['why_plausible']}")
                if h.get("kill_criterion"):
                    out.append(f"  Kill criterion: {h['kill_criterion']}")
            out.append("")

        rejected = facts.get("rejected_hypotheses") or []
        if rejected:
            out.append("# Rejected hypotheses (audit trail)")
            for r in rejected:
                if not isinstance(r, dict):
                    continue
                out.append(f"- [{r.get('id', '?')}] {r.get('claim', '')[:120]}")
                out.append(f"  Reason: {r.get('reason', '')[:200]}")
            out.append("")

        insights = facts.get("key_insights") or []
        if insights:
            out.append("# Key insights captured during the investigation")
            for ins in insights:
                out.append(f"- {ins}")
            out.append("")

        tool_calls = facts.get("tool_call_summary") or []
        if tool_calls:
            out.append("# Tool call trail (evidence chain)")
            for line in tool_calls[:50]:
                out.append(f"- {line}")
            if len(tool_calls) > 50:
                out.append(f"  ... and {len(tool_calls) - 50} more calls")
            out.append("")

        outcome_trail = facts.get("outcome_trail") or []
        if outcome_trail:
            # Group by normalized prose prefix so the writer can see
            # "N submissions of the same root cause" vs "N distinct
            # bugs". Bucketing key: first 240 chars of the answer with
            # whitespace collapsed and casefolded — enough to distinguish
            # genuinely different findings but tolerant of re-wording.
            import re as _re  # noqa: PLC0415
            def _bucket(text: str) -> str:
                return _re.sub(r"\s+", " ", (text or "")[:240]).casefold().strip()
            buckets: dict[str, int] = {}
            for o in outcome_trail:
                if isinstance(o, dict):
                    buckets[_bucket(o.get("answer") or "")] = buckets.get(_bucket(o.get("answer") or ""), 0) + 1
            unique = sum(1 for c in buckets.values() if c)
            duplicated = sum(c for c in buckets.values() if c > 1)
            out.append("# Outcome submission trail")
            out.append(
                f"Total submissions: {len(outcome_trail)} | "
                f"Unique root-cause clusters: {unique} | "
                f"Re-confirmations of same cluster: {duplicated}",
            )
            out.append(
                "If the same cluster appears N times, the agent was re-asked "
                "the same question N times and re-derived the same conclusion — "
                "this is high-confidence reproducibility, not N separate bugs. "
                "Emit ONE FindingSection per cluster, and mention reproducibility "
                "in audit_summary.",
            )
            out.append("")
            for i, o in enumerate(outcome_trail, 1):
                if not isinstance(o, dict):
                    continue
                out.append(
                    f"## Submission [{i}/{len(outcome_trail)}] — "
                    f"{(o.get('created_at') or '')[:19]} "
                    f"({o.get('kind', '?')}, conf={o.get('confidence', '?')})",
                )
                out.append((o.get("answer") or "")[:6000])
                out.append("")
            out.append("")

        variants = facts.get("variants_hunted") or []
        if variants:
            out.append("# Variant investigations spawned")
            for v in variants:
                if not isinstance(v, dict):
                    continue
                out.append(f"## Variant: {v.get('title', '?')} (status={v.get('status', '?')})")
                if v.get("question"):
                    out.append(f"Question: {v['question']}")
                if v.get("terminal_answer"):
                    out.append(f"Answer: {v['terminal_answer']}")
                for f in v.get("findings") or []:
                    if not isinstance(f, dict):
                        continue
                    out.append(
                        f"- Finding: {f.get('crash_type', '?')} in "
                        f"`{f.get('vulnerable_function', '?')}`",
                    )
                    if f.get("root_cause"):
                        out.append(f"  Root cause: {f['root_cause']}")
                    if f.get("poc_code"):
                        out.append(f"  PoC available: {f.get('poc_language', '?')} ({len(f['poc_code'])} chars)")
            out.append("")

        pocs = facts.get("poc_drafts") or []
        if pocs:
            out.append("# PoC drafts attached to this investigation")
            for p in pocs:
                if not isinstance(p, dict):
                    continue
                runnable = "RUNNABLE" if p.get("can_run") else "SKELETON"
                out.append(f"## {p.get('title', '(untitled)')} [{runnable}] ({p.get('language', '?')})")
                if p.get("expected_outcome"):
                    out.append(f"Expected: {p['expected_outcome']}")
                if p.get("build_command"):
                    out.append(f"Build: {p['build_command']}")
                if p.get("run_command"):
                    out.append(f"Run: {p['run_command']}")
                if p.get("code"):
                    out.append("```" + str(p.get("language") or ""))
                    out.append(p["code"][:4000])
                    out.append("```")
            out.append("")

        if facts.get("final_answer"):
            out.append("# Final submitted answer (authoritative)")
            out.append(str(facts["final_answer"]))
            out.append("")

        if facts.get("final_reasoning"):
            out.append("# Final reasoning chain")
            out.append(str(facts["final_reasoning"])[:8000])
            out.append("")

        out.append(
            "# Instruction\n\n"
            "Produce a ReportContent JSON object per the schema. "
            "Follow the standard audit-report structure exactly: one "
            "FindingSection per confirmed bug, sorted by severity "
            "descending, each with id (VR-NN), uppercase title, "
            "L+I scores, description, code_location (verbatim), "
            "proof_of_concept (when supplied), and recommendation. "
            "Do not fabricate findings, file paths, or behaviour."
        )
        return "\n".join(out)
