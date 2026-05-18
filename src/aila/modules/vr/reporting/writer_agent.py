"""Enterprise vulnerability report writer agent.

Takes raw investigation data (hypotheses, observations, final outcome,
tool trail, CVE intel) and produces structured, polished prose for the
PDF report sections. Modeled after Fortify / Invicti / Veracode report
structure:

    1. Executive summary    — non-technical, 1 paragraph
    2. Severity assessment  — CVSS context + business impact
    3. Technical analysis   — root cause walked at code level
    4. Affected components  — file/function/line locations
    5. Remediation          — concrete fix recommendations
    6. References           — CVE / CWE / advisory links

The writer is a SEPARATE LLM call from the investigation reasoner.
Its job is presentation, not investigation — it does not search,
does not pose new hypotheses, and never invents facts not in its
input. Hallucinations are prevented by:

- Constraining input to facts the investigation actually established
- Structured output schema (pydantic) enforced via chat_structured
- An explicit "DO NOT invent" rule in the prompt
"""
from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field

from aila.platform.services.factory import ServiceFactory

__all__ = [
    "ReportWriter",
    "ReportContent",
    "ReportSection",
]

_log = logging.getLogger(__name__)


class ReportSection(BaseModel):
    """One section of the rendered report."""

    heading: str
    body_markdown: str = Field(
        description=(
            "Prose body, may contain markdown code fences for code "
            "snippets, inline `code` for symbol names, and standard "
            "paragraph/bullet structure."
        ),
    )


class ReportContent(BaseModel):
    """Complete narrative content for the PDF report.

    Sections are produced in a fixed order; renderer maps them onto the
    HTML template slots.
    """

    title: str = Field(description="Short report title, no CVE id (it goes in metadata).")
    severity_label: str = Field(
        description=(
            "One of: 'Critical', 'High', 'Medium', 'Low', 'Informational'."
        ),
    )
    severity_rationale: str = Field(
        description="One sentence explaining why this severity was chosen.",
    )
    executive_summary: str = Field(
        description=(
            "2-4 sentence non-technical summary suitable for an "
            "executive audience. State what was found, where, and "
            "the operational risk. No code, no jargon."
        ),
    )
    technical_summary: str = Field(
        description=(
            "1-2 paragraph technical summary walking through the bug "
            "mechanism. Names the affected functions and the exact "
            "asymmetry / overflow / logic flaw. Reads like a senior "
            "engineer briefing the team."
        ),
    )
    root_cause_analysis: ReportSection = Field(
        description=(
            "Deep technical analysis. Multi-paragraph. Walks the "
            "execution path. Includes code references. Cites the "
            "observed evidence (hypothesis ids, function bodies, "
            "search results) that supports each claim."
        ),
    )
    affected_components: list[str] = Field(
        description=(
            "Bullet list of affected components in 'file:lineno function_name' "
            "format. One entry per identified locus."
        ),
    )
    reproduction_conditions: str = Field(
        description=(
            "Step-by-step preconditions that must hold for the bug "
            "to trigger. Configuration directives, request shape, "
            "build flags, runtime state. No PoC code — just the "
            "conditions."
        ),
    )
    remediation: ReportSection = Field(
        description=(
            "Concrete fix recommendations. Primary fix (code change "
            "sketch) and defense-in-depth options (config workaround, "
            "monitoring, hardening)."
        ),
    )
    variant_surface: str = Field(
        default="",
        description=(
            "Optional. If the investigation enumerated variant call "
            "sites or related code paths worth re-auditing, list them "
            "here with a short rationale each."
        ),
    )
    references: list[str] = Field(
        default_factory=list,
        description=(
            "External references: CVE pages, advisory URLs, related "
            "research. URLs only."
        ),
    )


class ReportWriter:
    """LLM-backed writer that turns raw investigation facts into report prose.

    Construction takes a ServiceFactory (for the LLM client). One
    instance can produce many reports; nothing is stored between
    calls.
    """

    _TASK_TYPE = "vulnerability_research.report_writer"

    def __init__(self, services: ServiceFactory | None = None) -> None:
        self._services = services or ServiceFactory()

    async def write(self, facts: dict[str, Any]) -> ReportContent:
        """Produce a ReportContent from a structured facts dict.

        ``facts`` shape (all keys optional, the writer adapts to what
        it gets):

          - investigation_title: str
          - cve_id: str | None
          - target_kind: str
          - target_display: str
          - target_repo: str | None
          - hypotheses: list[{id, claim, why_plausible, kill_criterion}]
          - rejected_hypotheses: list[{id, claim, reason}]
          - key_insights: list[str]   (observable strings the agent flagged)
          - final_answer: str         (the submit outcome's answer)
          - final_reasoning: str      (the submit outcome's reasoning)
          - confidence: str
          - cve_intel: list[dict]     (NVD-resolved description, CVSS, KEV, etc.)
          - tool_call_summary: list[str]  (one-liner per significant call)

        Returns a validated ReportContent. Raises LLMError on
        unrecoverable LLM failures (caller decides whether to fall
        back to a basic plain-text report or surface the error).
        """
        system_prompt = self._system_prompt()
        user_prompt = self._render_facts(facts)

        response = await self._services.llm_client.chat_structured(
            task_type=self._TASK_TYPE,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            model_class=ReportContent,
        )
        if response.disabled:
            raise RuntimeError(
                "LLM kill-switch active — cannot generate report",
            )
        # chat_structured returns LLMResponse; parse the JSON content
        # back through the model. The retry path inside
        # chat_structured already guarantees the content is valid
        # JSON matching the schema.
        import json as _json  # noqa: PLC0415

        return ReportContent.model_validate(_json.loads(response.content))

    @staticmethod
    def _system_prompt() -> str:
        return (
            "You are a senior security report writer. Your job: convert "
            "raw vulnerability research output into a polished, "
            "enterprise-grade narrative suitable for a Fortify / "
            "Invicti / Veracode-style PDF report.\n\n"
            "Hard rules:\n"
            "- DO NOT invent facts. Only state things present in the "
            "facts provided. If a section has no input, say "
            "'Not established by this investigation' in that section "
            "rather than fabricating content.\n"
            "- DO NOT reframe or soften the severity. If the facts say "
            "'heap buffer overflow with RCE possibility', mirror that.\n"
            "- DO write in active voice, present tense, third person.\n"
            "- DO name specific files / functions / line numbers when "
            "they appear in the facts.\n"
            "- DO write the executive_summary at a non-engineer level "
            "(audit committee, product owner). Reserve jargon for the "
            "technical sections.\n"
            "- DO cite hypotheses by id (h5, h7) when explaining how "
            "the conclusion was reached in root_cause_analysis.\n"
            "- DO include URLs in references when the CVE intel block "
            "supplies them.\n"
            "- When the input has a 'Variant investigations spawned' "
            "section, EACH variant + its findings MUST appear in the "
            "variant_surface output. Name each child variant, its "
            "status, and any confirmed finding inside it. Do not "
            "collapse them into a sentence.\n"
            "- When the input has a 'PoC drafts available' section, "
            "the reproduction_conditions output MUST reference the "
            "PoC (build + run commands, expected outcome, runnable "
            "vs skeleton status). The remediation output should "
            "acknowledge the PoC exists as evidence of exploitability.\n"
            "- When the input has an 'Outcome trail' with multiple "
            "entries, the technical_summary should briefly narrate "
            "the audit progression (hypothesis refinement, key "
            "pivots) instead of summarizing only the final state.\n"
            "- Output MUST be valid JSON matching the ReportContent "
            "schema. No prose outside the JSON object."
        )

    @staticmethod
    def _render_facts(facts: dict[str, Any]) -> str:
        """Render the facts dict into the writer's user prompt.

        Sections are clearly labelled so the writer can map them onto
        the output schema without guessing. Long fields are kept
        intact — the writer needs the full reasoning text to produce
        accurate prose; truncating would force fabrication.
        """
        out: list[str] = []
        out.append("# Investigation facts\n")
        out.append(f"Title: {facts.get('investigation_title') or '(untitled)'}")
        if facts.get("cve_id"):
            out.append(f"CVE: {facts['cve_id']}")
        out.append(f"Target kind: {facts.get('target_kind') or 'unknown'}")
        out.append(f"Target name: {facts.get('target_display') or '(unknown)'}")
        if facts.get("target_repo"):
            out.append(f"Target repo: {facts['target_repo']}")
        out.append(f"Final confidence: {facts.get('confidence') or 'unknown'}")
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
        if len(outcome_trail) > 1:
            out.append("# Outcome trail (every conclusion the agent emitted)")
            for o in outcome_trail:
                if not isinstance(o, dict):
                    continue
                kind = o.get("kind") or "?"
                conf = o.get("confidence") or "?"
                when = (o.get("created_at") or "")[:16]
                snippet = (o.get("answer") or "")[:160]
                out.append(f"- [{when}] {kind} (conf={conf}): {snippet}")
            out.append("")

        variants = facts.get("variants_hunted") or []
        if variants:
            out.append("# Variant investigations spawned (children)")
            for v in variants:
                if not isinstance(v, dict):
                    continue
                out.append(f"- {v.get('title', '?')} [status={v.get('status', '?')}]")
                if v.get("question"):
                    out.append(f"  Question: {v['question']}")
                for f in v.get("findings") or []:
                    if not isinstance(f, dict):
                        continue
                    poc_tag = (
                        f" PoC: {f.get('poc_language', '?')}"
                        if f.get("has_poc") else " (no PoC yet)"
                    )
                    out.append(
                        f"  ↳ finding: {f.get('crash_type', '?')} in "
                        f"`{f.get('vulnerable_function', '?')}`{poc_tag}",
                    )
                    if f.get("root_cause"):
                        out.append(f"     {f['root_cause'][:300]}")
            out.append("")

        pocs = facts.get("poc_drafts") or []
        if pocs:
            out.append("# PoC drafts available for this investigation's findings")
            for p in pocs:
                if not isinstance(p, dict):
                    continue
                runnable = "RUNNABLE" if p.get("can_run") else "SKELETON"
                out.append(
                    f"- [{runnable}] {p.get('title', '(untitled)')} "
                    f"({p.get('language', '?')}, {len(p.get('code', ''))} chars)",
                )
                if p.get("expected_outcome"):
                    out.append(f"  Expected: {p['expected_outcome'][:200]}")
                if p.get("build_command"):
                    out.append(f"  Build: {p['build_command'][:200]}")
                if p.get("run_command"):
                    out.append(f"  Run: {p['run_command'][:200]}")
                for c in p.get("caveats") or []:
                    out.append(f"  ⚠ {str(c)[:150]}")
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
            "Produce a ReportContent JSON object per the schema. Write "
            "it as if it will be printed and handed to a client's "
            "security team alongside a remediation plan. Be precise, "
            "be specific, do not fabricate."
        )
        return "\n".join(out)
