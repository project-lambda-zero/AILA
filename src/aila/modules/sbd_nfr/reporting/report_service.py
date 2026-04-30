"""LLM-powered pre-meeting report generation for the SbD NFR module.

Design references: D-01, D-03, D-04, D-05, D-06, D-11, REPORT-01, REPORT-02.

Generates a structured narrative report for a resolved NFR assessment session.
The report is rendered as HTML (for browser preview) or PDF (for download).

Pipeline:
  1. Load resolution results from SbdNfrResolutionResultRecord (NOT session.resolution_json)
  2. Load answers from SbdNfrAnswerRecord for the evidence map
  3. Load subtask component labels from SbdNfrSubtaskComponentRecord (for appendix)
  4. Call AilaLLMClient.chat_structured() with ReportNarrativeResponse as model_class
  5. Load branding config from ConfigRegistry (SbdNfrConfig)
  6. Render Jinja2 template -> HTML string
  7. Optionally convert to PDF via pdf_service.html_to_pdf()

Threat mitigations:
  T-136-04: Jinja2 autoescaping active by default — LLM output HTML-escaped.
  T-136-05: org_logo_url rendered as <img src="..."> — browser-resolved only.
  T-136-06: PDF generation is async-safe (delegated to pdf_service.html_to_pdf).
  T-136-07: llm_response.disabled checked before model_validate_json().
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from fastapi import HTTPException
from jinja2 import Environment, PackageLoader, select_autoescape
from sqlmodel import select

from aila.modules.sbd_nfr.contracts.artifacts import ReportNarrativeResponse
from aila.modules.sbd_nfr.db_models import (
    SbdNfrAnswerRecord,
    SbdNfrResolutionResultRecord,
    SbdNfrSessionRecord,
    SbdNfrSubtaskComponentRecord,
)
from aila.modules.sbd_nfr.services.config import SbdNfrConfig
from aila.platform.services.factory import ServiceFactory
from aila.platform.uow import UnitOfWork
from aila.storage.registry import ConfigRegistry

__all__ = ["generate_report_html", "generate_report_pdf"]

_log = logging.getLogger(__name__)

_REPORT_TASK_TYPE: str = "report"

# ---------------------------------------------------------------------------
# Public async entry points
# ---------------------------------------------------------------------------


async def generate_report_html(session_id: str) -> str:
    """Generate the pre-meeting report as an HTML string.

    Loads resolution data and answers, calls the LLM for a structured
    narrative, loads branding config, and renders the Jinja2 template.

    Args:
        session_id: The resolved session to generate a report for.

    Returns:
        Rendered HTML string.

    Raises:
        HTTPException(404): Session not found or status != "resolved".
        HTTPException(503): LLM is disabled by operator.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        session, classifications, answers, subtask_map = await _load_resolution_data(db, session_id)
    answer_map = _build_answer_map(answers)
    branding = await _load_branding_config()
    narrative = await _generate_narrative(session, classifications, answer_map, branding)

    env = Environment(
        loader=PackageLoader("aila.modules.sbd_nfr", "templates"),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")

    generated_at = datetime.now(timezone.utc)

    html_str: str = template.render(
        narrative=narrative,
        branding=branding,
        session=session,
        classifications=classifications,
        answer_map=answer_map,
        subtask_map=subtask_map,
        generated_at=generated_at,
    )
    return html_str


async def generate_report_pdf(session_id: str) -> bytes:
    """Generate the pre-meeting report as PDF bytes.

    Renders the report as HTML, then converts to PDF via weasyprint.  The
    conversion is synchronous and runs inline; large reports should be offloaded
    to a platform task by the caller.

    Args:
        session_id: The resolved session to generate a report for.

    Returns:
        PDF bytes.

    Raises:
        HTTPException(404): Session not found or status != "resolved".
        HTTPException(503): LLM is disabled by operator.
    """
    from aila.modules.sbd_nfr.reporting.pdf_service import html_to_pdf

    html_str = await generate_report_html(session_id)
    return html_to_pdf(html_str)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _load_resolution_data(
    db: object,
    session_id: str,
) -> tuple[
    SbdNfrSessionRecord,
    list[SbdNfrResolutionResultRecord],
    list[SbdNfrAnswerRecord],
    dict[str, str],
]:
    """Load session, classification results, answers, and subtask labels.

    Queries SbdNfrResolutionResultRecord rows (NOT session.resolution_json —
    the result table is the authoritative source for post-threshold
    classifications per the architecture decision).

    Also builds a subtask_map: {subtask_key: label} from
    SbdNfrSubtaskComponentRecord for the report appendix.

    Args:
        db: Async database session.
        session_id: Session to load.

    Returns:
        Tuple of (session, classifications, answers, subtask_map).

    Raises:
        HTTPException(404): Session not found or status != "resolved".
    """
    # Load session record
    session = (await db.exec(  # type: ignore[union-attr]
        select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
    )).first()
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id!r} not found.")
    if session.status not in {"resolved", "in_review", "approved", "report_generated"}:
        raise HTTPException(
            status_code=404,
            detail=f"Session {session_id!r} is not ready for reporting (status={session.status!r}).",
        )

    # Load classification results (authoritative source)
    classifications = list((await db.exec(  # type: ignore[union-attr]
        select(SbdNfrResolutionResultRecord)
        .where(SbdNfrResolutionResultRecord.session_id == session_id)
        .order_by(SbdNfrResolutionResultRecord.subtask_key)
    )).all())

    # Load answers for the evidence map
    answers = list((await db.exec(  # type: ignore[union-attr]
        select(SbdNfrAnswerRecord).where(SbdNfrAnswerRecord.session_id == session_id)
    )).all())

    # Load subtask component labels for the appendix
    subtask_components = list((await db.exec(  # type: ignore[union-attr]
        select(SbdNfrSubtaskComponentRecord).order_by(SbdNfrSubtaskComponentRecord.display_order)
    )).all())
    subtask_map: dict[str, str] = {st.key: st.label for st in subtask_components}

    return session, classifications, answers, subtask_map


def _build_answer_map(answers: list[SbdNfrAnswerRecord]) -> dict[str, str]:
    """Build a {question_id: answer_value} dict for LLM prompt injection.

    Args:
        answers: SbdNfrAnswerRecord rows for the session.

    Returns:
        Dict mapping question_id to answer_value.
    """
    return {a.question_id: a.answer_value for a in answers}


async def _generate_narrative(
    session: SbdNfrSessionRecord,
    classifications: list[SbdNfrResolutionResultRecord],
    answer_map: dict[str, str],
    config: SbdNfrConfig,
) -> ReportNarrativeResponse:
    """Call the LLM to generate a structured report narrative.

    Builds a system prompt with:
    - Professional security consultant tone with [QUESTION-ID: value] citation enforcement
    - Full answer evidence map block
    - All component classifications with their status, confidence, and reasoning
    - Separate requester section instructions (D-03)
    - Separate architect section instructions (D-04)

    Checks llm_response.disabled before parsing (T-136-07).

    Args:
        session: The resolved session record.
        classifications: All SbdNfrResolutionResultRecord rows for the session.
        answer_map: {question_id: answer_value} dict built from answers.
        config: Branding config (used for org_name in prompt framing).

    Returns:
        Parsed ReportNarrativeResponse.

    Raises:
        HTTPException(503): LLM is disabled by operator.
    """
    system_prompt = _build_report_system_prompt(session, classifications, answer_map, config)
    user_message = _build_report_user_message(session, classifications, answer_map)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    llm_client = ServiceFactory().llm_client
    _log.debug(
        "_generate_narrative: calling LLM for session %r with %d classifications",
        session.id,
        len(classifications),
    )

    llm_response = await llm_client.chat_structured(
        task_type=_REPORT_TASK_TYPE,
        messages=messages,
        model_class=ReportNarrativeResponse,
    )

    # T-136-07: check disabled sentinel before parsing to avoid treating the
    # disabled message string as a JSON payload.
    if llm_response.disabled:
        raise HTTPException(
            status_code=503,
            detail="LLM is disabled; report narrative cannot be generated.",
        )

    narrative = ReportNarrativeResponse.model_validate_json(llm_response.content)
    _log.debug("_generate_narrative: narrative parsed successfully for session %r", session.id)
    return narrative


async def _load_branding_config() -> SbdNfrConfig:
    """Load the 6 branding fields from ConfigRegistry.

    Reads each branding field individually via ConfigRegistry.get() following
    the env var > DB row > schema default resolution chain.

    Returns:
        SbdNfrConfig populated with current branding values.
    """
    registry = ConfigRegistry()
    ns = "sbd_nfr"

    branding_fields = [
        "questionnaire_title",
        "report_subtitle",
        "org_name",
        "org_logo_url",
        "primary_color",
        "footer_text",
    ]

    kwargs: dict[str, object] = {}
    for field in branding_fields:
        value = await registry.get(ns, field)
        if value is not None:
            kwargs[field] = value

    return SbdNfrConfig(**kwargs)


# ---------------------------------------------------------------------------
# Prompt building helpers
# ---------------------------------------------------------------------------


def _build_report_system_prompt(
    session: SbdNfrSessionRecord,
    classifications: list[SbdNfrResolutionResultRecord],
    answer_map: dict[str, str],
    config: SbdNfrConfig,
) -> str:
    """Build the LLM system prompt for the report narrative task.

    Includes:
    - Professional security consultant tone declaration (D-05)
    - [QUESTION-ID: answer_value] citation format enforcement
    - Full answer evidence map block
    - All 25 component classifications with status, confidence, and reasoning
    - Requester section instructions: prep checklist, scope decisions, timeline (D-03)
    - Architect section instructions: scope analysis, gray areas, evidence trail (D-04)

    Args:
        session: The resolved session record.
        classifications: Resolution result rows.
        answer_map: {question_id: answer_value} dict.
        config: Branding config for org_name framing.

    Returns:
        Formatted system prompt string.
    """
    lines = [
        "You are writing a pre-meeting security assessment report on behalf of a "
        f"professional security consultant at {config.org_name}.",
        "",
        "Use formal but clear language. The report will be read by:",
        "  1. The requester (project team) — who needs to prepare for the meeting.",
        "  2. The security architect — who needs to assess scope and plan the engagement.",
        "",
        "CITATION REQUIREMENT: Every claim you make about the assessment MUST cite the "
        "specific question ID and answer value using the format [QUESTION-ID: answer_value].",
        "Example: 'The system is externally accessible [SCOPE-01: External (APN; customer facing)].'",
        "Do not make claims about the project scope without citing the supporting answer.",
        "",
        "=== PROJECT CONTEXT ===",
        f"Project: {session.project_name}",
    ]

    if session.description:
        lines.append(f"Description: {session.description}")
    if session.business_unit:
        lines.append(f"Business Unit: {session.business_unit}")

    lines.append(f"Requester: {session.requestor_name} <{session.requestor_email}>")

    # Answer evidence map block
    lines.append("")
    lines.append("=== ANSWER EVIDENCE MAP ===")
    lines.append(
        "These are all the answers provided by the requester. "
        "Use these as your citation sources:"
    )
    if answer_map:
        for qid, value in sorted(answer_map.items()):
            lines.append(f"  {qid}: {value}")
    else:
        lines.append("  (no answers recorded)")

    # Component classification summary
    triggered = [c for c in classifications if c.classification == "triggered"]
    uncertain = [c for c in classifications if c.classification == "uncertain"]

    lines.append("")
    lines.append("=== COMPONENT CLASSIFICATION RESULTS ===")
    lines.append(
        f"Total components: {len(classifications)} | "
        f"Triggered: {len(triggered)} | "
        f"Uncertain: {len(uncertain)} | "
        f"Not triggered: {len(classifications) - len(triggered) - len(uncertain)}"
    )
    lines.append("")

    for cls in classifications:
        cited = json.loads(cls.cited_question_ids_json or "[]")
        cited_str = ", ".join(cited) if cited else "none"
        lines.append(f"Component: {cls.subtask_key}")
        lines.append(f"  Classification: {cls.classification}")
        lines.append(f"  Confidence: {cls.confidence:.2f}")
        lines.append(f"  Reasoning: {cls.reasoning}")
        lines.append(f"  Cited questions: {cited_str}")
        lines.append("")

    # Section 1: Requester section instructions (D-03)
    lines.append("=== REQUESTER SECTION INSTRUCTIONS (D-03) ===")
    lines.append(
        "Generate the 'requester_section' JSON field with these sub-fields:"
    )
    lines.append(
        "  prep_checklist: A list of specific documents or information the requester "
        "should bring to the architect meeting. Base this on the triggered components — "
        "cite the question IDs that drove each triggered classification. "
        "Examples: architecture diagrams, network topology, vendor contracts, "
        "data classification register, capacity estimates."
    )
    lines.append(
        "  scope_decisions_pending: A list of unanswered scope decisions that the "
        "architect will need to discuss. Focus on uncertain components and questions "
        "where the answer suggests ambiguity."
    )
    lines.append(
        "  supplier_details_needed: Set to true if any supplier-facing or third-party "
        "component was triggered (e.g. external network access, third-party integrations, "
        "cloud providers). Otherwise set to false."
    )
    lines.append(
        "  timeline_expectations: A single sentence describing the expected engagement "
        "timeline based on the number and severity of triggered components. "
        f"({len(triggered)} components triggered; {len(uncertain)} uncertain.)"
    )

    # Section 2: Architect section instructions (D-04)
    lines.append("")
    lines.append("=== ARCHITECT SECTION INSTRUCTIONS (D-04) ===")
    lines.append(
        "Generate the 'architect_section' JSON field with these sub-fields:"
    )
    lines.append(
        "  scope_analysis: A paragraph summarising which SbD components are in scope, "
        "which are not, and the overall security complexity of the engagement. "
        "Cite the scope answers that determine the boundary [QUESTION-ID: value]."
    )
    lines.append(
        "  gray_areas: A list of dicts, one per uncertain component, each with keys: "
        "'component' (subtask_key), 'reasoning' (why it is uncertain), "
        "'confidence' (the numeric confidence as a string). "
        "These are the items requiring architect discussion before the scope is confirmed."
    )
    lines.append(
        "  triggered_subtasks: A list of dicts, one per triggered component, each with keys: "
        "'label' (human-readable label), 'evidence' (one sentence citing the answers that "
        "triggered this component [QUESTION-ID: value]), 'cited_questions' (comma-separated "
        "question IDs). Only include triggered components, not uncertain or not_triggered."
    )
    lines.append(
        "  risk_flags: A short list of the highest-risk signals in the assessment. "
        "Each flag should be a single actionable sentence. Focus on: external exposure, "
        "data sensitivity, uncertain high-confidence components, and scope gaps."
    )

    return "\n".join(lines)


def _build_report_user_message(
    session: SbdNfrSessionRecord,
    classifications: list[SbdNfrResolutionResultRecord],
    answer_map: dict[str, str],
) -> str:
    """Build the user message requesting the report narrative.

    Provides a brief task description and reinforces the citation requirement.

    Args:
        session: The resolved session record.
        classifications: Resolution result rows.
        answer_map: {question_id: answer_value} dict.

    Returns:
        Formatted user message string.
    """
    triggered_count = sum(1 for c in classifications if c.classification == "triggered")
    uncertain_count = sum(1 for c in classifications if c.classification == "uncertain")

    lines = [
        f"Generate the pre-meeting security assessment report for project: {session.project_name}.",
        "",
        f"Summary: {triggered_count} SbD components triggered, {uncertain_count} uncertain, "
        f"{len(answer_map)} answers provided.",
        "",
        "Produce a complete ReportNarrativeResponse JSON object with:",
        "  - executive_summary: 2-3 paragraphs covering scope, key findings, "
        "and recommended next steps.",
        "  - requester_section: meeting prep guidance following the D-03 instructions.",
        "  - architect_section: scope analysis and evidence trail following D-04 instructions.",
        "",
        "Remember: every factual claim must use [QUESTION-ID: answer_value] citation format.",
    ]
    return "\n".join(lines)
