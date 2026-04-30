"""Jira work-item draft builder for the SbD NFR module.

Design references: D-09, D-10, REPORT-04.

Generates a Jira REST API v2 compatible JSON draft for a resolved NFR
assessment session.  No Jira API calls are made — the output is a
JiraWorkItemDraft that the caller can POST when Jira integration is added.

Classification partitioning (D-10):
  - HIGH-confidence triggered (confidence >= CONFIDENCE_THRESHOLD): sub-tasks
  - Uncertain: listed in parent description only — NOT sub-tasks
  - Not triggered: omitted from draft entirely

Threat mitigations:
  T-136-10: Reasoning included intentionally for architect review. Jira draft
            access is controlled by Plan 04 API endpoint authorization.
  T-136-11: PLACEHOLDER project/parent keys are intentional (D-09) — real
            keys are set by the caller when Jira integration is enabled.
"""

from __future__ import annotations

import json
import logging
from fastapi import HTTPException
from sqlmodel import select

from aila.modules.sbd_nfr.contracts.artifacts import JiraWorkItemDraft
from aila.modules.sbd_nfr.db_models import (
    SbdNfrResolutionResultRecord,
    SbdNfrSessionRecord,
)
from aila.modules.sbd_nfr.services.resolution_service import CONFIDENCE_THRESHOLD
from aila.platform.uow import UnitOfWork

__all__ = ["generate_jira_draft"]

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public async entry point
# ---------------------------------------------------------------------------


async def generate_jira_draft(session_id: str) -> JiraWorkItemDraft:
    """Generate a Jira REST API v2 draft for *session_id*.

    Args:
        session_id: Primary key of the SbdNfrSessionRecord to draft.

    Returns:
        JiraWorkItemDraft with parent issue and sub-task dicts.

    Raises:
        HTTPException(404): Session not found or not in "resolved" status.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        session, classifications = await _load_data(db, session_id)

    # Partition by classification and confidence (D-10)
    triggered_high = [
        c
        for c in classifications
        if c.classification == "triggered" and c.confidence >= CONFIDENCE_THRESHOLD
    ]
    uncertain = [c for c in classifications if c.classification == "uncertain"]

    parent = _build_parent_issue(session, triggered_high, uncertain)
    subtasks = [_build_subtask_issue(c) for c in triggered_high]
    uncertain_labels = [c.subtask_key.replace("_", " ").title() for c in uncertain]

    return JiraWorkItemDraft(
        parent=parent,
        subtasks=subtasks,
        uncertain_components=uncertain_labels,
    )


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


async def _load_data(
    db: object,
    session_id: str,
) -> tuple[SbdNfrSessionRecord, list[SbdNfrResolutionResultRecord]]:
    """Load session and resolution result records from DB."""
    session = (await db.exec(
        select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
    )).first()
    if session is None or session.status != "resolved":
        raise HTTPException(status_code=404, detail=f"Session {session_id!r} not found or not resolved")

    classifications = list((await db.exec(
        select(SbdNfrResolutionResultRecord).where(
            SbdNfrResolutionResultRecord.session_id == session_id
        )
    )).all())
    return session, classifications


# ---------------------------------------------------------------------------
# Issue builders
# ---------------------------------------------------------------------------


def _build_parent_issue(
    session: SbdNfrSessionRecord,
    triggered_high: list[SbdNfrResolutionResultRecord],
    uncertain: list[SbdNfrResolutionResultRecord],
) -> dict:
    """Build the Jira REST API v2 parent story fields dict (D-09)."""
    return {
        "fields": {
            "project": {"key": "PLACEHOLDER"},
            "summary": f"SbD NFR Assessment: {session.project_name}",
            "description": _build_parent_description(session, triggered_high, uncertain),
            "issuetype": {"name": "Story"},
            "components": [
                {"name": c.subtask_key.replace("_", " ").title()}
                for c in triggered_high
            ],
        }
    }


def _build_parent_description(
    session: SbdNfrSessionRecord,
    triggered_high: list[SbdNfrResolutionResultRecord],
    uncertain: list[SbdNfrResolutionResultRecord],
) -> str:
    """Build the plain-text parent issue description.

    Uses plain text rather than Atlassian Document Format (ADF) for maximum
    Jira version compatibility (RESEARCH.md assumption A2).
    """
    lines: list[str] = [
        f"SbD NFR Assessment — {session.project_name}",
        f"Session ID: {session.id}",
        f"Requestor: {session.requestor_name} <{session.requestor_email}>",
        "",
        f"Triggered components (high confidence, >= {CONFIDENCE_THRESHOLD:.0%}): {len(triggered_high)}",
        f"Components requiring architect review (uncertain): {len(uncertain)}",
        "",
    ]

    if triggered_high:
        lines.append("TRIGGERED COMPONENTS")
        lines.append("--------------------")
        for c in sorted(triggered_high, key=lambda x: x.subtask_key):
            label = c.subtask_key.replace("_", " ").title()
            lines.append(f"- {label} (confidence: {c.confidence:.0%})")
        lines.append("")

    if uncertain:
        lines.append("COMPONENTS REQUIRING ARCHITECT REVIEW")
        lines.append("--------------------------------------")
        lines.append("The following components require architect review before a Jira ticket is created:")
        lines.append("")
        for c in sorted(uncertain, key=lambda x: x.subtask_key):
            label = c.subtask_key.replace("_", " ").title()
            reasoning_excerpt = (c.reasoning[:150] + "...") if len(c.reasoning) > 150 else c.reasoning
            lines.append(
                f"- {label} (confidence: {c.confidence:.0%}, reasoning: {reasoning_excerpt})"
            )
        lines.append("")

    lines.append("NOTE: Project key 'PLACEHOLDER' must be replaced with your Jira project key before importing.")
    return "\n".join(lines)


def _build_subtask_issue(classification: SbdNfrResolutionResultRecord) -> dict:
    """Build a Jira REST API v2 sub-task fields dict (D-10)."""
    label = classification.subtask_key.replace("_", " ").title()
    return {
        "fields": {
            "project": {"key": "PLACEHOLDER"},
            "summary": f"SbD: {label}",
            "description": _build_subtask_description(classification),
            "issuetype": {"name": "Sub-task"},
            "parent": {"key": "PLACEHOLDER_PARENT_KEY"},
        }
    }


def _build_subtask_description(classification: SbdNfrResolutionResultRecord) -> str:
    """Build the plain-text sub-task description including LLM reasoning."""
    cited_ids: list[str] = []
    try:
        cited_ids = json.loads(classification.cited_question_ids_json or "[]")
    except (json.JSONDecodeError, AttributeError):
        cited_ids = []

    label = classification.subtask_key.replace("_", " ").title()
    lines: list[str] = [
        f"SbD Component: {label}",
        f"Component Key: {classification.subtask_key}",
        f"Classification: {classification.classification}",
        f"Confidence: {classification.confidence:.0%}",
        "",
        "REASONING",
        "---------",
        classification.reasoning or "No reasoning available.",
        "",
    ]

    if cited_ids:
        lines.append("CITED EVIDENCE QUESTIONS")
        lines.append("------------------------")
        for qid in cited_ids:
            lines.append(f"- {qid}")
        lines.append("")

    lines.append("NOTE: Sub-task key 'PLACEHOLDER_PARENT_KEY' must be replaced with the parent issue key.")
    return "\n".join(lines)
