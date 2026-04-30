"""Pydantic contract models for SbD NFR report and artifact generation.

Design references: D-08 (artifact contracts), D-14 (branding config).

Model taxonomy:
  LLM-internal models (fed to chat_structured):
    ReportNarrativeResponse, RequesterSection, ArchitectSection

  API-facing models (returned to callers):
    ArtifactMetadataResponse, JiraDraftSubtask, JiraWorkItemDraft

OpenAI strict mode compatibility (Pitfall 6):
  All fields on LLM-internal models use explicit non-None defaults so every
  field appears in the JSON schema 'required' array.  Optional fields use
  | None type only on the API-facing models.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from aila.api.schemas.common import APIModel

__all__ = [
    "RequesterSection",
    "ArchitectSection",
    "ReportNarrativeResponse",
    "ArtifactMetadataResponse",
    "JiraDraftSubtask",
    "JiraWorkItemDraft",
]


# ---------------------------------------------------------------------------
# LLM-internal models (fed to chat_structured for report narrative)
# ---------------------------------------------------------------------------


class RequesterSection(BaseModel):
    """LLM-generated section addressed to the project requester.

    Summarises what the requester needs to prepare, clarify, or decide
    before the security architect meeting.

    All fields have explicit non-None defaults (Pitfall 6: OpenAI strict mode).
    """

    prep_checklist: list[str] = Field(default_factory=list)
    scope_decisions_pending: list[str] = Field(default_factory=list)
    supplier_details_needed: bool = Field(default=False)
    timeline_expectations: str = Field(default="")


class ArchitectSection(BaseModel):
    """LLM-generated section addressed to the security architect.

    Provides scope analysis, gray areas requiring discussion, a list of
    triggered SbD sub-tasks with supporting evidence, and risk flags.

    gray_areas: list of dicts with keys: component, reasoning, confidence.
    triggered_subtasks: list of dicts with keys: label, evidence, cited_questions.

    All fields have explicit non-None defaults (Pitfall 6: OpenAI strict mode).
    """

    scope_analysis: str = Field(default="")
    gray_areas: list[dict[str, str]] = Field(default_factory=list)
    triggered_subtasks: list[dict[str, str]] = Field(default_factory=list)
    risk_flags: list[str] = Field(default_factory=list)


class ReportNarrativeResponse(BaseModel):
    """Full LLM response for the pre-meeting report narrative task.

    This is the model_class passed to AilaLLMClient.chat_structured().
    Callers must: ReportNarrativeResponse.model_validate_json(llm_response.content)

    executive_summary: high-level summary of the assessment scope and key findings.
    requester_section: requester-facing preparation guidance.
    architect_section: architect-facing scope analysis and sub-task evidence.
    """

    executive_summary: str = Field(default="")
    requester_section: RequesterSection = Field(default_factory=RequesterSection)
    architect_section: ArchitectSection = Field(default_factory=ArchitectSection)


# ---------------------------------------------------------------------------
# API-facing models
# ---------------------------------------------------------------------------


class ArtifactMetadataResponse(APIModel):
    """Metadata envelope returned when an artifact is generated.

    artifact_type: one of "report", "workbook", "jira_draft".
    format: file format of the generated artifact ("html", "pdf", "xlsx", "json").
    generated_at: UTC timestamp of artifact generation.
    """

    session_id: str
    artifact_type: str
    generated_at: datetime
    format: str


class JiraDraftSubtask(APIModel):
    """A single Jira sub-task candidate in a Jira draft.

    summary: one-line Jira issue summary.
    description: full Jira issue description with evidence.
    component_key: SbD sub-task key (e.g. "network_segment_placement").
    confidence: LLM confidence score for the triggering classification (0.0–1.0).
    """

    summary: str
    description: str
    component_key: str
    confidence: float


class JiraWorkItemDraft(APIModel):
    """A complete Jira work-item draft for the SbD assessment session.

    parent: Jira REST API v2 create-issue fields dict for the parent story.
    subtasks: list of Jira REST API v2 create-issue fields dicts for sub-tasks.
    uncertain_components: list of component keys classified as uncertain —
        these require architect review before a Jira ticket is created.

    Note: This is a draft only — no Jira API calls are made (D-08).
    The dict schemas match the Jira REST API v2 create-issue body so the
    caller can submit them directly when ready.
    """

    parent: dict[str, Any]
    subtasks: list[dict[str, Any]] = Field(default_factory=list)
    uncertain_components: list[str] = Field(default_factory=list)
