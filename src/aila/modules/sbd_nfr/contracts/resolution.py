"""Pydantic contract models for SbD NFR LLM resolution and per-question assist.

Design references: D-08, D-09, D-10, D-14, D-15, D-16.

Threat mitigations:
  T-135-02: Pydantic model_validate_json() enforces typed schema; Literal type
            on classification prevents arbitrary strings from passing validation.
  T-135-05: AssistRequest.history validated as list of dicts with role/content
            keys; user message placed in user role only (never system prompt).

OpenAI strict mode compatibility (Pitfall 6):
  All fields on ComponentClassification and ResolutionResponse use explicit
  non-None defaults so every field appears in the JSON schema 'required' array.
  Optional fields use | None type only on the API-facing models (not the LLM
  internal models).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from aila.api.schemas.common import APIModel

__all__ = [
    "ComponentClassification",
    "ResolutionResponse",
    "ComponentClassificationResponse",
    "ResolutionResultResponse",
    "AssistRequest",
    "AssistResponse",
]


# ---------------------------------------------------------------------------
# LLM internal models (fed to chat_structured)
# ---------------------------------------------------------------------------


class ComponentClassification(BaseModel):
    """LLM output model for a single SbD sub-task component classification.

    All fields have explicit non-None defaults per Pitfall 6: OpenAI strict
    mode requires every field to be present in the JSON schema 'required'
    array.  Fields with Optional type would be excluded from 'required' and
    cause validation errors.

    subtask_key must match one of the 25 SbdNfrSubtaskComponentRecord.key
    values.  The LLM returns a ComponentClassification for each of the 25
    components regardless of whether questions were answered for that component.

    confidence is a 0.0–1.0 float; the resolution_service applies a threshold
    (CONFIDENCE_THRESHOLD = 0.7) and reclassifies low-confidence results to
    "uncertain" (RESOLVE-03).
    """

    subtask_key: str = Field(default="")
    classification: Literal["triggered", "not_triggered", "uncertain"] = Field(
        default="uncertain"
    )
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = Field(default="")
    cited_question_ids: list[str] = Field(default_factory=list)


class ResolutionResponse(BaseModel):
    """Full LLM response wrapper for the resolution task.

    This is the model_class passed to AilaLLMClient.chat_structured().
    Callers must: ResolutionResponse.model_validate_json(llm_response.content)

    components: one ComponentClassification per SbD sub-task (25 total).
    executive_summary: LLM's own narrative summary of the overall assessment.
    """

    components: list[ComponentClassification] = Field(default_factory=list)
    executive_summary: str = Field(default="")


# ---------------------------------------------------------------------------
# API-facing response models
# ---------------------------------------------------------------------------


class ComponentClassificationResponse(APIModel):
    """API-facing detail for one classified SbD sub-task component.

    subtask_label is the human-readable label from SbdNfrSubtaskComponentRecord,
    joined at read time so callers do not need to look it up separately.
    """

    subtask_key: str
    subtask_label: str
    classification: str
    confidence: float
    reasoning: str
    cited_question_ids: list[str] = Field(default_factory=list)


class ResolutionResultResponse(APIModel):
    """API response for GET /sessions/{id}/resolution.

    Returns the session's resolution status and, when resolved, the full list
    of classified components with executive summary.

    resolved_at is None when the session has not yet completed resolution.
    executive_summary is None when the session has not yet completed resolution.
    components is empty when the session has not yet completed resolution.
    """

    session_id: str
    status: str
    resolved_at: datetime | None = None
    components: list[ComponentClassificationResponse] = Field(default_factory=list)
    executive_summary: str | None = None


# ---------------------------------------------------------------------------
# Assist request/response models (D-14, D-15, D-16)
# ---------------------------------------------------------------------------


class AssistRequest(APIModel):
    """Per-question LLM assist chat request (D-14, D-15).

    message: the user's natural language question about the current NFR question.
    history: prior chat turns in {"role": "user"|"assistant", "content": "..."} format.
             Capped at 40 turns; older turns are dropped by the caller.
    current_answer: the user's current answer value for the question being discussed.
                    Provided so the LLM can give context-aware help (D-15).

    Security (T-135-05): history is a list of dicts validated by Pydantic as
    list[dict[str, str]]; the user message is always placed in the "user" role
    and never injected into the system prompt.
    """

    message: str = Field(min_length=1, max_length=2000)
    history: list[dict[str, str]] = Field(default_factory=list, max_length=40)
    current_answer: str | None = None


class AssistResponse(APIModel):
    """Per-question LLM assist chat response (D-16).

    reply: the LLM's conversational response to the user's question.
           On LLM failure or disabled state, returns a graceful fallback message.
    """

    reply: str
