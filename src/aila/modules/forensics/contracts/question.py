"""Question and answer contract models for the forensics module."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AnswerCandidate",
    "QuestionInput",
]


class QuestionInput(BaseModel):
    """A specific question to investigate."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1)
    format_hint: str = Field(
        default="",
        description="Expected answer format hint.",
    )


class AnswerCandidate(BaseModel):
    """A candidate answer to an investigation question."""

    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    investigation_id: str | None = None
    question_text: str
    answer_text: str
    confidence: str = Field(description="One of: exact, strong, medium, caveated.")
    primary_artifact_id: str | None = None
    corroboration: list[str] = Field(default_factory=list)
    format_hint: str = ""
    created_at: datetime | None = None
