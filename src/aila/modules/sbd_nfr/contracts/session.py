"""Pydantic response and request models for the SbD NFR session API.

Design references: D-06, D-20, D-30, D-32, D-36, D-51.

These are pure Pydantic contract models — no SQLModel, no DB access.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from aila.api.schemas.common import APIModel

__all__ = [
    "SectionProgressResponse",
    "AnswerResponse",
    "SessionSummaryResponse",
    "SessionDetailResponse",
    "SessionCreateRequest",
    "AnswerInput",
    "BulkAnswerRequest",
    "ArchitectNotesRequest",
    "SubmitForReviewRequest",
    "ApproveSessionRequest",
]


class SectionProgressResponse(APIModel):
    """Progress counters for one section, skip-logic-aware.

    visible_count: required questions visible given current scope answers.
    answered_count: how many of those visible required questions are answered.
    total_count: all questions in the section (for UI display context).
    """

    section_key: str
    visible_count: int
    answered_count: int
    total_count: int


class AnswerResponse(APIModel):
    """One captured answer for a question within a session."""

    question_id: str
    answer_value: str
    note_text: str | None = None
    answered_by_name: str
    answered_by_email: str
    updated_at: datetime


class SessionSummaryResponse(APIModel):
    """Summary representation of an assessment session (list view)."""

    id: str
    status: str
    project_name: str
    description: str | None = None
    business_unit: str | None = None
    requestor_name: str
    requestor_email: str
    target_date: datetime | None = None
    is_template: bool
    template_name: str | None = None
    tags: list[str] = Field(default_factory=list)
    assigned_architect_id: str | None = None
    architect_notes: str | None = None
    created_at: datetime
    updated_at: datetime


class SessionDetailResponse(APIModel):
    """Full state snapshot of an assessment session per D-32.

    Contains the session metadata, all current answers, per-section progress
    (skip-logic-aware), and the ID of the next unanswered question.
    """

    session: SessionSummaryResponse
    schema_version: int
    share_token: str
    answers: list[AnswerResponse] = Field(default_factory=list)
    section_progress: list[SectionProgressResponse] = Field(default_factory=list)
    next_unanswered_question_id: str | None = None


class SessionCreateRequest(APIModel):
    """Request body for creating a new assessment session."""

    project_name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    business_unit: str | None = None
    requestor_name: str = Field(min_length=1, max_length=100)
    requestor_email: str = Field(min_length=3, max_length=200)
    target_date: datetime | None = None
    tags: list[str] = Field(default_factory=list)


class AnswerInput(APIModel):
    """Single answer payload within a bulk answer request."""

    question_id: str
    answer_value: str
    note_text: str | None = None


class BulkAnswerRequest(APIModel):
    """Request body for submitting one or more answers in a single call."""

    answers: list[AnswerInput] = Field(min_length=1)


class ArchitectNotesRequest(APIModel):
    """Request body for saving architect notes on a session (Phase 145 D-13)."""

    notes: str


class SubmitForReviewRequest(APIModel):
    """Request body for submitting a session for architect review (Phase 145 D-02)."""

    notes: str | None = None


class ApproveSessionRequest(APIModel):
    """Request body for architect approval of a session (Phase 145 D-02)."""

    notes: str | None = None
