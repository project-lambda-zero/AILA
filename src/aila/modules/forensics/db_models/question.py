"""Question and answer candidate table definitions."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now

__all__ = ["AnswerCandidateRecord"]


class AnswerCandidateRecord(SQLModel, table=True):
    """A candidate answer to an investigation question.

    Written by: free-flow agent and resolver workflow states.
    Consumed by: Q&A table UI, write-up generator.
    """

    __tablename__ = "forensics_answer_candidates"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    investigation_id: str | None = Field(default=None, index=True)
    question_text: str = Field(sa_column=Column(Text))
    answer_text: str = Field(default="", sa_column=Column(Text))
    confidence: str = Field(default="caveated")
    primary_artifact_id: str | None = None
    corroboration_json: str = Field(default="[]", sa_column=Column(Text))
    format_hint: str = Field(default="")
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
