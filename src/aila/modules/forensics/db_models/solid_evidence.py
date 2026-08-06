"""Solid evidence -- durable analyst-tagged findings.

Analyst-owned rows produced by tagging a completed investigation's
final answer (or a specific answer candidate) as TRUE (confirmed) or
FALSE (disproved). Surfaces in the Solid Evidence tab on the project
dashboard and drives the CONFIRMED / DISPROVED blocks rendered into
every future investigation's system prompt so the agent does not
re-chase questions the analyst has already settled.

Written by: POST /forensics/projects/{pid}/investigations/{iid}/tag.
Consumed by: GET /forensics/projects/{pid}/solid-evidence (Solid
Evidence tab) and indirectly by the investigator via the linked
analyst directive.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts import utc_now

__all__ = ["SolidEvidenceRecord"]


class SolidEvidenceRecord(SQLModel, table=True):
    """A single analyst-tagged finding, TRUE or FALSE."""

    __tablename__ = "forensics_solid_evidence"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True, max_length=64)
    question: str = Field(sa_column=Column(Text))
    answer: str = Field(sa_column=Column(Text))
    verdict: str = Field(index=True, max_length=16)  # "true" | "false"
    confidence: str = Field(default="unknown", max_length=16)
    source_investigation_id: str | None = Field(default=None, index=True, max_length=64)
    source_answer_id: str | None = Field(default=None, max_length=64)
    source_directive_id: str | None = Field(default=None, max_length=64)
    primary_artifact: str | None = Field(default=None, sa_column=Column(Text))
    corroboration_json: str = Field(default="[]", sa_column=Column(Text))
    tagged_by: str | None = Field(default=None, max_length=64)
    tagged_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    notes: str = Field(default="", sa_column=Column(Text))
