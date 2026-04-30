"""Artifact and lead table definitions for the forensics module."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now

__all__ = ["ArtifactRecord", "LeadRecord"]


class ArtifactRecord(SQLModel, table=True):
    """A normalized artifact extracted from forensic evidence.

    Written by: forensics.state_collection workflow state.
    Consumed by: lead scoring, resolver, free-flow agent, artifact explorer UI.
    """

    __tablename__ = "forensics_artifacts"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    artifact_family: str = Field(index=True)
    artifact_type: str = Field(index=True)
    source_tool: str = Field(default="")
    source_evidence_id: str | None = None
    # Set when this artifact was emitted by a specific investigation
    # (i.e. by the agent at answer-submission time). NULL for rows
    # produced by intake or full-analysis collectors.
    source_investigation_id: str | None = Field(default=None, index=True, max_length=64)
    data_json: str = Field(default="{}", sa_column=Column(Text))
    lead_score: float | None = None
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class LeadRecord(SQLModel, table=True):
    """A promoted lead scored from artifact analysis.

    Written by: forensics.state_promotion workflow state.
    Consumed by: resolver, free-flow agent, VIA table UI.
    """

    __tablename__ = "forensics_leads"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    artifact_id: str = Field(index=True)
    score: float = Field(default=0.0)
    reason: str = Field(default="", sa_column=Column(Text))
    artifact_family: str = Field(default="")
    related_artifact_ids_json: str = Field(default="[]", sa_column=Column(Text))
    question_families_json: str = Field(default="[]", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
