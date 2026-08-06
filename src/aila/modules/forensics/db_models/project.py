"""Project and evidence table definitions for the forensics module."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import BigInteger, Column, DateTime, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts import utc_now

__all__ = ["ForensicsProjectRecord", "ProjectEvidenceRecord"]


class ForensicsProjectRecord(SQLModel, table=True):
    """A forensics investigation project tied to an analyzer machine.

    Written by: POST /forensics/projects.
    Consumed by: project listing, dashboard, investigation workflows.
    """

    __tablename__ = "forensics_projects"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    name: str = Field(index=True, max_length=255)
    description: str = Field(default="", sa_column=Column(Text))
    system_id: int = Field(index=True)
    evidence_directory: str = Field(sa_column=Column(Text))
    analyzer_os: str = Field(default="linux", max_length=16)
    project_kind: str = Field(default="disk_evidence", max_length=32, index=True)
    status: str = Field(default="created", index=True)
    team_id: str | None = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class ProjectEvidenceRecord(SQLModel, table=True):
    """An evidence file discovered during project intake.

    Written by: forensics.state_intake workflow state.
    Consumed by: artifact collection, evidence tree UI.
    """

    __tablename__ = "forensics_project_evidence"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    file_path: str = Field(sa_column=Column(Text))
    evidence_type: str = Field(default="unknown", index=True)
    file_hash_sha256: str | None = None
    # BIGINT -- disk images / E01s routinely exceed int32 (2GB); 100GB+ common.
    size_bytes: int | None = Field(default=None, sa_column=Column(BigInteger))
    metadata_json: str | None = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
