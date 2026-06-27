"""Finding suppressions -- analyst-marked false positives on auto-findings.

Auto-findings are derived at read-time from ``ArtifactRecord.data_json``
``records[]`` that carry ``suspicious_reasons``. Since there is no stable
row id, a suppression is keyed on a deterministic fingerprint built from
``(artifact_type, executable, path, name, user)`` -- the same tuple the
findings endpoint uses for dedup.

Written by: POST /forensics/projects/{pid}/findings/suppress.
Consumed by: GET /forensics/projects/{pid}/findings (hides matching rows)
and indirectly by the investigator via the linked AnalystDirective.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now

__all__ = ["FindingSuppressionRecord"]


class FindingSuppressionRecord(SQLModel, table=True):
    """A single analyst false-positive mark on a heuristic finding."""

    __tablename__ = "forensics_finding_suppressions"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True, max_length=64)
    fingerprint: str = Field(max_length=64)  # sha256[:64] of the identity tuple
    artifact_type: str | None = Field(default=None, max_length=128)
    executable: str | None = Field(default=None, sa_column=Column(Text))
    path: str | None = Field(default=None, sa_column=Column(Text))
    name: str | None = Field(default=None, sa_column=Column(Text))
    # ``user`` is a SQL reserved word in some dialects; use finding_user.
    finding_user: str | None = Field(default=None, sa_column=Column(Text))
    reasons_json: str = Field(default="[]", sa_column=Column(Text))
    notes: str = Field(default="", sa_column=Column(Text))
    source_directive_id: str | None = Field(default=None, max_length=64)
    suppressed_by: str | None = Field(default=None, max_length=64)
    suppressed_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
