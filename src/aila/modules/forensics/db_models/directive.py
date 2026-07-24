"""Analyst directives -- free-text guidance from a human analyst.

Directives are persistent project- or investigation-scoped notes the
investigator reads in every turn so a human can steer the agent
("extract ips-godeep.zip and analyze contents", "ignore /var/log,
focus on /tmp persistence", etc.).

Written by: POST /forensics/projects/{pid}/directives.
Consumed by: HonestInvestigator._load_directives() each turn.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts import utc_now

__all__ = ["AnalystDirectiveRecord"]


class AnalystDirectiveRecord(SQLModel, table=True):
    """A free-text analyst directive scoped to a project or investigation.

    Scope rules:
    - ``investigation_id is None`` → project-wide directive, applied to
      every investigation under ``project_id``.
    - ``investigation_id is not None`` → applied only to that one
      investigation.

    The record is read on every investigator turn; soft-deleted entries
    (``active=False``) are excluded from the prompt but kept for audit.
    """

    __tablename__ = "forensics_analyst_directives"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    investigation_id: str | None = Field(default=None, index=True)
    text: str = Field(sa_column=Column(Text))
    created_by: str | None = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    resolved_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    active: bool = Field(default=True, index=True)
    # Analyst verdict produced by tagging a completed investigation.
    # NULL = free-text guidance (legacy / human-authored).
    # "true" = confirmed finding (treat as ground truth in future runs).
    # "false" = disproved hypothesis (do not re-pursue in future runs).
    verdict: str | None = Field(default=None, index=True, max_length=16)
    strategy_family: str | None = Field(default=None, index=True, max_length=64)
    required_artifact: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    source_investigation_id: str | None = Field(default=None, max_length=64)
    source_answer_id: str | None = Field(default=None, max_length=64)
