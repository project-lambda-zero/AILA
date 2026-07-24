"""Investigation, agent step, and write-up table definitions."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts import utc_now

__all__ = ["AgentStepRecord", "InvestigationRunRecord", "WriteUpRecord"]


class InvestigationRunRecord(SQLModel, table=True):
    """A single free-flow investigation session.

    Written by: POST /forensics/projects/{id}/investigate.
    Consumed by: investigation detail, agent step listing, write-up generation.
    """

    __tablename__ = "forensics_investigations"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    question: str = Field(sa_column=Column(Text))
    status: str = Field(default="pending", index=True)
    task_id: str | None = Field(default=None, index=True)
    max_attempts: int = Field(default=10)
    attempts_used: int = Field(default=0)
    final_answer: str | None = Field(default=None, sa_column=Column(Text))
    confidence: str | None = None
    # When this investigation was started via the "Rerun (enriched)"
    # path, this points at the prior attempt whose findings are
    # carried forward. NULL for the original (root) investigation.
    parent_investigation_id: str | None = Field(default=None, index=True, max_length=64)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class AgentStepRecord(SQLModel, table=True):
    """A single step taken by the free-flow agent during investigation.

    Written by: forensics free-flow workflow state.
    Consumed by: investigation detail UI, write-up generator.
    """

    __tablename__ = "forensics_agent_steps"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    investigation_id: str = Field(index=True)
    step_number: int = Field(default=0)
    action: str = Field(default="reasoning")
    script_content: str | None = Field(default=None, sa_column=Column(Text))
    command: str | None = Field(default=None, sa_column=Column(Text))
    stdout: str | None = Field(default=None, sa_column=Column(Text))
    stderr: str | None = Field(default=None, sa_column=Column(Text))
    exit_code: int | None = None
    reasoning: str = Field(default="", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class WriteUpRecord(SQLModel, table=True):
    """A professional forensic write-up generated from investigation steps.

    Written by: forensics write-up generation service.
    Consumed by: write-up listing UI, report export.
    """

    __tablename__ = "forensics_writeups"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    investigation_id: str | None = Field(default=None, index=True)
    title: str = Field(default="", max_length=512)
    content_markdown: str = Field(default="", sa_column=Column(Text))
    methodology: str = Field(default="", sa_column=Column(Text))
    artifacts_referenced_json: str = Field(default="[]", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
