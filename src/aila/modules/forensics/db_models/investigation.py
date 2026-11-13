"""Investigation, agent step, and write-up table definitions."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts import utc_now
from aila.platform.events.entity_status import track_status_changes

__all__ = ["AgentStepRecord", "InvestigationRunRecord", "WriteUpRecord"]


class InvestigationRunRecord(SQLModel, table=True):
    """A single free-flow investigation session.

    Written by: POST /forensics/projects/{id}/investigate.
    Consumed by: investigation detail, agent step listing, write-up generation.
    """

    __tablename__ = "forensics_investigations"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str = Field(index=True)
    # Denormalised copy of ``forensics_projects.team_id`` at insert time
    # (#59). Populated on every write path from the parent project so the
    # do_orm_execute team-scope listener can auto-filter reads without
    # a preceding parent-row join. The project ownership guard still
    # runs on the parent row for defense-in-depth. Nullable to match the
    # parent's ``NULL == admin-owned`` convention.
    team_id: str | None = Field(default=None, index=True)
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
    # RFC-09 criterion 4: pin-per-investigation. First resolve of a prompt
    # key on this row records the current production-alias version here;
    # subsequent resolves for the SAME investigation return the pinned
    # version so a live production-alias flip never rewrites a running
    # investigation. JSON object mapping prompt-key -> resolved version
    # string. Empty object = nothing pinned yet. Mirrors the base column
    # on ``InvestigationRecordBase`` (this table does not extend the base
    # so the field is declared directly). Migration 115 adds the column.
    prompt_pins_json: str = Field(
        default="{}", sa_type=Text, sa_column_kwargs={"nullable": True},
    )
    # Platform ``persona_spawn`` (RFC-13/03) reads the investigation-level
    # ``strategy_family`` as the fallback family when a primary branch was
    # INSERTed without one. This table does not extend
    # ``InvestigationRecordBase`` (see ``prompt_pins_json`` above), so the
    # column is declared directly here; migration 122 adds it. Default
    # "generic" mirrors the forensics investigator's own fallback family.
    strategy_family: str = Field(default="generic", max_length=64)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    # RFC-09 criterion 4 requires ``resolve_pinned_prompt`` to stamp the
    # row's modification time when it persists a fresh pin. Added here
    # for that hot path (SQLModel would otherwise raise on setattr for
    # an unmapped attribute under Pydantic v2). Nullable so migration 115
    # can backfill existing rows without a data migration.
    updated_at: datetime | None = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )
    # Written by the platform investigation lifecycle: re-enqueueing a stuck
    # run clears ``pause_reason`` and nulls ``started_at`` while resetting the
    # row to ``created``. SQLModel rejects assignment to an undeclared field,
    # so both columns must exist for that reset to commit. Nullable so
    # existing rows need no backfill; migration 149 adds the columns.
    pause_reason: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    started_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))


# Every committed status transition is announced as an
# ``entity.status_changed`` domain event (worker writes reach the API
# process via the Redis bridge) and pushed to the team's SSE streams.
track_status_changes(InvestigationRunRecord, module_id="forensics", entity_kind="investigation")


class AgentStepRecord(SQLModel, table=True):
    """A single step taken by the free-flow agent during investigation.

    Written by: forensics free-flow workflow state.
    Consumed by: investigation detail UI, write-up generator.
    """

    __tablename__ = "forensics_agent_steps"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    investigation_id: str = Field(index=True)
    # Denormalised copy of the parent investigation's team_id (#59) --
    # stamped at insert time so the team-scope listener can auto-filter
    # step reads without a two-hop join back to ``forensics_projects``.
    team_id: str | None = Field(default=None, index=True)
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
    # Denormalised copy of ``forensics_projects.team_id`` (#59) so the
    # team-scope listener can auto-filter write-up reads.
    team_id: str | None = Field(default=None, index=True)
    investigation_id: str | None = Field(default=None, index=True)
    title: str = Field(default="", max_length=512)
    content_markdown: str = Field(default="", sa_column=Column(Text))
    methodology: str = Field(default="", sa_column=Column(Text))
    artifacts_referenced_json: str = Field(default="[]", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
