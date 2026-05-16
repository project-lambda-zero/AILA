"""Project table definition for the vulnerability research module.

Per D-53: target identity moved to VRTargetRecord (M3.T-1). VRProjectRecord
now holds only project-scoped fields:
  - Identity: id, name, cve_id, team_id
  - Target reference: target_id (NOT NULL), patched_target_id (optional, for
    differential analysis)
  - Lifecycle: status, budget_json, obligations_json, context_notes
  - Machine assignment: analysis_system_id, poc_system_id
  - Timestamps: created_at, updated_at

All target metadata (target_class, target_path, binary_id, mitigations,
ingestion descriptor) lives on VRTargetRecord and is read via the
target_id FK at workflow execution time.

Written by: POST /api/vr/projects (after the api_router creates the
underlying vr_targets row first).
Consumed by: workflow states, agent, advisory builder.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

__all__ = ["VRProjectRecord"]


class VRProjectRecord(TeamScopedMixin, SQLModel, table=True):
    """A vulnerability research project bound to one or two targets.

    The project is the unit of workflow execution + budget + obligation
    tracking. Target identity (binary_id, paths, mitigations, language)
    lives on the linked ``VRTargetRecord``.
    """

    __tablename__ = "vr_projects"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    name: str = Field(index=True, max_length=255)
    cve_id: str | None = Field(default=None, index=True, max_length=32)

    target_id: str = Field(
        sa_column=Column(
            "target_id",
            ForeignKey("vr_targets.id"),
            nullable=False,
            index=True,
        ),
    )
    patched_target_id: str | None = Field(
        default=None,
        sa_column=Column(
            "patched_target_id",
            ForeignKey("vr_targets.id"),
            nullable=True,
            index=True,
        ),
    )

    analysis_system_id: int | None = Field(default=None)
    poc_system_id: int | None = Field(default=None)

    context_notes: str = Field(default="", sa_column=Column(Text))
    status: str = Field(default="created", index=True, max_length=32)
    budget_json: str = Field(default="{}", sa_column=Column(Text))
    obligations_json: str = Field(default="{}", sa_column=Column(Text))

    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
