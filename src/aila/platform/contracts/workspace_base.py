"""Workspace record + contract bases shared by the investigation engine (RFC-01).

A concrete module workspace collapses to::

    class VRWorkspaceRecord(WorkspaceRecordBase, table=True):
        __tablename__ = "vr_workspaces"

The unique constraint name is derived from that ``__tablename__``, so the
vr and malware workspace tables can no longer collide on a shared name.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from pydantic import Field as PField
from sqlalchemy import DateTime, Text
from sqlmodel import Field, SQLModel

from aila.storage.mixins import TeamScopedMixin

from ._common import utc_now
from ._naming import TableDerivedConstraintsMixin, TabledUq
from .enums import WorkspaceStatus

__all__ = [
    "WorkspaceCreateBase",
    "WorkspacePatchBase",
    "WorkspaceRecordBase",
    "WorkspaceSummaryBase",
]


class WorkspaceRecordBase(TableDerivedConstraintsMixin, TeamScopedMixin, SQLModel):
    """Shared columns for every module's workspace table.

    A concrete subclass MUST set ``__tablename__`` and ``table=True``; the
    unique constraint name is materialized against that ``__tablename__``.
    """

    __table_args__ = (TabledUq("team_id", "slug", suffix="team_slug"),)

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    name: str = Field(index=True, max_length=255)
    slug: str = Field(index=True, max_length=128)
    description: str = Field(default="", sa_type=Text, sa_column_kwargs={"nullable": True})
    theme: str = Field(default="custom", max_length=64)
    status: str = Field(default="active", index=True, max_length=32)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class WorkspaceSummaryBase(BaseModel):
    """Shared read-only workspace projection. Modules add their ``theme`` enum."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    slug: str
    description: str
    status: WorkspaceStatus
    target_count: int = 0
    active_investigation_count: int = 0
    created_at: str | None = None
    updated_at: str | None = None


class WorkspaceCreateBase(BaseModel):
    """Shared workspace create payload. Modules add their ``theme`` enum."""

    model_config = ConfigDict(extra="forbid")

    name: str = PField(min_length=1, max_length=255)
    slug: str = PField(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z0-9][a-z0-9_-]*$",
        description="URL-safe identifier. Lowercase alphanumeric + hyphen/underscore.",
    )
    description: str = PField(default="", max_length=4096)


class WorkspacePatchBase(BaseModel):
    """Shared workspace partial-update payload. Modules add their ``theme`` enum."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = PField(default=None, min_length=1, max_length=255)
    description: str | None = PField(default=None, max_length=4096)
    status: WorkspaceStatus | None = None
