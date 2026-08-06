"""Project record + contract bases shared by the investigation engine (RFC-01).

A concrete module project collapses to::

    class VRProjectRecord(ProjectRecordBase, table=True):
        __tablename__ = "vr_projects"
        __target_tablename__ = "vr_targets"

Module-specific residue (vr-only ``cve_id`` / ``patched_target_id`` /
``poc_system_id``) lives on the concrete subclass, not the base.
``analysis_system_id`` is shared -- both modules keep the same
``int | None`` machine-assignment field -- so it stays on the base.
"""
from __future__ import annotations

from datetime import datetime
from typing import ClassVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy import DateTime, Text
from sqlmodel import Field, SQLModel

from aila.storage.mixins import TeamScopedMixin

from ._common import utc_now
from ._naming import TableDerivedConstraintsMixin, TabledFk

__all__ = [
    "ProjectRecordBase",
    "ProjectSummaryBase",
]


class ProjectRecordBase(TableDerivedConstraintsMixin, TeamScopedMixin, SQLModel):
    """Shared columns for every module's project table (D-53).

    A concrete subclass MUST set ``__tablename__``,
    ``__target_tablename__``, and ``table=True``. The FK from
    ``target_id`` to the module's targets table is derived by
    ``TableDerivedConstraintsMixin``.
    """

    __target_tablename__: ClassVar[str]
    __table_args__ = (
        TabledFk("target_id", target_attr="__target_tablename__"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    name: str = Field(index=True, max_length=255)

    target_id: str = Field(index=True)

    analysis_system_id: int | None = Field(default=None)

    context_notes: str = Field(default="", sa_type=Text, sa_column_kwargs={"nullable": True})
    status: str = Field(default="created", index=True, max_length=32)
    created_by: str | None = Field(default=None, index=True, max_length=64)
    budget_json: str = Field(default="{}", sa_type=Text, sa_column_kwargs={"nullable": True})
    obligations_json: str = Field(default="{}", sa_type=Text, sa_column_kwargs={"nullable": True})

    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class ProjectSummaryBase(BaseModel):
    """Shared read-only project projection.

    Modules narrow ``status`` to their ``*ProjectStatus`` StrEnum on the
    concrete subclass and add module-specific fields (vr: ``cve_id``,
    ``patched_target_id``, ``poc_system_id``, ``latest_disclosure_status``,
    ``disclosure_submission_count``).
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    status: str
    workspace_id: str | None = None
    target_id: str | None = None
    finding_count: int = 0
    operator_id: str | None = None
    created_at: str | None = None
    analysis_system_id: int | None = None
