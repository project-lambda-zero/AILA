"""Branch record + contract bases shared by the investigation engine (RFC-01).

Zero-domain table: the vr and malware branch tables carry the same 14 columns.
A concrete module branch collapses to::

    class VRInvestigationBranchRecord(BranchRecordBase, table=True):
        __tablename__ = "vr_investigation_branches"
        __investigation_tablename__ = "vr_investigations"

The FK columns are plain fields on the base; ``TableDerivedConstraintsMixin``
derives the ForeignKeyConstraints (investigation_id -> the module's
investigation table, parent/merged -> the module's own branch table) from the
subclass tablename class vars.
"""
from __future__ import annotations

from datetime import datetime
from typing import ClassVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from ._common import utc_now
from ._naming import TableDerivedConstraintsMixin, TabledFk
from .enums import BranchStatus, PersonaVoice

__all__ = ["BranchRecordBase", "BranchSummaryBase"]


class BranchRecordBase(TableDerivedConstraintsMixin, SQLModel):
    """Shared columns for every module's investigation-branch table (D-41).

    A concrete subclass MUST set ``__tablename__``, ``__investigation_tablename__``,
    and ``table=True``.
    """

    __investigation_tablename__: ClassVar[str]
    __table_args__ = (
        TabledFk("investigation_id", target_attr="__investigation_tablename__"),
        TabledFk("parent_branch_id"),
        TabledFk("merged_into_branch_id"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    investigation_id: str = Field(index=True)
    parent_branch_id: str | None = Field(default=None, index=True)
    merged_into_branch_id: str | None = Field(default=None, index=True)

    status: str = Field(default="active", index=True, max_length=32)
    # persona_voice is stored as a plain string, NOT NULL with a structural
    # marker default; migration 064 backfilled and tightened it. Python
    # writers always supply a real value.
    persona_voice: str = Field(default="unspecified", max_length=32, nullable=False)
    strategy_family: str | None = Field(default=None, max_length=128, index=True)
    fork_reason: str = Field(default="", sa_column=Column(Text))
    fork_at_turn: int | None = Field(default=None)

    case_state_json: str = Field(default="{}", sa_column=Column(Text))
    branch_cost_usd: float = Field(default=0.0)
    turn_count: int = Field(default=0)

    closed_reason: str = Field(default="", sa_column=Column(Text))
    promoted: bool = Field(default=False)
    closed_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))

    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class BranchSummaryBase(BaseModel):
    """Shared read-only projection of one branch within an investigation."""

    model_config = ConfigDict(extra="forbid")

    id: str
    investigation_id: str
    parent_branch_id: str | None = None
    status: BranchStatus
    persona_voice: PersonaVoice | None = None
    fork_reason: str = ""
    fork_at_turn: int | None = None
    turn_count: int = 0
    branch_cost_usd: float = 0.0
    closed_reason: str = ""
    merged_into_branch_id: str | None = None
    promoted: bool = False
    closed_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    strategy_family: str | None = None
    cursor_state: str | None = None
    cursor_archived_state: str | None = None
