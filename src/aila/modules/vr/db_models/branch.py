"""Investigation branch table definition (M3.R-1).

Per D-41: each branch carries its own ReasoningCaseState snapshot in
``case_state_json``. ``parent_branch_id`` builds the branch tree.
``merged_into_branch_id`` records the consolidation target when a
branch merges into a sibling.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts import utc_now

__all__ = ["VRInvestigationBranchRecord"]


class VRInvestigationBranchRecord(SQLModel, table=True):
    """One branch within an investigation (D-41)."""

    __tablename__ = "vr_investigation_branches"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    investigation_id: str = Field(
        sa_column=Column(
            "investigation_id",
            ForeignKey("vr_investigations.id"),
            nullable=False,
            index=True,
        ),
    )
    parent_branch_id: str | None = Field(
        default=None,
        sa_column=Column(
            "parent_branch_id",
            ForeignKey("vr_investigation_branches.id"),
            nullable=True,
            index=True,
        ),
    )
    merged_into_branch_id: str | None = Field(
        default=None,
        sa_column=Column(
            "merged_into_branch_id",
            ForeignKey("vr_investigation_branches.id"),
            nullable=True,
            index=True,
        ),
    )

    status: str = Field(default="active", index=True, max_length=32)
    # fix §180 -- NOT NULL with structural-marker default. Backfilled and
    # tightened by migration ``064_vr_branch_persona_voice_not_null``.
    # Python writers (§177/§178) always supply a real value; the default
    # is a defensive net for schema-bypass INSERTs.
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
