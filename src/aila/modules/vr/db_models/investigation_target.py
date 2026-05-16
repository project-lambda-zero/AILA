"""vr_investigation_targets join table (v0.4 multi-target).

Many-to-many between vr_investigations and vr_targets with a role
column. Primary target stays redundant in vr_investigations.target_id
for backward compatibility + cost attribution.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

__all__ = ["VRInvestigationTargetRecord"]


class VRInvestigationTargetRecord(TeamScopedMixin, SQLModel, table=True):
    """One (investigation, target, role) attachment."""

    __tablename__ = "vr_investigation_targets"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id", "target_id",
            name="uq_vr_investigation_target",
        ),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)

    investigation_id: str = Field(
        sa_column=Column(
            "investigation_id",
            ForeignKey("vr_investigations.id"),
            nullable=False,
            index=True,
        ),
    )
    target_id: str = Field(
        sa_column=Column(
            "target_id",
            ForeignKey("vr_targets.id"),
            nullable=False,
            index=True,
        ),
    )
    role: str = Field(default="comparison", max_length=32, index=True)
    rationale: str = Field(default="", sa_column=Column(Text))

    attached_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
    )
