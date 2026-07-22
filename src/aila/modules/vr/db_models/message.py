"""Investigation message table definition (M3.R-1).

Per D-43: conversational UX -- operator + engine exchange typed
messages. Each message has a payload_kind matching one of the 10
D-44 typed payloads; payload itself is a JSON dict (per-kind shape
validated by the renderer / dispatcher, not at the DB layer).
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now

__all__ = ["VRInvestigationMessageRecord"]


class VRInvestigationMessageRecord(SQLModel, table=True):
    """One message in an investigation conversation."""

    __tablename__ = "vr_investigation_messages"
    # Migration 063 built a composite index on (investigation_id,
    # auto_steering_key) for the dedup lookup, not a single-column index
    # on auto_steering_key. Declare it here so create_all (tests, fresh
    # installs) matches the migrated production shape. The partial
    # UNIQUE constraint from 063 is not modelled on the SQLModel side
    # (partial unique is enforced only in migrations).
    __table_args__ = (
        Index(
            "ix_vr_investigation_messages_auto_steering_key",
            "investigation_id",
            "auto_steering_key",
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
    branch_id: str = Field(
        sa_column=Column(
            "branch_id",
            ForeignKey("vr_investigation_branches.id"),
            nullable=False,
            index=True,
        ),
    )

    sender_kind: str = Field(max_length=16)  # engine|operator
    sender_id: str | None = Field(default=None, max_length=64)
    payload_kind: str = Field(max_length=32, index=True)
    payload_json: str = Field(default="{}", sa_column=Column(Text))
    operator_intent: str | None = Field(default=None, max_length=32)
    at_turn: int | None = Field(default=None)
    evidence_refs_json: str = Field(default="[]", sa_column=Column(Text))
    # Exact-key dedup for auto_steering rows (§331/§332/§338). NULL on
    # every non-auto_steering message. Composite index +
    # partial-UNIQUE built in migration 063 (see __table_args__).
    auto_steering_key: str | None = Field(
        default=None, max_length=128,
    )

    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True), index=True,
    )
