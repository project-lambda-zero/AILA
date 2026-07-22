"""Investigation message table definition (M3.R-1).

Per D-43: conversational UX -- operator + engine exchange typed messages.
The shared columns live on the platform base (RFC-01); this module sets the
concrete table + foreign-key target names and preserves the VR-specific
composite Index on (investigation_id, auto_steering_key) used by the
auto_steering exact-key dedup lookup.
"""
from __future__ import annotations

from typing import ClassVar

from sqlalchemy import Index

from aila.platform.contracts.message_base import MessageRecordBase

__all__ = ["VRInvestigationMessageRecord"]


class VRInvestigationMessageRecord(MessageRecordBase, table=True):
    """One message in an investigation conversation."""

    __tablename__ = "vr_investigation_messages"
    __investigation_tablename__: ClassVar[str] = "vr_investigations"
    __branch_tablename__: ClassVar[str] = "vr_investigation_branches"

    # Migration 063 built a composite index on (investigation_id,
    # auto_steering_key) for the dedup lookup, not a single-column index
    # on auto_steering_key. Declare it here so create_all (tests, fresh
    # installs) matches the migrated production shape. The partial
    # UNIQUE constraint from 063 is not modelled on the SQLModel side
    # (partial unique is enforced only in migrations).
    __table_args__ = (
        *MessageRecordBase.__table_args__,
        Index(
            "ix_vr_investigation_messages_auto_steering_key",
            "investigation_id",
            "auto_steering_key",
        ),
    )
