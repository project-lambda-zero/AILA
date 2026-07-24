"""Message record + contract bases shared by the investigation engine (RFC-01).

Zero-domain table, NOT TeamScoped -- messages inherit their team scope from
the investigation they belong to. A concrete module message collapses to::

    class VRInvestigationMessageRecord(MessageRecordBase, table=True):
        __tablename__ = "vr_investigation_messages"
        __investigation_tablename__ = "vr_investigations"
        __branch_tablename__ = "vr_investigation_branches"

The FK columns are plain fields on the base; ``TableDerivedConstraintsMixin``
derives the ForeignKeyConstraints (investigation_id -> the module's
investigation table, branch_id -> the module's branch table) from the
subclass tablename class vars.

Module-specific residue held by the concrete subclass:

* ``acked_at`` (malware only, migration 070 -- operator-side ACK timestamp
  consumed by the malware agent's ``_consume_pending_operator_messages``)

Module-specific INDEX shape held by the concrete subclass:

* vr builds a composite ``(investigation_id, auto_steering_key)`` Index
* malware indexes ``auto_steering_key`` as a full-column index

Neither is expressible in a single shared base column definition, so
``auto_steering_key`` is declared here without ``index=True`` and each
subclass adds its own ``__table_args__`` entry.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from pydantic import Field as PField
from sqlalchemy import DateTime, Text
from sqlmodel import Field, SQLModel

from ._common import utc_now
from ._naming import TableDerivedConstraintsMixin, TabledFk
from .enums import OperatorIntent, SenderKind
from .mcp_payload import PayloadKind

__all__ = [
    "MessageCreateBase",
    "MessageRecordBase",
    "MessageSummaryBase",
]


class MessageRecordBase(TableDerivedConstraintsMixin, SQLModel):
    """Shared columns for every module's investigation-message table (D-43).

    A concrete subclass MUST set ``__tablename__``, ``__investigation_tablename__``,
    ``__branch_tablename__``, and ``table=True``.
    """

    __investigation_tablename__: ClassVar[str]
    __branch_tablename__: ClassVar[str]
    __table_args__ = (
        TabledFk("investigation_id", target_attr="__investigation_tablename__"),
        TabledFk("branch_id", target_attr="__branch_tablename__"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    investigation_id: str = Field(index=True)
    branch_id: str = Field(index=True)

    sender_kind: str = Field(max_length=16)  # engine|operator|system
    sender_id: str | None = Field(default=None, max_length=64)
    payload_kind: str = Field(max_length=32, index=True)
    payload_json: str = Field(default="{}", sa_type=Text, sa_column_kwargs={"nullable": True})
    operator_intent: str | None = Field(default=None, max_length=32)
    at_turn: int | None = Field(default=None)
    evidence_refs_json: str = Field(default="[]", sa_type=Text, sa_column_kwargs={"nullable": True})
    # Exact-key dedup for auto_steering rows. Index shape differs per module
    # (vr = composite (investigation_id, auto_steering_key); malware =
    # full-column index). The subclass carries the module-specific Index in
    # its own __table_args__; the base column stays plain.
    auto_steering_key: str | None = Field(default=None, max_length=128)

    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True), index=True,
    )


class MessageSummaryBase(BaseModel):
    """Read-only projection of one message.

    The ``payload`` dict shape depends on ``payload_kind`` and is rendered by
    the frontend per-kind. Evidence refs are AgentStepRecord IDs supporting
    the message's claims.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    investigation_id: str
    branch_id: str
    sender_kind: SenderKind
    sender_id: str | None = None
    payload_kind: PayloadKind
    payload: dict[str, Any] = PField(default_factory=dict)
    operator_intent: OperatorIntent | None = None
    at_turn: int | None = None
    evidence_refs: list[str] = PField(default_factory=list)
    created_at: datetime | None = None


class MessageCreateBase(BaseModel):
    """Input payload for an operator-sent message.

    Engine messages are NOT created via this API -- they emit from the
    reasoning loop directly. This shape is operator-only.
    """

    model_config = ConfigDict(extra="forbid")

    branch_id: str | None = PField(
        default=None,
        description=(
            "Branch context for the message. When None, applies to the "
            "investigation's primary branch."
        ),
    )
    text: str = PField(
        min_length=1,
        description="Free-form operator input. Engine classifies intent.",
    )
    explicit_intent: OperatorIntent | None = PField(
        default=None,
        description="When set, skip auto-classification and use this intent directly.",
    )
