"""Platform-owned durable event streams and transactional outbox records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Column, DateTime, Index, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel

from ..platform.contracts import JsonObject, utc_now
from .mixins import TeamScopedMixin

__all__ = [
    "EventEnvelope",
    "EventOutboxRecord",
    "EventStreamRecord",
]


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    """Authoritative event representation returned by PostgreSQL replay."""

    event_id: str
    stream_id: str
    sequence: int
    event_type: str
    payload: JsonObject
    created_at: datetime


class EventStreamRecord(TeamScopedMixin, SQLModel, table=True):
    """A stream identity and its transactionally allocated last sequence."""

    __tablename__ = "platform_event_streams"

    id: str = Field(primary_key=True)
    module_id: str = Field(index=True)
    last_sequence: int = Field(default=0, sa_type=BigInteger)
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
    )


class EventOutboxRecord(TeamScopedMixin, SQLModel, table=True):
    """Retained event payload plus its at-least-once relay publication state."""

    __tablename__ = "platform_event_outbox"
    __table_args__ = (
        UniqueConstraint(
            "stream_id",
            "sequence",
            name="uq_platform_event_outbox_stream_sequence",
        ),
        Index(
            "ix_platform_event_outbox_unpublished",
            "published_at",
            "stream_id",
            "sequence",
        ),
    )

    event_id: str = Field(primary_key=True)
    stream_id: str = Field(foreign_key="platform_event_streams.id")
    module_id: str = Field(index=True)
    sequence: int = Field(sa_type=BigInteger)
    event_type: str
    payload: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSONB, nullable=False),
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
    )
    published_at: datetime | None = Field(
        default=None,
        sa_type=DateTime(timezone=True),
    )
