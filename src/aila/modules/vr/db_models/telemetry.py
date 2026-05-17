"""Fuzz campaign telemetry table (08_FRONTEND_UX.md §1.5).

One row per measurement collected during a fuzz campaign. Workers
POST a measurement every N seconds; the UI reads back the series to
render coverage / exec-rate sparklines and detect "stuck" campaigns
(no progress in 4 h).
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now

__all__ = ["VRFuzzTelemetryRecord"]


class VRFuzzTelemetryRecord(SQLModel, table=True):
    """One time-series measurement for one fuzz campaign."""

    __tablename__ = "vr_fuzz_telemetry"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    campaign_id: str = Field(
        sa_column=Column(
            "campaign_id",
            ForeignKey("vr_fuzz_campaigns.id"),
            nullable=False,
            index=True,
        ),
    )
    measured_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
        index=True,
    )
    execs_per_sec: float | None = Field(default=None)
    total_execs: int | None = Field(default=None, sa_column=Column(BigInteger, nullable=True))
    corpus_size: int | None = Field(default=None)
    coverage_pct: float | None = Field(default=None)
    crashes_found: int | None = Field(default=None)
