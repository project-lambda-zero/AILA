"""CVE record table (v0.4 GA-51).

vr_cve_records -- one row per CVE (NVD / GHSA / MITRE / manual), written by
the VR CVE ingest endpoint.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from aila.platform.contracts import utc_now

__all__ = ["VRCVERecord"]


class VRCVERecord(SQLModel, table=True):
    """One ingested CVE record."""

    __tablename__ = "vr_cve_records"
    __table_args__ = (
        UniqueConstraint("cve_id", name="uq_vr_cve_records_cve_id"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    cve_id: str = Field(max_length=32, index=True)
    source: str = Field(max_length=16, index=True)
    title: str = Field(default="", max_length=512)
    description: str = Field(default="", sa_column=Column(Text))

    published_at: datetime | None = Field(
        default=None, sa_type=DateTime(timezone=True), index=True,
    )
    last_modified_at: datetime | None = Field(
        default=None, sa_type=DateTime(timezone=True),
    )

    cvss_score: float | None = Field(default=None, index=True)
    cwe_ids_json: str = Field(default="[]", sa_column=Column(Text))
    references_json: str = Field(default="[]", sa_column=Column(Text))
    affected_components_json: str = Field(default="[]", sa_column=Column(Text))

    raw_payload_json: str = Field(default="{}", sa_column=Column(Text))

    # Number of audit memos flagged as potentially invalidated by this CVE.
    invalidations_triggered: int = Field(default=0)

    ingested_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True), index=True,
    )
