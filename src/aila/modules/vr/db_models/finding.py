"""Finding table definition for the vulnerability research module."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Float, ForeignKey, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now

__all__ = ["VRFindingRecord"]


class VRFindingRecord(SQLModel, table=True):
    """A single vulnerability finding produced by the VR module.

    Written by: vr.crash_triage tool, vr.state_validate workflow state.
    Consumed by: advisory builder, disclosure tracker, dashboard.

    A finding is the durable artifact of a confirmed crash or vulnerability:
    triage metadata (signature, root cause, vulnerable function), reproduction
    evidence (PoC code, ASAN report), classification (CVSS, CWE), and
    coordinated-disclosure tracking. Free-form structured payloads (advisory
    body, evidence references) are stored as JSON text so the Pydantic
    contracts in ``contracts/finding.py`` and ``contracts/advisory.py`` remain
    the source of truth for shape.
    """

    __tablename__ = "vr_findings"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str | None = Field(default=None, index=True, max_length=64)
    target_id: str | None = Field(
        default=None,
        sa_column=Column(
            "target_id",
            ForeignKey("vr_targets.id"),
            nullable=True,
            index=True,
        ),
    )
    team_id: str | None = Field(default=None, index=True)
    crash_type: str | None = Field(default=None, index=True, max_length=64)
    crash_signature: str | None = Field(default=None, max_length=128)
    root_cause: str = Field(default="", sa_column=Column(Text))
    vulnerable_function: str | None = Field(default=None, max_length=255)
    poc_code: str | None = Field(default=None, sa_column=Column(Text))
    poc_language: str | None = Field(default=None, max_length=32)
    poc_reliability: str | None = Field(default=None, max_length=16)
    asan_report: str | None = Field(default=None, sa_column=Column(Text))
    cvss_vector: str | None = Field(default=None, max_length=128)
    cvss_score: float | None = Field(default=None, sa_column=Column(Float))
    cwe_id: str | None = Field(default=None, max_length=16)
    advisory_json: str = Field(default="{}", sa_column=Column(Text))
    # Coordinated-disclosure tracking — these mutate over the disclosure timeline.
    disclosure_status: str = Field(default="undisclosed", index=True, max_length=32)
    vendor_contact: str | None = Field(default=None, sa_column=Column(Text))
    reported_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    embargo_until: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    assigned_cve_id: str | None = Field(default=None, max_length=32)
    patch_version: str | None = Field(default=None, max_length=64)
    # Evidence references (artifact ids, file hashes) and obligation snapshot.
    evidence_refs_json: str = Field(default="[]", sa_column=Column(Text))
    obligations_json: str = Field(default="{}", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
