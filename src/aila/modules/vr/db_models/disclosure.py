"""Disclosure submission table (Disclosure Lifecycle plan).

One row per (finding, track) tuple. The same finding may be disclosed
through multiple tracks in parallel (chrome_vrp + blog_post + CVE
assignment); each is its own submission with its own lifecycle.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

__all__ = ["VRDisclosureSubmissionRecord"]


class VRDisclosureSubmissionRecord(TeamScopedMixin, SQLModel, table=True):
    """One submission of one finding through one disclosure track."""

    __tablename__ = "vr_disclosure_submissions"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)

    finding_id: str = Field(
        sa_column=Column(
            "finding_id",
            ForeignKey("vr_findings.id"),
            nullable=False,
            index=True,
        ),
    )
    workspace_id: str = Field(
        sa_column=Column(
            "workspace_id",
            ForeignKey("vr_workspaces.id"),
            nullable=False,
            index=True,
        ),
    )
    track_id: str = Field(max_length=64, index=True)
    kind: str = Field(max_length=32, index=True)

    status: str = Field(default="drafted", max_length=24, index=True)
    poc_tier: str = Field(default="no_poc", max_length=24)
    severity_rating: str | None = Field(default=None, max_length=64)
    embargo_days_used: int | None = Field(default=None)
    embargo_until: datetime | None = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        index=True,
    )

    vendor_reference: str | None = Field(default=None, max_length=128, index=True)
    bounty_awarded_usd: float | None = Field(default=None)

    rendered_submission_body: str | None = Field(
        default=None,
        sa_column=Column(Text, nullable=True),
    )
    rendered_submission_format: str = Field(default="markdown", max_length=16)
    last_rendered_at: datetime | None = Field(
        default=None,
        sa_type=DateTime(timezone=True),
    )
    rendered_submission_metadata_json: str = Field(
        default="{}",
        sa_column=Column(Text),
    )

    notes: str = Field(default="", sa_column=Column(Text))
    validation_errors_json: str = Field(default="[]", sa_column=Column(Text))

    created_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
    )
