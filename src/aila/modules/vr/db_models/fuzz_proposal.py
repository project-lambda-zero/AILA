"""Fuzz campaign proposal table -- operator-in-the-loop with full
pre-fuzz prep (D-37 + audit-first reasoning model).

The reasoning agent prepares EVERYTHING needed to fuzz before
asking the operator. The operator clicks Approve; AILA's
ProposalPreparer SSHes the workstation, writes the harness +
seeds + dict, runs the build, materializes the campaign row, and
optionally launches.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts import utc_now
from aila.storage.mixins import TeamScopedMixin

__all__ = ["VRFuzzCampaignProposalRecord"]


class VRFuzzCampaignProposalRecord(TeamScopedMixin, SQLModel, table=True):
    """One fuzz-campaign proposal pending operator decision."""

    __tablename__ = "vr_fuzz_campaign_proposals"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    investigation_id: str = Field(
        sa_column=Column(
            "investigation_id",
            ForeignKey("vr_investigations.id"),
            nullable=False,
            index=True,
        ),
    )
    outcome_id: str = Field(
        sa_column=Column(
            "outcome_id",
            ForeignKey("vr_investigation_outcomes.id"),
            nullable=False,
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
    workspace_id: str = Field(
        sa_column=Column(
            "workspace_id",
            ForeignKey("vr_workspaces.id"),
            nullable=False,
            index=True,
        ),
    )

    profile: str = Field(max_length=128)
    rationale: str = Field(default="", sa_column=Column(Text))
    confidence: str = Field(default="medium", max_length=24)
    target_descriptor_json: str = Field(
        default="{}", sa_column=Column(Text),
    )

    # Suggested campaign config (operator can override on accept).
    suggested_engine_id: str | None = Field(default=None, max_length=32)
    suggested_engine_config_json: str = Field(
        default="{}", sa_column=Column(Text),
    )
    suggested_strategy_id: str | None = Field(default=None, max_length=32)
    suggested_duration_hours: int | None = Field(default=None)

    # PRE-FUZZ PREP authored by the reasoning agent.
    harness_source: str | None = Field(
        default=None, sa_column=Column(Text, nullable=True),
    )
    harness_language: str | None = Field(default=None, max_length=16)
    harness_build_command: str | None = Field(
        default=None, sa_column=Column(Text, nullable=True),
    )
    harness_target_path: str | None = Field(default=None, max_length=1024)
    seed_corpus_json: str = Field(default="[]", sa_column=Column(Text))
    dictionary_content: str | None = Field(
        default=None, sa_column=Column(Text, nullable=True),
    )

    # Lifecycle.
    status: str = Field(default="pending", max_length=24, index=True)
    accepted_campaign_id: str | None = Field(
        default=None,
        sa_column=Column(
            "accepted_campaign_id",
            ForeignKey("vr_fuzz_campaigns.id"),
            nullable=True,
        ),
    )
    decided_at: datetime | None = Field(
        default=None,
        sa_type=DateTime(timezone=True),
    )
    decided_by: str | None = Field(default=None, max_length=64)
    decision_reason: str | None = Field(
        default=None, sa_column=Column(Text, nullable=True),
    )
    prepare_log: str | None = Field(
        default=None, sa_column=Column(Text, nullable=True),
    )

    created_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
    )
