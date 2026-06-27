"""Fuzzing campaign + crash tables (Fuzzing plan)."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

__all__ = ["VRFuzzCampaignRecord", "VRFuzzCrashRecord"]


class VRFuzzCampaignRecord(TeamScopedMixin, SQLModel, table=True):
    """One fuzzing campaign -- long-running, may produce many crashes."""

    __tablename__ = "vr_fuzz_campaigns"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
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

    name: str = Field(max_length=255, index=True)
    engine_id: str = Field(max_length=64, index=True)
    strategy_id: str = Field(max_length=64, index=True)
    engine_config_json: str = Field(default="{}", sa_column=Column(Text))
    strategy_config_json: str = Field(default="{}", sa_column=Column(Text))

    status: str = Field(default="created", max_length=24, index=True)
    duration_hours: int | None = Field(default=None)
    analysis_system_id: int | None = Field(default=None, index=True)
    remote_pid: int | None = Field(default=None)
    remote_corpus_dir: str | None = Field(default=None, max_length=1024)
    remote_crashes_dir: str | None = Field(default=None, max_length=1024)
    launched_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    launch_log: str | None = Field(default=None, sa_column=Column(Text, nullable=True))

    execs_per_sec: float | None = Field(default=None)
    total_execs: int = Field(default=0)
    corpus_size: int = Field(default=0)
    coverage_pct: float | None = Field(default=None)
    crashes_found: int = Field(default=0)

    started_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    stopped_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    last_progress_at: datetime | None = Field(
        default=None, sa_type=DateTime(timezone=True),
    )

    notes: str = Field(default="", sa_column=Column(Text))

    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )
    updated_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )


class VRFuzzCrashRecord(TeamScopedMixin, SQLModel, table=True):
    """One crash discovered by a campaign.

    Dedup by (campaign_id, stack_hash) -- a crash with the same stack
    hash is registered as DUPLICATE pointing at the earliest matching
    crash. Operator promotes to vr_findings explicitly.
    """

    __tablename__ = "vr_fuzz_crashes"
    __table_args__ = (
        UniqueConstraint(
            "campaign_id", "stack_hash",
            name="uq_vr_fuzz_crashes_campaign_stack",
        ),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    campaign_id: str = Field(
        sa_column=Column(
            "campaign_id",
            ForeignKey("vr_fuzz_campaigns.id"),
            nullable=False,
            index=True,
        ),
    )

    stack_hash: str = Field(max_length=128, index=True)
    crash_type: str | None = Field(default=None, max_length=64, index=True)
    crash_signature: str | None = Field(default=None, max_length=512)
    severity: str = Field(default="unknown", max_length=16, index=True)

    triage_verdict: str = Field(default="untriaged", max_length=32, index=True)
    triage_reason: str | None = Field(default=None, max_length=512)
    duplicate_of_crash_id: str | None = Field(
        default=None, max_length=64, index=True,
    )
    promoted_to_finding_id: str | None = Field(
        default=None, max_length=64, index=True,
    )

    reproducer_path: str | None = Field(default=None, max_length=1024)
    reproducer_size_bytes: int | None = Field(default=None)
    stack_trace: str | None = Field(default=None, sa_column=Column(Text))
    extra_json: str = Field(default="{}", sa_column=Column(Text))
    reproducer_head_hex: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    reproducer_head_truncated_size: int | None = Field(default=None)
    llm_summary: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    triage_chain_json: str = Field(default="[]", sa_column=Column(Text))

    discovered_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True), index=True,
    )
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )
    updated_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )
