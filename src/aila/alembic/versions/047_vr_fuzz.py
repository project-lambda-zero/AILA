"""047 -- VR fuzzing campaigns + crashes (Fuzzing plan).

Adds two new tables:
  vr_fuzz_campaigns  -- one long-running campaign per (target, engine, strategy)
  vr_fuzz_crashes    -- one crash per (campaign, stack_hash); dedup enforced

Revision ID: 047_vr_fuzz
Revises: 046_vr_disclosure_submissions
Create Date: 2026-05-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "047_vr_fuzz"
down_revision: str | None = "046_vr_disclosure_submissions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vr_fuzz_campaigns",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("team_id", sa.Text(), nullable=True),
        sa.Column(
            "target_id", sa.String(64),
            sa.ForeignKey("vr_targets.id"), nullable=False,
        ),
        sa.Column(
            "workspace_id", sa.String(64),
            sa.ForeignKey("vr_workspaces.id"), nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("engine_id", sa.String(64), nullable=False),
        sa.Column("strategy_id", sa.String(64), nullable=False),
        sa.Column("engine_config_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("strategy_config_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("status", sa.String(24), nullable=False, server_default="created"),
        sa.Column("duration_hours", sa.Integer(), nullable=True),
        sa.Column("workstation_host", sa.String(255), nullable=True),
        sa.Column("execs_per_sec", sa.Float(), nullable=True),
        sa.Column("total_execs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("corpus_size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("coverage_pct", sa.Float(), nullable=True),
        sa.Column("crashes_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stopped_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_progress_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
    )
    for ix in (
        ("ix_vr_fuzz_campaigns_team_id", ["team_id"]),
        ("ix_vr_fuzz_campaigns_target_id", ["target_id"]),
        ("ix_vr_fuzz_campaigns_workspace_id", ["workspace_id"]),
        ("ix_vr_fuzz_campaigns_name", ["name"]),
        ("ix_vr_fuzz_campaigns_engine_id", ["engine_id"]),
        ("ix_vr_fuzz_campaigns_strategy_id", ["strategy_id"]),
        ("ix_vr_fuzz_campaigns_status", ["status"]),
        ("ix_vr_fuzz_campaigns_workstation_host", ["workstation_host"]),
    ):
        op.create_index(ix[0], "vr_fuzz_campaigns", ix[1])

    op.create_table(
        "vr_fuzz_crashes",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("team_id", sa.Text(), nullable=True),
        sa.Column(
            "campaign_id", sa.String(64),
            sa.ForeignKey("vr_fuzz_campaigns.id"), nullable=False,
        ),
        sa.Column("stack_hash", sa.String(128), nullable=False),
        sa.Column("crash_type", sa.String(64), nullable=True),
        sa.Column("crash_signature", sa.String(512), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default="unknown"),
        sa.Column(
            "triage_verdict", sa.String(32),
            nullable=False, server_default="untriaged",
        ),
        sa.Column("triage_reason", sa.String(512), nullable=True),
        sa.Column("duplicate_of_crash_id", sa.String(64), nullable=True),
        sa.Column("promoted_to_finding_id", sa.String(64), nullable=True),
        sa.Column("reproducer_path", sa.String(1024), nullable=True),
        sa.Column("reproducer_size_bytes", sa.Integer(), nullable=True),
        sa.Column("stack_trace", sa.Text(), nullable=True),
        sa.Column("extra_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column(
            "discovered_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "campaign_id", "stack_hash",
            name="uq_vr_fuzz_crashes_campaign_stack",
        ),
    )
    for ix in (
        ("ix_vr_fuzz_crashes_team_id", ["team_id"]),
        ("ix_vr_fuzz_crashes_campaign_id", ["campaign_id"]),
        ("ix_vr_fuzz_crashes_stack_hash", ["stack_hash"]),
        ("ix_vr_fuzz_crashes_crash_type", ["crash_type"]),
        ("ix_vr_fuzz_crashes_severity", ["severity"]),
        ("ix_vr_fuzz_crashes_triage_verdict", ["triage_verdict"]),
        ("ix_vr_fuzz_crashes_duplicate_of_crash_id", ["duplicate_of_crash_id"]),
        ("ix_vr_fuzz_crashes_promoted_to_finding_id", ["promoted_to_finding_id"]),
        ("ix_vr_fuzz_crashes_discovered_at", ["discovered_at"]),
    ):
        op.create_index(ix[0], "vr_fuzz_crashes", ix[1])


def downgrade() -> None:
    for ix in (
        "ix_vr_fuzz_crashes_discovered_at",
        "ix_vr_fuzz_crashes_promoted_to_finding_id",
        "ix_vr_fuzz_crashes_duplicate_of_crash_id",
        "ix_vr_fuzz_crashes_triage_verdict",
        "ix_vr_fuzz_crashes_severity",
        "ix_vr_fuzz_crashes_crash_type",
        "ix_vr_fuzz_crashes_stack_hash",
        "ix_vr_fuzz_crashes_campaign_id",
        "ix_vr_fuzz_crashes_team_id",
    ):
        op.drop_index(ix, table_name="vr_fuzz_crashes")
    op.drop_table("vr_fuzz_crashes")
    for ix in (
        "ix_vr_fuzz_campaigns_workstation_host",
        "ix_vr_fuzz_campaigns_status",
        "ix_vr_fuzz_campaigns_strategy_id",
        "ix_vr_fuzz_campaigns_engine_id",
        "ix_vr_fuzz_campaigns_name",
        "ix_vr_fuzz_campaigns_workspace_id",
        "ix_vr_fuzz_campaigns_target_id",
        "ix_vr_fuzz_campaigns_team_id",
    ):
        op.drop_index(ix, table_name="vr_fuzz_campaigns")
    op.drop_table("vr_fuzz_campaigns")
