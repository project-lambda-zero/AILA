"""054 -- replace vr_fuzz_campaigns.workstation_host (free-text) with
analysis_system_id (FK to managedsystemrecord.id).

Architectural correctness fix. `workstation_host` was a string label
with no link to the platform's `ManagedSystemRecord` table -- the
operator had no way to pick a registered rig from the UI, AILA could
not SSH into it, and the campaign's workstation was effectively
opaque. The FK makes the workstation a first-class entity: the
campaign points at the same row the project's `analysis_system_id`
points at, the SSH bridge can reach it, and the heartbeat /
compatibility surfaces work uniformly.

Destructive: drops `workstation_host`. No production users per
CLAUDE.md (single-tenant dev), so we don't bother backfilling -- any
existing free-text values would not resolve to a `ManagedSystemRecord`
id anyway.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "054_vr_campaign_system_fk"
down_revision: str | None = "053_vr_v05_closure"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vr_fuzz_campaigns",
        sa.Column(
            "analysis_system_id",
            sa.Integer(),
            sa.ForeignKey("managedsystemrecord.id"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_vr_fuzz_campaigns_analysis_system_id",
        "vr_fuzz_campaigns",
        ["analysis_system_id"],
    )
    op.drop_index(
        "ix_vr_fuzz_campaigns_workstation_host", "vr_fuzz_campaigns",
    )
    op.drop_column("vr_fuzz_campaigns", "workstation_host")

    # Launch / report bookkeeping for the new launcher endpoint.
    op.add_column(
        "vr_fuzz_campaigns",
        sa.Column("remote_pid", sa.Integer(), nullable=True),
    )
    op.add_column(
        "vr_fuzz_campaigns",
        sa.Column("remote_corpus_dir", sa.String(length=1024), nullable=True),
    )
    op.add_column(
        "vr_fuzz_campaigns",
        sa.Column("remote_crashes_dir", sa.String(length=1024), nullable=True),
    )
    op.add_column(
        "vr_fuzz_campaigns",
        sa.Column("launched_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "vr_fuzz_campaigns",
        sa.Column("launch_log", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vr_fuzz_campaigns", "launch_log")
    op.drop_column("vr_fuzz_campaigns", "launched_at")
    op.drop_column("vr_fuzz_campaigns", "remote_crashes_dir")
    op.drop_column("vr_fuzz_campaigns", "remote_corpus_dir")
    op.drop_column("vr_fuzz_campaigns", "remote_pid")
    op.drop_index(
        "ix_vr_fuzz_campaigns_analysis_system_id", "vr_fuzz_campaigns",
    )
    op.drop_column("vr_fuzz_campaigns", "analysis_system_id")
    op.add_column(
        "vr_fuzz_campaigns",
        sa.Column("workstation_host", sa.String(length=255), nullable=True),
    )
    op.create_index(
        "ix_vr_fuzz_campaigns_workstation_host",
        "vr_fuzz_campaigns",
        ["workstation_host"],
    )
