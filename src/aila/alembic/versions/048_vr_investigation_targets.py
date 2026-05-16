"""048 — vr_investigation_targets join table (v0.4 GA-49).

Multi-target investigation support. An investigation has one primary
target in vr_investigations.target_id (unchanged) PLUS optional
secondary targets attached via this M:N join with a role column.

Revision ID: 048_vr_investigation_targets
Revises: 047_vr_fuzz
Create Date: 2026-05-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "048_vr_investigation_targets"
down_revision: str | None = "047_vr_fuzz"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vr_investigation_targets",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("team_id", sa.Text(), nullable=True),
        sa.Column(
            "investigation_id", sa.String(64),
            sa.ForeignKey("vr_investigations.id"), nullable=False,
        ),
        sa.Column(
            "target_id", sa.String(64),
            sa.ForeignKey("vr_targets.id"), nullable=False,
        ),
        sa.Column("role", sa.String(32), nullable=False, server_default="comparison"),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "attached_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "investigation_id", "target_id",
            name="uq_vr_investigation_target",
        ),
    )
    op.create_index(
        "ix_vr_investigation_targets_team_id",
        "vr_investigation_targets", ["team_id"],
    )
    op.create_index(
        "ix_vr_investigation_targets_investigation_id",
        "vr_investigation_targets", ["investigation_id"],
    )
    op.create_index(
        "ix_vr_investigation_targets_target_id",
        "vr_investigation_targets", ["target_id"],
    )
    op.create_index(
        "ix_vr_investigation_targets_role",
        "vr_investigation_targets", ["role"],
    )


def downgrade() -> None:
    for ix in (
        "ix_vr_investigation_targets_role",
        "ix_vr_investigation_targets_target_id",
        "ix_vr_investigation_targets_investigation_id",
        "ix_vr_investigation_targets_team_id",
    ):
        op.drop_index(ix, table_name="vr_investigation_targets")
    op.drop_table("vr_investigation_targets")
