"""038 -- add reasoning_graph_snapshots platform table.

Durable storage for platform-owned reasoning/evidence graph snapshots emitted
per turn by reasoning-engine consumers (starting with forensics freeflow).

Revision ID: 038_reasoning_graph_snapshots
Revises: 037_forensics_inv_parent
Create Date: 2026-04-25
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision = "038_reasoning_graph_snapshots"
down_revision = "037_forensics_inv_parent"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "reasoning_graph_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=True),
        sa.Column("module_id", sa.String(length=255), nullable=False),
        sa.Column("subject_kind", sa.String(length=255), nullable=False),
        sa.Column("subject_id", sa.String(length=255), nullable=False),
        sa.Column("step_number", sa.Integer(), nullable=False),
        sa.Column("strategy_family", sa.String(length=64), nullable=False, server_default="generic"),
        sa.Column("graph_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "module_id",
            "subject_kind",
            "subject_id",
            "step_number",
            name="uq_reasoninggraphs_subject_step",
        ),
    )
    op.create_index(
        "ix_reasoninggraphs_subject",
        "reasoning_graph_snapshots",
        ["module_id", "subject_kind", "subject_id"],
    )
    op.create_index(
        "ix_reasoning_graph_snapshots_run_id",
        "reasoning_graph_snapshots",
        ["run_id"],
    )
    op.create_index(
        "ix_reasoning_graph_snapshots_module_id",
        "reasoning_graph_snapshots",
        ["module_id"],
    )
    op.create_index(
        "ix_reasoning_graph_snapshots_subject_kind",
        "reasoning_graph_snapshots",
        ["subject_kind"],
    )
    op.create_index(
        "ix_reasoning_graph_snapshots_subject_id",
        "reasoning_graph_snapshots",
        ["subject_id"],
    )
    op.create_index(
        "ix_reasoning_graph_snapshots_step_number",
        "reasoning_graph_snapshots",
        ["step_number"],
    )


def downgrade() -> None:
    op.drop_index("ix_reasoning_graph_snapshots_step_number", table_name="reasoning_graph_snapshots")
    op.drop_index("ix_reasoning_graph_snapshots_subject_id", table_name="reasoning_graph_snapshots")
    op.drop_index("ix_reasoning_graph_snapshots_subject_kind", table_name="reasoning_graph_snapshots")
    op.drop_index("ix_reasoning_graph_snapshots_module_id", table_name="reasoning_graph_snapshots")
    op.drop_index("ix_reasoning_graph_snapshots_run_id", table_name="reasoning_graph_snapshots")
    op.drop_index("ix_reasoninggraphs_subject", table_name="reasoning_graph_snapshots")
    op.drop_table("reasoning_graph_snapshots")
