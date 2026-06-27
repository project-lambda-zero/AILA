"""039 -- add structured steering fields to forensics analyst directives.

Adds explicit strategy-family and required-artifact fields so operator steering
is no longer encoded only in free-text notes.

Revision ID: 039_forensics_directive_controls
Revises: 038_reasoning_graph_snapshots
Create Date: 2026-04-25
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "039_forensics_directive_controls"
down_revision = "038_reasoning_graph_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "forensics_analyst_directives",
        sa.Column("strategy_family", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "forensics_analyst_directives",
        sa.Column("required_artifact", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_forensics_analyst_directives_strategy_family",
        "forensics_analyst_directives",
        ["strategy_family"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_forensics_analyst_directives_strategy_family",
        table_name="forensics_analyst_directives",
    )
    op.drop_column("forensics_analyst_directives", "required_artifact")
    op.drop_column("forensics_analyst_directives", "strategy_family")
