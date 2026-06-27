"""037 -- add parent_investigation_id to forensics_investigations.

Lets the API expose a "Rerun (enriched)" path: a new investigation
that carries the prior attempt's persisted observables forward and
gets a one-shot prompt block summarising the prior outcome. NULL for
root (original) investigations.

Revision ID: 037_forensics_investigation_parent
Revises: 036_forensics_artifacts_src_inv
Create Date: 2026-04-19
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "037_forensics_inv_parent"
down_revision = "036_forensics_artifacts_src_inv"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "forensics_investigations",
        sa.Column("parent_investigation_id", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_forensics_investigations_parent_investigation_id",
        "forensics_investigations",
        ["parent_investigation_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_forensics_investigations_parent_investigation_id",
        table_name="forensics_investigations",
    )
    op.drop_column("forensics_investigations", "parent_investigation_id")
