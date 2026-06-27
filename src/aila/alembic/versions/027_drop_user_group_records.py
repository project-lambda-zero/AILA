"""027 -- drop user_group_records table (Phase 184 audit cleanup).

UserGroupRecord was an orphaned schema object: no router imported it,
no service used it, and no endpoint wrote to it. Removed from db_models.py
in the same commit. The table is safe to drop since it has always been empty.

Revision ID: 027_drop_user_group_records
Revises: 026_drop_legacy_task_columns
Create Date: 2026-04-14
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "027_drop_user_group_records"
down_revision: str | None = "026_drop_legacy_task_columns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_table("user_group_records")


def downgrade() -> None:
    op.create_table(
        "user_group_records",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("allowed_modules_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_user_group_records_name", "user_group_records", ["name"], unique=True)
