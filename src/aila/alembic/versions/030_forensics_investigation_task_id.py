"""030 -- add task_id column to forensics_investigations.

Stores the ARQ task ID so the SSE event stream endpoint can
look up the Redis Stream key for live progress tracking.

Revision ID: 030_forensics_investigation_task_id
Revises: 029_forensics_analyzer_os
Create Date: 2026-04-16
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "030_inv_task_id"
down_revision = "029_forensics_analyzer_os"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "forensics_investigations",
        sa.Column("task_id", sa.String(), nullable=True),
    )
    op.create_index(
        "ix_forensics_investigations_task_id",
        "forensics_investigations",
        ["task_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_forensics_investigations_task_id", table_name="forensics_investigations")
    op.drop_column("forensics_investigations", "task_id")
