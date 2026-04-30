"""Add version column to taskrecord for optimistic locking (CONC-03).

Existing rows receive version=1 via server_default.

Revision ID: 011_taskrecord_version
Revises: 010_team_isolation
Create Date: 2026-04-11
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "011_taskrecord_version"
down_revision = "010_team_isolation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "taskrecord",
        sa.Column("version", sa.Integer, server_default="1", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("taskrecord", "version")
