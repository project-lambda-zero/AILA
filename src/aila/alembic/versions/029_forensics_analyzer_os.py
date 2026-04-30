"""029 — add analyzer_os column to forensics_projects.

Supports Windows and Linux analyzer machines by storing the OS type
per project. Defaults to 'linux' for backward compatibility.

Revision ID: 029_forensics_analyzer_os
Revises: 028_forensics_tables
Create Date: 2026-04-14
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "029_forensics_analyzer_os"
down_revision = "028_forensics_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "forensics_projects",
        sa.Column("analyzer_os", sa.String(length=16), server_default="linux", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("forensics_projects", "analyzer_os")
