"""033 -- add project_kind column to forensics_projects.

Distinguishes disk-evidence projects (the default -- run the full
collection + deep_analysis pipeline over disk images / memory dumps /
pcaps) from raw-directory projects (rootfs-style: intake just
enumerates the files and the free-flow investigator reads them
directly, no dissect / volatility / tshark).

Revision ID: 033_forensics_project_kind
Revises: 032_forensics_directives
Create Date: 2026-04-18
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "033_forensics_project_kind"
down_revision = "032_forensics_directives"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "forensics_projects",
        sa.Column(
            "project_kind",
            sa.String(length=32),
            server_default="disk_evidence",
            nullable=False,
        ),
    )
    op.create_index(
        "ix_forensics_projects_project_kind",
        "forensics_projects",
        ["project_kind"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_forensics_projects_project_kind",
        table_name="forensics_projects",
    )
    op.drop_column("forensics_projects", "project_kind")
