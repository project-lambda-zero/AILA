"""036 -- add source_investigation_id to forensics_artifacts.

Lets the agent persist its observables/provenance as proper artifact
rows at answer-submission time, while keeping intake/full-analysis
rows untouched (NULL). Indexed for the upcoming
``GET /artifacts?source=investigations`` filter.

Revision ID: 036_forensics_artifacts_source_investigation
Revises: 035_forensics_finding_suppressions
Create Date: 2026-04-19
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "036_forensics_artifacts_src_inv"
down_revision = "035_forensics_finding_supp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "forensics_artifacts",
        sa.Column("source_investigation_id", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_forensics_artifacts_source_investigation_id",
        "forensics_artifacts",
        ["source_investigation_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_forensics_artifacts_source_investigation_id",
        table_name="forensics_artifacts",
    )
    op.drop_column("forensics_artifacts", "source_investigation_id")
