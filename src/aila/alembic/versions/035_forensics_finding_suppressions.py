"""035 -- forensics_finding_suppressions table.

Auto-findings are derived at read-time from ``normalized_artifacts`` so
they have no stable ID. To let analysts permanently hide a row as
false-positive we store a suppression record keyed on the row's
fingerprint (same tuple the dedup path already uses: artifact_type +
executable + path + name + user -- hashed to a stable 64-char string).

Suppressions are per-project. Each suppression also drops a
verdict="false" AnalystDirective so every future investigation's system
prompt learns "these look suspicious but the analyst already cleared
them".

Revision ID: 035_forensics_finding_suppressions
Revises: 034_forensics_solid_evidence
Create Date: 2026-04-19
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "035_forensics_finding_supp"
down_revision = "034_forensics_solid_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "forensics_finding_suppressions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("artifact_type", sa.String(length=128), nullable=True),
        sa.Column("executable", sa.Text(), nullable=True),
        sa.Column("path", sa.Text(), nullable=True),
        sa.Column("name", sa.Text(), nullable=True),
        sa.Column("finding_user", sa.Text(), nullable=True),
        sa.Column("reasons_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("source_directive_id", sa.String(length=64), nullable=True),
        sa.Column("suppressed_by", sa.String(length=64), nullable=True),
        sa.Column(
            "suppressed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_index(
        "ix_forensics_finding_suppressions_project_id",
        "forensics_finding_suppressions",
        ["project_id"],
    )
    op.create_index(
        "ix_forensics_finding_suppressions_fingerprint",
        "forensics_finding_suppressions",
        ["project_id", "fingerprint"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_forensics_finding_suppressions_fingerprint",
        table_name="forensics_finding_suppressions",
    )
    op.drop_index(
        "ix_forensics_finding_suppressions_project_id",
        table_name="forensics_finding_suppressions",
    )
    op.drop_table("forensics_finding_suppressions")
