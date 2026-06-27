"""034 -- analyst verdicts on directives + forensics_solid_evidence table.

Extends forensics_analyst_directives with a tri-state ``verdict`` column
(NULL = free-text guidance as before; ``"true"`` / ``"false"`` =
analyst-tagged verdict of a prior investigation) plus back-links to the
investigation + answer candidate that produced it.

Adds the ``forensics_solid_evidence`` table -- durable, per-project rows
holding analyst-confirmed (TRUE) or analyst-rejected (FALSE) findings.
These surface both in the Solid Evidence tab and in every future
investigation's system prompt so the agent does not re-chase already
settled questions.

Revision ID: 034_forensics_solid_evidence
Revises: 033_forensics_project_kind
Create Date: 2026-04-19
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "034_forensics_solid_evidence"
down_revision = "033_forensics_project_kind"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "forensics_analyst_directives",
        sa.Column("verdict", sa.String(length=16), nullable=True),
    )
    op.add_column(
        "forensics_analyst_directives",
        sa.Column("source_investigation_id", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "forensics_analyst_directives",
        sa.Column("source_answer_id", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_forensics_analyst_directives_verdict",
        "forensics_analyst_directives",
        ["verdict"],
    )

    op.create_table(
        "forensics_solid_evidence",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("project_id", sa.String(length=64), nullable=False),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("answer", sa.Text(), nullable=False),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False, server_default="unknown"),
        sa.Column("source_investigation_id", sa.String(length=64), nullable=True),
        sa.Column("source_answer_id", sa.String(length=64), nullable=True),
        sa.Column("source_directive_id", sa.String(length=64), nullable=True),
        sa.Column("primary_artifact", sa.Text(), nullable=True),
        sa.Column("corroboration_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("tagged_by", sa.String(length=64), nullable=True),
        sa.Column(
            "tagged_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_forensics_solid_evidence_project_id",
        "forensics_solid_evidence",
        ["project_id"],
    )
    op.create_index(
        "ix_forensics_solid_evidence_verdict",
        "forensics_solid_evidence",
        ["verdict"],
    )
    op.create_index(
        "ix_forensics_solid_evidence_source_investigation_id",
        "forensics_solid_evidence",
        ["source_investigation_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_forensics_solid_evidence_source_investigation_id",
        table_name="forensics_solid_evidence",
    )
    op.drop_index(
        "ix_forensics_solid_evidence_verdict",
        table_name="forensics_solid_evidence",
    )
    op.drop_index(
        "ix_forensics_solid_evidence_project_id",
        table_name="forensics_solid_evidence",
    )
    op.drop_table("forensics_solid_evidence")

    op.drop_index(
        "ix_forensics_analyst_directives_verdict",
        table_name="forensics_analyst_directives",
    )
    op.drop_column("forensics_analyst_directives", "source_answer_id")
    op.drop_column("forensics_analyst_directives", "source_investigation_id")
    op.drop_column("forensics_analyst_directives", "verdict")
