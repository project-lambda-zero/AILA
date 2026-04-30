"""Create forensics_analyst_directives table.

Analyst directives are persistent, free-text guidance entries scoped to
a forensics project (and optionally narrowed to a single investigation).
The investigator reads them on every turn so a human can steer the agent
mid-flight ("extract ips-godeep.zip", "ignore /var/log").
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "032_forensics_directives"
down_revision = "031_evidence_size_bigint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "forensics_analyst_directives",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("investigation_id", sa.String(), nullable=True),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
    )
    op.create_index(
        "ix_forensics_analyst_directives_project_id",
        "forensics_analyst_directives",
        ["project_id"],
    )
    op.create_index(
        "ix_forensics_analyst_directives_investigation_id",
        "forensics_analyst_directives",
        ["investigation_id"],
    )
    op.create_index(
        "ix_forensics_analyst_directives_active",
        "forensics_analyst_directives",
        ["active"],
    )
    op.create_index(
        "ix_forensics_analyst_directives_created_by",
        "forensics_analyst_directives",
        ["created_by"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_forensics_analyst_directives_created_by",
        table_name="forensics_analyst_directives",
    )
    op.drop_index(
        "ix_forensics_analyst_directives_active",
        table_name="forensics_analyst_directives",
    )
    op.drop_index(
        "ix_forensics_analyst_directives_investigation_id",
        table_name="forensics_analyst_directives",
    )
    op.drop_index(
        "ix_forensics_analyst_directives_project_id",
        table_name="forensics_analyst_directives",
    )
    op.drop_table("forensics_analyst_directives")
