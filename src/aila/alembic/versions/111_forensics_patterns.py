"""111 -- Forensics pattern catalog (RFC-12 Phase 4).

Adds ``forensics_patterns``, the forensics equivalent of ``vr_patterns``
and ``malware_patterns``. The structured fields live here; the body +
embedding live in the mirrored ``KnowledgeEntryRecord`` written by
``PatternStore`` in the same transaction, joined back via
``knowledge_entry_id``.

Forensics has no workspace table -- the project is the forensics
workspace, so ``workspace_id`` foreign-keys ``forensics_projects.id``
(callers pass ``investigation.project_id`` as the workspace id).

Revision ID: 111_forensics_patterns
Revises: 110_reconcile_embed_1024
Create Date: 2026-08-03
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "111_forensics_patterns"
down_revision: str | None = "110_reconcile_embed_1024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "forensics_patterns",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("team_id", sa.Text(), nullable=True),
        sa.Column(
            "workspace_id", sa.String(64),
            sa.ForeignKey("forensics_projects.id"), nullable=False,
        ),
        sa.Column(
            "investigation_id", sa.String(64),
            sa.ForeignKey("forensics_investigations.id"), nullable=True,
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("summary", sa.String(512), nullable=False),
        sa.Column("body", sa.Text(), nullable=False, server_default=""),
        sa.Column("applicability_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="medium"),
        sa.Column("evidence_refs_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("scope", sa.String(16), nullable=False, server_default="local"),
        sa.Column("superseded_by", sa.String(64), nullable=True),
        sa.Column("knowledge_entry_id", sa.Integer(), nullable=True),
        sa.Column("times_retrieved", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_forensics_patterns_team_id", "forensics_patterns", ["team_id"])
    op.create_index(
        "ix_forensics_patterns_workspace_id", "forensics_patterns", ["workspace_id"],
    )
    op.create_index(
        "ix_forensics_patterns_investigation_id",
        "forensics_patterns", ["investigation_id"],
    )
    op.create_index("ix_forensics_patterns_kind", "forensics_patterns", ["kind"])
    op.create_index("ix_forensics_patterns_status", "forensics_patterns", ["status"])
    op.create_index("ix_forensics_patterns_scope", "forensics_patterns", ["scope"])
    op.create_index(
        "ix_forensics_patterns_confidence", "forensics_patterns", ["confidence"],
    )
    op.create_index(
        "ix_forensics_patterns_superseded_by", "forensics_patterns", ["superseded_by"],
    )
    op.create_index(
        "ix_forensics_patterns_knowledge_entry_id",
        "forensics_patterns", ["knowledge_entry_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_forensics_patterns_knowledge_entry_id", table_name="forensics_patterns",
    )
    op.drop_index(
        "ix_forensics_patterns_superseded_by", table_name="forensics_patterns",
    )
    op.drop_index(
        "ix_forensics_patterns_confidence", table_name="forensics_patterns",
    )
    op.drop_index("ix_forensics_patterns_scope", table_name="forensics_patterns")
    op.drop_index("ix_forensics_patterns_status", table_name="forensics_patterns")
    op.drop_index("ix_forensics_patterns_kind", table_name="forensics_patterns")
    op.drop_index(
        "ix_forensics_patterns_investigation_id", table_name="forensics_patterns",
    )
    op.drop_index(
        "ix_forensics_patterns_workspace_id", table_name="forensics_patterns",
    )
    op.drop_index("ix_forensics_patterns_team_id", table_name="forensics_patterns")
    op.drop_table("forensics_patterns")
