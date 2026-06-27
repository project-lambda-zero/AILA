"""045 -- VR pattern catalog (Knowledge Transfer plan GA-41).

Adds one new table ``vr_patterns`` that stores the structured fields of
each reusable pattern. The body + embedding live in the mirrored
``KnowledgeEntryRecord`` (no new vector store); this table holds the
queryable schema and the FK back to the mirror entry id.

Revision ID: 045_vr_patterns
Revises: 044_vr_reasoning_tables
Create Date: 2026-05-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "045_vr_patterns"
down_revision: str | None = "044_vr_reasoning_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vr_patterns",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("team_id", sa.Text(), nullable=True),
        sa.Column(
            "workspace_id", sa.String(64),
            sa.ForeignKey("vr_workspaces.id"), nullable=False,
        ),
        sa.Column(
            "investigation_id", sa.String(64),
            sa.ForeignKey("vr_investigations.id"), nullable=True,
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
    op.create_index("ix_vr_patterns_team_id", "vr_patterns", ["team_id"])
    op.create_index("ix_vr_patterns_workspace_id", "vr_patterns", ["workspace_id"])
    op.create_index("ix_vr_patterns_investigation_id", "vr_patterns", ["investigation_id"])
    op.create_index("ix_vr_patterns_kind", "vr_patterns", ["kind"])
    op.create_index("ix_vr_patterns_status", "vr_patterns", ["status"])
    op.create_index("ix_vr_patterns_scope", "vr_patterns", ["scope"])
    op.create_index("ix_vr_patterns_confidence", "vr_patterns", ["confidence"])
    op.create_index("ix_vr_patterns_superseded_by", "vr_patterns", ["superseded_by"])
    op.create_index(
        "ix_vr_patterns_knowledge_entry_id", "vr_patterns", ["knowledge_entry_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_vr_patterns_knowledge_entry_id", table_name="vr_patterns")
    op.drop_index("ix_vr_patterns_superseded_by", table_name="vr_patterns")
    op.drop_index("ix_vr_patterns_confidence", table_name="vr_patterns")
    op.drop_index("ix_vr_patterns_scope", table_name="vr_patterns")
    op.drop_index("ix_vr_patterns_status", table_name="vr_patterns")
    op.drop_index("ix_vr_patterns_kind", table_name="vr_patterns")
    op.drop_index("ix_vr_patterns_investigation_id", table_name="vr_patterns")
    op.drop_index("ix_vr_patterns_workspace_id", table_name="vr_patterns")
    op.drop_index("ix_vr_patterns_team_id", table_name="vr_patterns")
    op.drop_table("vr_patterns")
