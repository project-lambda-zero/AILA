"""100 -- knowledge entry edges for multi-hop retrieval (RFC-12 criterion 5).

Directed labelled edges between knowledge entries so the graph retrieval
path can follow a seed match N hops to gather related entries. Columns
match platform/services/knowledge_graph.py (KnowledgeEntryEdge) so
create_all (tests, fresh installs) matches the migrated schema. The
foreign keys cascade on delete so removing a knowledge entry drops its
edges. Names prefixed knowledge_entry_edges_. Guarded with IF NOT EXISTS.

Revision ID: 100_knowledge_entry_edges
Revises:     099_retrieval_eval_tables
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "100_knowledge_entry_edges"
down_revision: str | None = "099_retrieval_eval_tables"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS knowledge_entry_edges (
            id SERIAL NOT NULL PRIMARY KEY,
            src_id INTEGER NOT NULL
                REFERENCES knowledgeentryrecord(id) ON DELETE CASCADE,
            dst_id INTEGER NOT NULL
                REFERENCES knowledgeentryrecord(id) ON DELETE CASCADE,
            relation VARCHAR(64) NOT NULL,
            weight FLOAT NOT NULL DEFAULT 1.0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_knowledge_entry_edges_src_dst_relation
                UNIQUE (src_id, dst_id, relation)
        );
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_knowledge_entry_edges_src_id "
        "ON knowledge_entry_edges (src_id);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_knowledge_entry_edges_dst_id "
        "ON knowledge_entry_edges (dst_id);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_knowledge_entry_edges_relation "
        "ON knowledge_entry_edges (relation);"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS knowledge_entry_edges;"))
