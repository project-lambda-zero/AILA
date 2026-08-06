"""Widen knowledge embedding to vector(1024) and clear truncated vectors.

The ORM model and KnowledgeService previously truncated BGE-M3's 1024-dim
output down to a Vector(384) column, discarding 640 dimensions on every store
and query. This migration makes the column match BGE-M3 at full width.

Existing vectors were stored either truncated-to-384 or as an earlier
zero-padded shape; neither is a valid 1024-dim BGE-M3 embedding, and pgvector
cannot cast 384-dim rows into a vector(1024) typmod. The column is therefore
cleared (set NULL) before the type change; run ``scripts/reembed_knowledge.py``
afterwards to re-embed every row from its stored ``content`` at full 1024 dims.
Retrieval degrades to full-text-only for rows with a NULL embedding until the
backfill completes (the vector leg skips NULL embeddings).

Revision ID: 077_knowledge_embedding_1024
Revises: 076_oidc_default_team
Create Date: 2026-07-21
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect as sa_inspect

# revision identifiers, used by Alembic.
revision: str = "077_knowledge_embedding_1024"
down_revision: Union[str, None] = "076_oidc_default_team"
branch_labels = None
depends_on = None

TABLE_NAME = "knowledgeentryrecord"
_HNSW = (
    f"CREATE INDEX ix_knowledge_embedding_hnsw ON {TABLE_NAME} "
    f"USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)"
)


def _table_exists(connection: sa.Connection) -> bool:
    inspector = sa_inspect(connection)
    return TABLE_NAME in inspector.get_table_names()


def _resize(dim: int) -> None:
    op.execute("DROP INDEX IF EXISTS ix_knowledge_embedding_hnsw")
    op.execute(f"UPDATE {TABLE_NAME} SET embedding = NULL")
    op.execute(f"ALTER TABLE {TABLE_NAME} ALTER COLUMN embedding TYPE vector({dim})")
    op.execute(_HNSW)


def upgrade() -> None:
    if not _table_exists(op.get_bind()):
        return
    _resize(1024)


def downgrade() -> None:
    if not _table_exists(op.get_bind()):
        return
    _resize(384)
