"""Create knowledge table migration + resize pgvector embedding to 1024-dim.

Phase 165 D-08: KnowledgeEntryRecord was previously created via create_all
and had no Alembic migration. This migration:
1. Creates the knowledgeentryrecord table if it does not exist
2. Resizes the embedding column from Vector(384) to Vector(1024) for BGE-M3
3. Drops and recreates the HNSW index on the resized column

Revision ID: 009_knowledge_table_migration
Revises: 008_add_condition_expr_json
Create Date: 2026-04-11
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect as sa_inspect

# revision identifiers, used by Alembic.
revision: str = "009_knowledge_table_migration"
down_revision: Union[str, None] = "008_add_condition_expr_json"
branch_labels = None
depends_on = None

TABLE_NAME = "knowledgeentryrecord"


def _table_exists(connection: sa.Connection) -> bool:
    """Check if the knowledge table already exists in the database."""
    inspector = sa_inspect(connection)
    return TABLE_NAME in inspector.get_table_names()


def upgrade() -> None:
    connection = op.get_bind()

    if not _table_exists(connection):
        # --- Scenario 1: Fresh DB, table never created ---
        # Create table with Vector(1024) from the start.
        # pgvector extension must already be enabled (it is -- other tables use it).
        op.create_table(
            TABLE_NAME,
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("namespace", sa.String(), nullable=False, index=True),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column(
                "embedding",
                sa.Column("embedding", sa.LargeBinary()).type,  # placeholder -- replaced below
                nullable=True,
            ),
            sa.Column(
                "search_vector",
                sa.Text(),  # placeholder -- replaced with raw SQL below
                nullable=True,
            ),
            sa.Column("entry_metadata", sa.Text(), nullable=True, server_default="{}"),
            sa.Column("dedup_key", sa.Text(), nullable=True, index=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("namespace", "dedup_key", name="uq_knowledgeentryrecord_namespace_dedup_key"),
        )
        # create_table with pgvector and tsvector requires raw DDL for special types.
        # Drop the placeholder columns and add proper ones:
        op.drop_column(TABLE_NAME, "embedding")
        op.drop_column(TABLE_NAME, "search_vector")
        op.execute(f"ALTER TABLE {TABLE_NAME} ADD COLUMN embedding vector(1024)")
        op.execute(
            f"ALTER TABLE {TABLE_NAME} ADD COLUMN search_vector tsvector "
            f"GENERATED ALWAYS AS (to_tsvector('english', content)) STORED"
        )
        # Create indexes
        op.execute(
            f"CREATE INDEX ix_knowledge_embedding_hnsw ON {TABLE_NAME} "
            f"USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)"
        )
        op.execute(
            f"CREATE INDEX ix_knowledge_search_vector ON {TABLE_NAME} "
            f"USING gin (search_vector)"
        )
    else:
        # --- Scenario 2: Table exists with Vector(384), resize to 1024 ---
        # Step 1: Drop HNSW index (cannot ALTER type with index present)
        op.execute("DROP INDEX IF EXISTS ix_knowledge_embedding_hnsw")

        # Step 2: Resize embedding column from vector(384) to vector(1024)
        # Existing 384-dim vectors will be preserved. Queries against them with
        # 1024-dim query vectors will work -- pgvector pads/truncates as needed,
        # but quality degrades. KnowledgeService.embed() zero-pads 384->1024
        # for backward compat. Full re-embedding is a future task.
        op.execute(
            f"ALTER TABLE {TABLE_NAME} ALTER COLUMN embedding TYPE vector(1024)"
        )

        # Step 3: Recreate HNSW index on the resized column
        op.execute(
            f"CREATE INDEX ix_knowledge_embedding_hnsw ON {TABLE_NAME} "
            f"USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)"
        )


def downgrade() -> None:
    connection = op.get_bind()

    if not _table_exists(connection):
        # Nothing to downgrade if table does not exist
        return

    # Reverse: resize 1024 -> 384 (will truncate vectors that are 1024-dim)
    op.execute("DROP INDEX IF EXISTS ix_knowledge_embedding_hnsw")
    op.execute(
        f"ALTER TABLE {TABLE_NAME} ALTER COLUMN embedding TYPE vector(384)"
    )
    op.execute(
        f"CREATE INDEX ix_knowledge_embedding_hnsw ON {TABLE_NAME} "
        f"USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)"
    )
