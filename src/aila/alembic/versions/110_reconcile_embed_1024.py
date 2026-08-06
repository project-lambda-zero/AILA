"""Reconcile knowledge embedding width to vector(1024), idempotently.

Migration 077 widened ``knowledgeentryrecord.embedding`` to vector(1024) to
match the BGE-M3 provider (1024-dim). A database bootstrapped through
``scripts/db_init.py`` (create tables from the ORM models, then stamp the
current head) never runs the migration DDL, so its column width is whatever
the ORM model declared at bootstrap time. A database bootstrapped before the
model reached Vector(1024) therefore ends up stamped past 077 while its column
is still vector(384). Every knowledge write then fails at flush time with
``expected 384 dimensions, not 1024`` and the failure is swallowed by
caller-side try/except, so the whole knowledge store silently stops persisting.

This migration is the self-heal. It inspects the live column width and widens
it to vector(1024) only when it is narrower, so it is a no-op on a database
that already ran 077 (the common case) and a repair on a drifted create_all
database. 384-dim rows cannot cast into a vector(1024) typmod, so any
pre-existing embedding is cleared before the type change; retrieval degrades to
full-text-only for a NULL-embedding row until it is re-embedded from its stored
``content``.

Revision ID: 110_reconcile_embed_1024
Revises: 109_forensics_child_team_id
Create Date: 2026-08-02
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect as sa_inspect

# revision identifiers, used by Alembic.
revision: str = "110_reconcile_embed_1024"
down_revision: Union[str, None] = "109_forensics_child_team_id"
branch_labels = None
depends_on = None

TABLE_NAME = "knowledgeentryrecord"
TARGET_DIM = 1024
_HNSW = (
    f"CREATE INDEX ix_knowledge_embedding_hnsw ON {TABLE_NAME} "
    f"USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)"
)


def _table_exists(connection: sa.Connection) -> bool:
    inspector = sa_inspect(connection)
    return TABLE_NAME in inspector.get_table_names()


def _current_dim(connection: sa.Connection) -> int | None:
    """Return the declared pgvector width of the embedding column, or None.

    ``format_type`` renders ``vector(1024)`` for a typmod-bearing pgvector
    column; the width is parsed out. Returns None when the column has no
    typmod (bare ``vector``) or the render does not match, which the caller
    treats as "unknown, leave alone".
    """
    row = connection.execute(
        sa.text(
            "SELECT format_type(a.atttypid, a.atttypmod) "
            "FROM pg_attribute a JOIN pg_class c ON a.attrelid = c.oid "
            "WHERE c.relname = :t AND a.attname = 'embedding'"
        ),
        {"t": TABLE_NAME},
    ).scalar()
    rendered = str(row or "")
    # format_type renders "vector(1024)" for a typmod-bearing pgvector column.
    # Parse the width digits between the parens without an except -- a bare
    # "vector" (no typmod) or any non-numeric render returns None (unknown).
    if "(" not in rendered or not rendered.endswith(")"):
        return None
    inner = rendered.split("(", 1)[1].rstrip(")").strip()
    return int(inner) if inner.isdigit() else None


def _resize(dim: int) -> None:
    op.execute("DROP INDEX IF EXISTS ix_knowledge_embedding_hnsw")
    op.execute(f"UPDATE {TABLE_NAME} SET embedding = NULL")
    op.execute(f"ALTER TABLE {TABLE_NAME} ALTER COLUMN embedding TYPE vector({dim})")
    op.execute(_HNSW)


def upgrade() -> None:
    bind = op.get_bind()
    if not _table_exists(bind):
        return
    current = _current_dim(bind)
    # Only widen when the column is narrower than the target. A column already
    # at 1024 (ran 077, or bootstrapped from the current ORM model) is left
    # untouched so no embedding is needlessly cleared.
    if current is not None and current < TARGET_DIM:
        _resize(TARGET_DIM)


def downgrade() -> None:
    # No-op: this migration only ever widens a drifted column up to the width
    # the ORM model + every other migration already assume. Narrowing back to
    # 384 would re-introduce the exact defect this repairs, so the downgrade
    # deliberately leaves the reconciled 1024-dim column in place.
    return
