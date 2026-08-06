"""Composite index on notification_records(user_id, created_at) (#45).

The notifications list and unread queries filter by user_id and order by
created_at DESC. Without a matching index those scans go sequential on a table
that grows per user over time. Migration 075 indexed the other hot created_at
columns but not this one; the standalone user_id index alone does not serve the
ordered read.

Created CONCURRENTLY (outside a transaction) so building it does not hold a
write lock on a live table. The model side carries the index so a freshly
created schema (tests, new installs) already has it; this backfills existing
databases.

Revision ID: 078_notification_created_index
Revises: 077_knowledge_embedding_1024
Create Date: 2026-07-21
"""
from __future__ import annotations

from alembic import op

revision: str = "078_notification_created_index"
down_revision: str | None = "077_knowledge_embedding_1024"
branch_labels = None
depends_on = None

_INDEX = "ix_notification_user_created"
_TABLE = "notification_records"


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(
            f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {_INDEX} "
            f"ON {_TABLE} (user_id, created_at)"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {_INDEX}")
