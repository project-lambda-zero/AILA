"""Add indexes on hot query columns (issue #45-3).

workflowrunrecord.module_id is filtered by the systems scan-history map;
auditeventrecord.created_at and artifactrecord.created_at are ordered/filtered
by time (audit trail listing, artifact search ordering, retention cleanup).
None were indexed, so those scans went sequential on tables that grow without
bound in production.

Indexes are created CONCURRENTLY (outside a transaction) so building them does
not hold a write lock on a large live table. The model side carries index=True
so a freshly created schema (tests, new installs) already has them; this
migration backfills existing databases.

Revision ID: 075_hot_column_indexes
Revises: 074_automation_tz_disable
"""
from __future__ import annotations

from alembic import op

revision: str = "075_hot_column_indexes"
down_revision: str | None = "074_automation_tz_disable"
branch_labels = None
depends_on = None


_INDEXES: tuple[tuple[str, str, str], ...] = (
    ("ix_workflowrunrecord_module_id", "workflowrunrecord", "module_id"),
    ("ix_auditeventrecord_created_at", "auditeventrecord", "created_at"),
    ("ix_artifactrecord_created_at", "artifactrecord", "created_at"),
)


def upgrade() -> None:
    with op.get_context().autocommit_block():
        for index_name, table, column in _INDEXES:
            op.execute(
                f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {index_name} "
                f"ON {table} ({column})"
            )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        for index_name, _table, _column in reversed(_INDEXES):
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {index_name}")
