"""093 -- knowledge entry provenance columns (RFC-12 criterion 1).

Adds per-vector provenance to ``knowledgeentryrecord`` so every stored
embedding carries the identity of the model that produced it, a content
hash for change detection and dedup audit, the source category, and a
last-write timestamp. Closes the provenance half of RFC-12 criterion 1
(``every vector carries model_id + updated_at``).

Columns match the SQLModel fields added to ``KnowledgeEntryRecord`` in
storage/db_models.py so ``create_all`` (tests, fresh installs) matches the
migrated schema. All four are nullable so the add runs on an existing
populated table without a backfill; rows written from this point on are
fully stamped by ``KnowledgeService.store``. Index names are prefixed for
the database-scoped Postgres namespace. Guarded with ``IF NOT EXISTS``.

Revision ID: 093_knowledge_entry_provenance
Revises:     092_mcp_server_instances
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "093_knowledge_entry_provenance"
down_revision: str | None = "092_mcp_server_instances"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text(
        "ALTER TABLE knowledgeentryrecord "
        "ADD COLUMN IF NOT EXISTS model_id VARCHAR;"
    ))
    op.execute(sa.text(
        "ALTER TABLE knowledgeentryrecord "
        "ADD COLUMN IF NOT EXISTS content_hash VARCHAR;"
    ))
    op.execute(sa.text(
        "ALTER TABLE knowledgeentryrecord "
        "ADD COLUMN IF NOT EXISTS source_type VARCHAR;"
    ))
    op.execute(sa.text(
        "ALTER TABLE knowledgeentryrecord "
        "ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_knowledgeentryrecord_model_id "
        "ON knowledgeentryrecord (model_id);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_knowledgeentryrecord_content_hash "
        "ON knowledgeentryrecord (content_hash);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_knowledgeentryrecord_source_type "
        "ON knowledgeentryrecord (source_type);"
    ))


def downgrade() -> None:
    op.execute(sa.text(
        "DROP INDEX IF EXISTS ix_knowledgeentryrecord_source_type;"
    ))
    op.execute(sa.text(
        "DROP INDEX IF EXISTS ix_knowledgeentryrecord_content_hash;"
    ))
    op.execute(sa.text(
        "DROP INDEX IF EXISTS ix_knowledgeentryrecord_model_id;"
    ))
    op.execute(sa.text(
        "ALTER TABLE knowledgeentryrecord DROP COLUMN IF EXISTS updated_at;"
    ))
    op.execute(sa.text(
        "ALTER TABLE knowledgeentryrecord DROP COLUMN IF EXISTS source_type;"
    ))
    op.execute(sa.text(
        "ALTER TABLE knowledgeentryrecord DROP COLUMN IF EXISTS content_hash;"
    ))
    op.execute(sa.text(
        "ALTER TABLE knowledgeentryrecord DROP COLUMN IF EXISTS model_id;"
    ))
