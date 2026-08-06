"""089 -- add prompt_content_hash to auditsealrecord (RFC-09 step 1).

Tags each audit seal with the sha256 of the resolved system prompt
template that produced the call, so the HMAC chain-of-custody record is
attributable to the exact prompt content (the same tag already added to
llm_cost_records in 086). Nullable: calls outside an agent turn (scoring,
report generation) leave it unset. The seal step reads it from the
correlation ContextVar the agent turn loop sets. The SQLModel model is
updated in the same commit so create_all (tests, fresh installs) matches
the migrated schema.

Guarded with IF NOT EXISTS so a re-run, or a fresh database that already
carries the column, is a no-op.

Revision ID: 089_seal_prompt_content_hash
Revises:     088_outcome_claimed_at
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "089_seal_prompt_content_hash"
down_revision: str | None = "088_outcome_claimed_at"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text(
        "ALTER TABLE auditsealrecord "
        "ADD COLUMN IF NOT EXISTS prompt_content_hash VARCHAR"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_auditsealrecord_prompt_content_hash "
        "ON auditsealrecord (prompt_content_hash)"
    ))


def downgrade() -> None:
    op.execute(sa.text(
        "DROP INDEX IF EXISTS ix_auditsealrecord_prompt_content_hash"
    ))
    op.execute(sa.text(
        "ALTER TABLE auditsealrecord DROP COLUMN IF EXISTS prompt_content_hash"
    ))
