"""094 -- add prompt_version to cost + seal records (RFC-09).

Tags each LLM cost record and audit seal with the resolved prompt version
(the version-store key) that produced the call, alongside the existing
prompt_content_hash. Together they answer "which prompt, at which version,
cost how much and produced what" without replay. Nullable: inline prompts
with no version-store entry, and calls outside an agent turn, leave it
unset. The agent turn loop and idempotent_llm_call set it through the
correlation ContextVar that the cost + seal writers read. The SQLModel
models are updated in the same commit so create_all (tests, fresh
installs) matches the migrated schema.

Guarded with IF NOT EXISTS so a re-run, or a fresh database that already
carries the column, is a no-op.

Revision ID: 094_prompt_version_attribution
Revises:     093_knowledge_entry_provenance
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "094_prompt_version_attribution"
down_revision: str | None = "093_knowledge_entry_provenance"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text(
        "ALTER TABLE llm_cost_records "
        "ADD COLUMN IF NOT EXISTS prompt_version VARCHAR"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_llm_cost_records_prompt_version "
        "ON llm_cost_records (prompt_version)"
    ))
    op.execute(sa.text(
        "ALTER TABLE auditsealrecord "
        "ADD COLUMN IF NOT EXISTS prompt_version VARCHAR"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_auditsealrecord_prompt_version "
        "ON auditsealrecord (prompt_version)"
    ))


def downgrade() -> None:
    op.execute(sa.text(
        "DROP INDEX IF EXISTS ix_auditsealrecord_prompt_version"
    ))
    op.execute(sa.text(
        "ALTER TABLE auditsealrecord DROP COLUMN IF EXISTS prompt_version"
    ))
    op.execute(sa.text(
        "DROP INDEX IF EXISTS ix_llm_cost_records_prompt_version"
    ))
    op.execute(sa.text(
        "ALTER TABLE llm_cost_records DROP COLUMN IF EXISTS prompt_version"
    ))
