"""086 -- add prompt_content_hash to llm_cost_records (RFC-09 step 1).

Tags each LLM cost record with the sha256 of the resolved system prompt
template that produced the call, so cost (and later quality) is attributable
to the exact prompt content. Nullable: calls outside an agent turn (scoring,
report generation) leave it unset. The agent turn loop sets it through the
correlation ContextVar (``aila.platform.llm.correlation``) that the
cost-record writer reads. The SQLModel model is updated in the same commit so
``create_all`` (tests, fresh installs) matches the migrated schema.

Guarded with IF NOT EXISTS so a re-run, or a fresh database that already
carries the column, is a no-op.

Revision ID: 086_llm_cost_prompt_content_hash
Revises:     085_malware_mcp_call_log_join_keys
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "086_llm_cost_prompt_content_hash"
down_revision: str | None = "085_malware_mcp_call_log_join_keys"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text(
        "ALTER TABLE llm_cost_records "
        "ADD COLUMN IF NOT EXISTS prompt_content_hash VARCHAR"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_llm_cost_records_prompt_content_hash "
        "ON llm_cost_records (prompt_content_hash)"
    ))


def downgrade() -> None:
    op.execute(sa.text(
        "DROP INDEX IF EXISTS ix_llm_cost_records_prompt_content_hash"
    ))
    op.execute(sa.text(
        "ALTER TABLE llm_cost_records DROP COLUMN IF EXISTS prompt_content_hash"
    ))
