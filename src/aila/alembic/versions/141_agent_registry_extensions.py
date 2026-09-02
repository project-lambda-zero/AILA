"""141 -- extend specialist_agent for unified agent registry and RAG visibility.

Adds agent_type, model_role, prompt_key, and rag_scope columns to the
specialist_agent table so core dialectic personas (halvar, maddie, renzo,
dante, oracle) and specialists coexist in a single editable registry with full
visibility into their prompt bindings and RAG retrieval domains.

Revision ID: 141_agent_registry_extensions
Revises:     140_outcome_superseded_at
Create Date: 2026-08-26
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "141_agent_registry_extensions"
down_revision: str | None = "140_outcome_superseded_at"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text(
        "ALTER TABLE specialist_agent "
        "ADD COLUMN IF NOT EXISTS agent_type VARCHAR(32) NOT NULL DEFAULT 'specialist'"
    ))
    op.execute(sa.text(
        "ALTER TABLE specialist_agent "
        "ADD COLUMN IF NOT EXISTS model_role VARCHAR(64)"
    ))
    op.execute(sa.text(
        "ALTER TABLE specialist_agent "
        "ADD COLUMN IF NOT EXISTS prompt_key VARCHAR(128)"
    ))
    op.execute(sa.text(
        "ALTER TABLE specialist_agent "
        "ADD COLUMN IF NOT EXISTS rag_scope VARCHAR(256) DEFAULT 'cve_intel,patterns,knowledge,corpus'"
    ))


def downgrade() -> None:
    op.execute(sa.text("ALTER TABLE specialist_agent DROP COLUMN IF EXISTS agent_type"))
    op.execute(sa.text("ALTER TABLE specialist_agent DROP COLUMN IF EXISTS model_role"))
    op.execute(sa.text("ALTER TABLE specialist_agent DROP COLUMN IF EXISTS prompt_key"))
    op.execute(sa.text("ALTER TABLE specialist_agent DROP COLUMN IF EXISTS rag_scope"))
