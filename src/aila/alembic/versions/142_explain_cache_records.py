"""142 -- explain_cache_records table for the vulnerability CVE explain cache.

Adds ``explain_cache_records`` -- one cached LLM explanation per
vulnerability report run (D-17). ``GET /vulnerability/reports/{run_id}/explain``
reads this table first and returns 200 on a hit; a miss queues the explain
task. The table was previously created only by ``create_all`` on fresh
databases, so databases upgraded through Alembic never received it.

Creation uses ``IF NOT EXISTS`` so databases where ``create_all`` already ran
are left intact.

Revision ID: 142_explain_cache_records
Revises: 141_agent_registry_extensions
Create Date: 2026-10-29
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "142_explain_cache_records"
down_revision: str | None = "141_agent_registry_extensions"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS explain_cache_records (
            id SERIAL PRIMARY KEY,
            run_id TEXT NOT NULL,
            content TEXT NOT NULL DEFAULT '',
            cached_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """))
    op.execute(sa.text(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_ecr_run_id ON explain_cache_records (run_id)"
    ))
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aila_app') THEN
                EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON explain_cache_records TO aila_app';
                EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE explain_cache_records_id_seq TO aila_app';
            END IF;
        END
        $$;
    """))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS explain_cache_records"))
