"""Create llm_cost_records table (LLM-COST-01).

Durable per-call LLM cost records for cost intelligence features.
Stores model_id, task_type, run_id, token counts, dollar cost, and
optional human-equivalent cost columns (Plan 175-03).

Team isolation enforced via RLS policy (T-175-02 mitigation).

Revision ID: 017_llm_cost_record
Revises: 016_confidence_drift
Create Date: 2026-04-11
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "017_llm_cost_record"
down_revision: Union[str, None] = "016_confidence_drift"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "llm_cost_records",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("team_id", sa.Text(), nullable=True, index=True),
        sa.Column("run_id", sa.Text(), nullable=False, server_default="_no_run", index=True),
        sa.Column("model_id", sa.Text(), nullable=False, index=True),
        sa.Column("task_type", sa.Text(), nullable=False, server_default="", index=True),
        sa.Column("prompt_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cost_usd", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("human_cost_hours", sa.Float(), nullable=True),
        sa.Column("human_cost_usd", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_index(
        "ix_llmcostrecord_run_id_model_id",
        "llm_cost_records",
        ["run_id", "model_id"],
    )
    op.create_index(
        "ix_llmcostrecord_team_created",
        "llm_cost_records",
        ["team_id", "created_at"],
    )

    # RLS policy for team isolation (T-175-02 mitigation, consistent with migration 012)
    op.execute(sa.text(
        "ALTER TABLE llm_cost_records ENABLE ROW LEVEL SECURITY"
    ))
    op.execute(sa.text(
        "ALTER TABLE llm_cost_records FORCE ROW LEVEL SECURITY"
    ))
    # RLS policy: team isolation with safe admin bypass.
    # Admin access requires app.team_id = '__admin__' (explicit, not empty/NULL).
    # Empty string or NULL app.team_id gets NO access (fail-closed).
    op.execute(sa.text("""
        CREATE POLICY team_isolation_llm_cost_records
            ON llm_cost_records
            USING (
                team_id = current_setting('app.team_id', true)::text
                OR current_setting('app.team_id', true)::text = '__admin__'
            )
    """))

    # Grant table access to aila_app role (if it exists from migration 010)
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aila_app') THEN
                EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON llm_cost_records TO aila_app';
            END IF;
        END
        $$;
    """))

    # Budget alert deduplication index (Phase 175 / D-03a)
    # Partial unique index on notification_records.source_entity_id WHERE NOT NULL.
    # Enables INSERT ... ON CONFLICT (source_entity_id) DO NOTHING as a race-safe
    # dedup strategy for budget alerts and missing-pricing notifications.
    op.create_index(
        "ix_notification_source_entity_dedup",
        "notification_records",
        ["source_entity_id"],
        unique=True,
        postgresql_where=sa.text("source_entity_id IS NOT NULL"),
    )


def downgrade() -> None:
    # Drop notification dedup index (D-03a) first -- no table dependency
    op.drop_index("ix_notification_source_entity_dedup", table_name="notification_records")

    op.execute(sa.text(
        "DROP POLICY IF EXISTS team_isolation_llm_cost_records "
        "ON llm_cost_records"
    ))
    op.execute(sa.text(
        "ALTER TABLE llm_cost_records DISABLE ROW LEVEL SECURITY"
    ))
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aila_app') THEN
                EXECUTE 'REVOKE SELECT, INSERT, UPDATE, DELETE ON llm_cost_records FROM aila_app';
            END IF;
        END
        $$;
    """))
    op.drop_index("ix_llmcostrecord_run_id_model_id", table_name="llm_cost_records")
    op.drop_index("ix_llmcostrecord_team_created", table_name="llm_cost_records")
    op.drop_table("llm_cost_records")
