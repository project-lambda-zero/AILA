"""082 -- observability join keys on cost + MCP-call records (#39).

Adds ``investigation_id`` / ``branch_id`` / ``turn_number`` to
``llm_cost_records`` and ``vr_mcp_call_log`` so a cost record or a tool-call
log can be joined back to the investigation, branch, and turn that produced
it. All nullable: calls outside an agent turn (scoring, report generation)
leave them unset.

The agent turn loop sets these through a ContextVar
(``aila.platform.llm.correlation``) that the cost-record writer and the VR
MCP-call logger read. The SQLModel models are updated in the same commit so
``create_all`` (tests, fresh installs) matches the migrated schema.

Revision ID: 082_observability_join_keys
Revises:     081_vr_schema_reconcile
Create Date: 2026-07-21
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "082_observability_join_keys"
down_revision: str | None = "081_vr_schema_reconcile"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        ALTER TABLE llm_cost_records
            ADD COLUMN IF NOT EXISTS investigation_id VARCHAR,
            ADD COLUMN IF NOT EXISTS branch_id VARCHAR,
            ADD COLUMN IF NOT EXISTS turn_number INTEGER;
    """))
    op.execute(sa.text("""
        ALTER TABLE vr_mcp_call_log
            ADD COLUMN IF NOT EXISTS investigation_id VARCHAR(36),
            ADD COLUMN IF NOT EXISTS branch_id VARCHAR(36),
            ADD COLUMN IF NOT EXISTS turn_number INTEGER;
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_llm_cost_records_investigation_id "
        "ON llm_cost_records (investigation_id);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_llm_cost_records_branch_id "
        "ON llm_cost_records (branch_id);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_vr_mcp_call_log_investigation_id "
        "ON vr_mcp_call_log (investigation_id);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_vr_mcp_call_log_branch_id "
        "ON vr_mcp_call_log (branch_id);"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP INDEX IF EXISTS ix_vr_mcp_call_log_branch_id;"))
    op.execute(sa.text("DROP INDEX IF EXISTS ix_vr_mcp_call_log_investigation_id;"))
    op.execute(sa.text("DROP INDEX IF EXISTS ix_llm_cost_records_branch_id;"))
    op.execute(sa.text("DROP INDEX IF EXISTS ix_llm_cost_records_investigation_id;"))
    op.execute(sa.text("""
        ALTER TABLE vr_mcp_call_log
            DROP COLUMN IF EXISTS turn_number,
            DROP COLUMN IF EXISTS branch_id,
            DROP COLUMN IF EXISTS investigation_id;
    """))
    op.execute(sa.text("""
        ALTER TABLE llm_cost_records
            DROP COLUMN IF EXISTS turn_number,
            DROP COLUMN IF EXISTS branch_id,
            DROP COLUMN IF EXISTS investigation_id;
    """))
