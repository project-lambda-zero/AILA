"""098 -- add instance_id to MCP call logs (RFC-11 provenance).

Records which cataloged MCP server instance served each tool call, so a
call in a pooled multi-instance capability is traceable to the instance
that handled it. The column lives on the shared McpCallLogRecordBase, so
both module call-log tables receive it. Nullable for backward compatibility
-- calls that predate instance-aware dispatch, or dispatch with an empty
catalog, leave it null. Columns match the SQLModel base so create_all
(tests, fresh installs) matches the migrated schema. Guarded with IF NOT
EXISTS.

Revision ID: 098_mcp_call_log_instance_id
Revises:     097_eval_calibration_proposals
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "098_mcp_call_log_instance_id"
down_revision: str | None = "097_eval_calibration_proposals"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text(
        "ALTER TABLE vr_mcp_call_log "
        "ADD COLUMN IF NOT EXISTS instance_id VARCHAR"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_vr_mcp_call_log_instance_id "
        "ON vr_mcp_call_log (instance_id)"
    ))
    op.execute(sa.text(
        "ALTER TABLE malware_mcp_call_log "
        "ADD COLUMN IF NOT EXISTS instance_id VARCHAR"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_malware_mcp_call_log_instance_id "
        "ON malware_mcp_call_log (instance_id)"
    ))


def downgrade() -> None:
    op.execute(sa.text(
        "DROP INDEX IF EXISTS ix_malware_mcp_call_log_instance_id"
    ))
    op.execute(sa.text(
        "ALTER TABLE malware_mcp_call_log DROP COLUMN IF EXISTS instance_id"
    ))
    op.execute(sa.text(
        "DROP INDEX IF EXISTS ix_vr_mcp_call_log_instance_id"
    ))
    op.execute(sa.text(
        "ALTER TABLE vr_mcp_call_log DROP COLUMN IF EXISTS instance_id"
    ))
