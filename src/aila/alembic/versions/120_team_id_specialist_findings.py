"""120 -- team_id columns on specialist_agent and finding_workflow_records.

RFC-208 P0 (#99, #100): two currently-unscoped surfaces gain a nullable,
indexed ``team_id`` (String) column so the API layer can filter cross-team
reads/writes.

* ``specialist_agent`` (platform-owned SpecialistAgentRecord). Migration
  103 already declared this column when it created the table; this
  migration is idempotent (``ADD COLUMN IF NOT EXISTS`` +
  ``CREATE INDEX IF NOT EXISTS``) so it is a no-op on databases that
  came through 103 and correctly repairs any that predate it.
* ``finding_workflow_records`` (FindingWorkflowRecord). The column is
  net-new here: transitions before this migration had no team stamp, so
  existing rows keep ``team_id = NULL`` (visible to admin only).

Both columns are nullable: a NULL row is a platform-global default
visible to every team (the ``_BUILTINS`` specialist defaults use this),
and it lets legacy rows survive the migration without a synthetic
back-fill of a team we do not know.

``downgrade()`` drops the indexes and columns from both tables using
``IF EXISTS`` guards so a partial-state database survives rollback.
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "120_team_id_specialist_findings"
down_revision: str | None = "119_branch_strategy_bf"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    # specialist_agent.team_id -- idempotent (migration 103 already added
    # it inline, but older databases may lack it).
    op.execute(sa.text(
        "ALTER TABLE IF EXISTS specialist_agent "
        "ADD COLUMN IF NOT EXISTS team_id VARCHAR(64)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_specialist_agent_team_id "
        "ON specialist_agent (team_id)"
    ))

    # finding_workflow_records.team_id -- net-new column.
    op.execute(sa.text(
        "ALTER TABLE IF EXISTS finding_workflow_records "
        "ADD COLUMN IF NOT EXISTS team_id VARCHAR(64)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_finding_workflow_records_team_id "
        "ON finding_workflow_records (team_id)"
    ))


def downgrade() -> None:
    op.execute(sa.text(
        "DROP INDEX IF EXISTS ix_finding_workflow_records_team_id"
    ))
    op.execute(sa.text(
        "ALTER TABLE IF EXISTS finding_workflow_records "
        "DROP COLUMN IF EXISTS team_id"
    ))
    op.execute(sa.text(
        "DROP INDEX IF EXISTS ix_specialist_agent_team_id"
    ))
    op.execute(sa.text(
        "ALTER TABLE IF EXISTS specialist_agent "
        "DROP COLUMN IF EXISTS team_id"
    ))
