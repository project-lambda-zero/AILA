"""Reconcile platform table drift with SQLModel definitions.

Several platform tables have a column type or constraint shape that differs
between the SQLModel model (what ``create_all`` builds for fresh installs and
tests) and the Alembic migrations (what production ran through). None of the
gaps below crash today; this migration converges an already-migrated database
onto the model so fresh-installed and long-lived databases match:

* ``scheduled_report_records.team_id`` -- was VARCHAR(64) via the
  TeamScopedMixin migration; the model column is unbounded ``str`` / TEXT.
* ``reasoning_graph_snapshots.module_id`` / ``subject_kind`` /
  ``subject_id`` -- migration created them VARCHAR(255); the model columns
  are unbounded ``str`` / TEXT.
* ``automation_schedule_records.cron_timezone`` -- migration created it
  VARCHAR(64); the model column is unbounded ``str`` / TEXT.
* ``team_records.name`` uniqueness -- the model declares
  ``UniqueConstraint("name", name="uq_team_records_name")``; older
  databases carry only the ``ix_team_records_name`` unique index. Promote
  the index into the named constraint so ``pg_constraint`` matches the
  model. Guarded so a database already carrying the constraint is a no-op.

Revision ID: 080_platform_schema_reconcile
Revises: 079_refresh_token_client_meta
Create Date: 2026-07-22
"""
from __future__ import annotations

from alembic import op

revision: str = "080_platform_schema_reconcile"
down_revision: str | None = "079_refresh_token_client_meta"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE scheduled_report_records ALTER COLUMN team_id TYPE TEXT")
    op.execute("ALTER TABLE reasoning_graph_snapshots ALTER COLUMN module_id TYPE TEXT")
    op.execute("ALTER TABLE reasoning_graph_snapshots ALTER COLUMN subject_kind TYPE TEXT")
    op.execute("ALTER TABLE reasoning_graph_snapshots ALTER COLUMN subject_id TYPE TEXT")
    op.execute("ALTER TABLE automation_schedule_records ALTER COLUMN cron_timezone TYPE TEXT")
    op.execute(
        """
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_team_records_name')
     AND EXISTS (SELECT 1 FROM pg_class WHERE relname = 'ix_team_records_name') THEN
    ALTER TABLE team_records ADD CONSTRAINT uq_team_records_name UNIQUE USING INDEX ix_team_records_name;
  END IF;
END $$;
"""
    )


def downgrade() -> None:
    op.execute("ALTER TABLE scheduled_report_records ALTER COLUMN team_id TYPE VARCHAR(64)")
    op.execute(
        "ALTER TABLE reasoning_graph_snapshots ALTER COLUMN module_id TYPE VARCHAR(255)"
    )
    op.execute(
        "ALTER TABLE reasoning_graph_snapshots ALTER COLUMN subject_kind TYPE VARCHAR(255)"
    )
    op.execute(
        "ALTER TABLE reasoning_graph_snapshots ALTER COLUMN subject_id TYPE VARCHAR(255)"
    )
    op.execute(
        "ALTER TABLE automation_schedule_records ALTER COLUMN cron_timezone TYPE VARCHAR(64)"
    )
    op.execute("ALTER TABLE team_records DROP CONSTRAINT IF EXISTS uq_team_records_name")
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_team_records_name ON team_records (name)"
    )
