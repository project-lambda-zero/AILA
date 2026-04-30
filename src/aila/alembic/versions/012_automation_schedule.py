"""Create automation_schedule_records table (AUTO-01).

Platform-owned automation schedules replace module-owned ScheduledScanRecord.
The old scheduledscanrecord table is kept for migration path (deprecated).

Revision ID: 012_automation_schedule
Revises: 011_taskrecord_version
Create Date: 2026-04-11
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "012_automation_schedule"
down_revision: Union[str, None] = "011_taskrecord_version"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "automation_schedule_records",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("team_id", sa.Text(), nullable=True, index=True),
        sa.Column("action_id", sa.Text(), nullable=False, index=True),
        sa.Column("target_name", sa.Text(), nullable=False, index=True),
        sa.Column("cron_expression", sa.Text(), nullable=False),
        sa.Column("action_kwargs_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true", index=True),
        sa.Column("created_by", sa.Text(), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_result", sa.Text(), nullable=True),
    )

    # RLS policy for team isolation (consistent with migration 010)
    op.execute(sa.text(
        "ALTER TABLE automation_schedule_records ENABLE ROW LEVEL SECURITY"
    ))
    op.execute(sa.text(
        "ALTER TABLE automation_schedule_records FORCE ROW LEVEL SECURITY"
    ))
    op.execute(sa.text("""
        CREATE POLICY team_isolation_automation_schedule_records
            ON automation_schedule_records
            USING (
                team_id = current_setting('app.team_id', true)::text
                OR current_setting('app.team_id', true) = ''
                OR current_setting('app.team_id', true) IS NULL
            )
    """))

    # Grant table access to aila_app role (if it exists from migration 010)
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aila_app') THEN
                EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON automation_schedule_records TO aila_app';
            END IF;
        END
        $$;
    """))


def downgrade() -> None:
    op.execute(sa.text(
        "DROP POLICY IF EXISTS team_isolation_automation_schedule_records "
        "ON automation_schedule_records"
    ))
    op.execute(sa.text(
        "ALTER TABLE automation_schedule_records DISABLE ROW LEVEL SECURITY"
    ))
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aila_app') THEN
                EXECUTE 'REVOKE SELECT, INSERT, UPDATE, DELETE ON automation_schedule_records FROM aila_app';
            END IF;
        END
        $$;
    """))
    op.drop_table("automation_schedule_records")
