"""074 -- automation cron timezone + disable reason (#46-2, #46-4b).

Adds two nullable columns to ``automation_schedule_records`` so the
runner can (a) evaluate cron expressions against a wall-clock timezone
and (b) auto-disable schedules that fail to parse without raising on
every subsequent tick:

- ``cron_timezone`` -- IANA zone name (e.g. ``UTC``, ``America/New_York``).
  Interpreted by ``AutomationRunner._is_due`` via ``zoneinfo.ZoneInfo``
  so a schedule like ``0 9 * * *`` fires at 09:00 in that zone rather
  than 09:00 UTC. NULL and unrecognized names fall back to UTC at
  read time. A server default of ``'UTC'`` covers existing rows and
  any future INSERT that omits the column.

- ``disable_reason`` -- short cause populated by the runner when a
  cron expression or timezone cannot be parsed. The runner also flips
  ``enabled`` to false so the row is not re-attempted every tick.
  Operators clear ``disable_reason`` and set ``enabled`` back to true
  to re-arm the schedule.

Both columns are nullable at the database layer. No index is added:
neither column participates in the runner's due-selection WHERE, and
UI listings paginate over an already-narrow team-scoped result set.

Revision ID: 074_automation_tz_disable
Revises: 073_scheduled_report_team_scope
Create Date: 2026-07-21
"""
from __future__ import annotations

from alembic import op

revision: str = "074_automation_tz_disable"
down_revision: str | None = "073_scheduled_report_team_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE automation_schedule_records "
        "ADD COLUMN cron_timezone VARCHAR(64) DEFAULT 'UTC'"
    )
    op.execute(
        "ALTER TABLE automation_schedule_records "
        "ADD COLUMN disable_reason TEXT"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE automation_schedule_records "
        "DROP COLUMN IF EXISTS disable_reason"
    )
    op.execute(
        "ALTER TABLE automation_schedule_records "
        "DROP COLUMN IF EXISTS cron_timezone"
    )
