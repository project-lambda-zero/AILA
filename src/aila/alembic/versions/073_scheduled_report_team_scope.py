"""073 -- team-scope scheduled_report_records (#48-6).

Adds a nullable, indexed ``team_id`` column to ``scheduled_report_records``
so the scheduled-reports CRUD endpoints can scope rows to the caller's
team. The column is nullable per the TeamScopedMixin convention (D-01):
god-tier admin rows carry ``team_id = NULL`` (TEAM-06) and remain visible
to every admin, while a team-scoped admin sees only rows stamped with its
own team.

Existing rows are best-effort backfilled from ``user_records`` via the
``created_by`` foreign relation; rows whose creator has no resolvable team
stay NULL (owned by the god-tier view). No NOT NULL constraint is applied
-- NULL is a valid, meaningful value here.

Revision ID: 073_scheduled_report_team_scope
Revises: 072_malware_observation_dedup
Create Date: 2026-07-20
"""
from __future__ import annotations

from alembic import op

revision: str = "073_scheduled_report_team_scope"
down_revision: str | None = "072_malware_observation_dedup"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE scheduled_report_records ADD COLUMN team_id VARCHAR(64)"
    )
    # Best-effort backfill: inherit the creator's team. A creator with no
    # row in user_records (or a NULL team_id there) leaves the schedule
    # NULL, which the god-tier admin view still surfaces.
    op.execute(
        "UPDATE scheduled_report_records AS s "
        "SET team_id = u.team_id "
        "FROM user_records AS u "
        "WHERE u.id = s.created_by AND u.team_id IS NOT NULL"
    )
    op.execute(
        "CREATE INDEX ix_scheduled_report_records_team_id "
        "ON scheduled_report_records (team_id)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_scheduled_report_records_team_id")
    op.execute(
        "ALTER TABLE scheduled_report_records DROP COLUMN IF EXISTS team_id"
    )
