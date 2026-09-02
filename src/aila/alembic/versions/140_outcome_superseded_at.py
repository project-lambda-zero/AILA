"""140 -- add superseded_at to investigation-outcome tables (req 26 fix 5).

Reset archives outcomes instead of hard-deleting them: a prior run's
ratified outcomes survive for display and audit, while agent-context
reads filter ``superseded_at IS NULL`` for a clean slate (mirrors the
message-table archive in the same fix). Nullable, so existing rows read
as active. The SQLModel base ``OutcomeRecordBase`` is updated in the same
commit so create_all (tests, fresh installs) matches the migrated schema.

Coverage mirrors migration 088 (claimed_at): the two production
investigation-outcome tables. Guarded with IF NOT EXISTS so a re-run, or
a fresh create_all database that already carries the column, is a no-op.

Revision ID: 140_outcome_superseded_at
Revises:     139_sandbox_exec_history
Create Date: 2026-08-26
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "140_outcome_superseded_at"
down_revision: str | None = "139_sandbox_exec_history"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None

_TABLES = ("vr_investigation_outcomes", "malware_investigation_outcomes")


def upgrade() -> None:
    for table in _TABLES:
        op.execute(sa.text(
            f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ"
        ))


def downgrade() -> None:
    for table in _TABLES:
        op.execute(sa.text(
            f"ALTER TABLE {table} DROP COLUMN IF EXISTS superseded_at"
        ))
