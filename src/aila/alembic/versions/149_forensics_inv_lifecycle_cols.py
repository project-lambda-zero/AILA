"""149 -- forensics investigation lifecycle columns.

Adds nullable ``pause_reason`` text and ``started_at`` timestamptz columns to
``forensics_investigations``. The platform investigation lifecycle writes both
when it re-enqueues a stuck run (#450). Table-existence guarded to match the
codebase's migration style.

Revision ID: 149_forensics_inv_lifecycle_cols
Revises:     148_project_failure_reason
Create Date: 2026-11-13
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "149_forensics_inv_lifecycle_cols"
down_revision: str | None = "148_project_failure_reason"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "forensics_investigations"
_COLUMNS: dict[str, str] = {
    "pause_reason": "TEXT",
    "started_at": "TIMESTAMP WITH TIME ZONE",
}


def _table_present() -> bool:
    """Return True when ``_TABLE`` exists in the bound DB."""
    return _TABLE in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if _table_present():
        for column, ddl_type in _COLUMNS.items():
            op.execute(sa.text(f"ALTER TABLE {_TABLE} ADD COLUMN IF NOT EXISTS {column} {ddl_type}"))


def downgrade() -> None:
    if _table_present():
        for column in _COLUMNS:
            op.execute(sa.text(f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS {column}"))
