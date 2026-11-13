"""148 -- forensics project failure reason.

Adds a nullable ``failure_reason`` text column to ``forensics_projects`` so a
failed intake keeps its cause on the project row. Table-existence guarded to
match the codebase's migration style.

Revision ID: 148_project_failure_reason
Revises:     147_drop_project_obligations
Create Date: 2026-11-12
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "148_project_failure_reason"
down_revision: str | None = "147_drop_project_obligations"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "forensics_projects"
_COLUMN: str = "failure_reason"


def _table_present() -> bool:
    """Return True when ``_TABLE`` exists in the bound DB."""
    return _TABLE in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if _table_present():
        op.execute(sa.text(f"ALTER TABLE {_TABLE} ADD COLUMN IF NOT EXISTS {_COLUMN} TEXT"))


def downgrade() -> None:
    if _table_present():
        op.execute(sa.text(f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS {_COLUMN}"))
