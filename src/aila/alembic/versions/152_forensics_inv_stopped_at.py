"""152 -- forensics investigation terminal timestamp.

Adds nullable ``stopped_at`` to ``forensics_investigations``. The shared orphan
branch reaper uses it to identify branches left active under a terminal parent;
the panel finalizer writes it with the terminal status. Rows terminal before
this column existed use the reaper's ``updated_at`` fallback.

Revision ID: 152_forensics_inv_stopped_at
Revises:     151_forensics_panel_inv_cols
Create Date: 2026-11-15
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "152_forensics_inv_stopped_at"
down_revision: str | None = "151_forensics_panel_inv_cols"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None

_TABLE = "forensics_investigations"
_COLUMN = "stopped_at"


def _table_present() -> bool:
    return _TABLE in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if _table_present():
        op.execute(sa.text(
            f"ALTER TABLE {_TABLE} ADD COLUMN IF NOT EXISTS {_COLUMN} TIMESTAMPTZ",
        ))


def downgrade() -> None:
    if _table_present():
        op.execute(sa.text(f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS {_COLUMN}"))
