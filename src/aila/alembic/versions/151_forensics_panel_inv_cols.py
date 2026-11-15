"""151 -- forensics panel investigation columns.

Adds ``auto_pilot`` (NOT NULL, server default true, so existing rows backfill
to the platform default) and nullable ``primary_outcome_id`` to
``forensics_investigations``. The platform investigation loop reads
``auto_pilot`` for unknown-confidence decisions, and the panel writes
``primary_outcome_id`` when sibling review approves the canonical outcome.
Table-existence guarded to match the codebase's migration style.

Revision ID: 151_forensics_panel_inv_cols
Revises:     150_drop_module_llm_model_config
Create Date: 2026-11-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "151_forensics_panel_inv_cols"
down_revision: str | None = "150_drop_module_llm_model_config"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "forensics_investigations"
_COLUMNS: dict[str, str] = {
    "auto_pilot": "BOOLEAN NOT NULL DEFAULT TRUE",
    "primary_outcome_id": "VARCHAR(64)",
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
