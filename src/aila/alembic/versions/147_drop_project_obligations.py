"""147 -- drop obligation residue columns.

The obligation system was removed in 0.6.5. ``obligations_json`` on the project
tables (``vr_projects``, ``malware_projects``) and on ``malware_findings`` has no
model, reader, or writer left in ``src/aila``. Table-existence guarded to match
the codebase's migration style.

Revision ID: 147_drop_project_obligations
Revises:     146_drop_vr_finding_nday_columns
Create Date: 2026-11-04
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "147_drop_project_obligations"
down_revision: str | None = "146_drop_vr_finding_nday_columns"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLES: tuple[str, ...] = ("vr_projects", "malware_projects", "malware_findings")
_COLUMN: str = "obligations_json"


def _present_tables() -> set[str]:
    """Return the subset of ``_TABLES`` that exist in the bound DB."""
    inspector = sa.inspect(op.get_bind())
    existing = set(inspector.get_table_names())
    return {table for table in _TABLES if table in existing}


def upgrade() -> None:
    for table in sorted(_present_tables()):
        op.execute(sa.text(f"ALTER TABLE {table} DROP COLUMN IF EXISTS {_COLUMN}"))


def downgrade() -> None:
    for table in sorted(_present_tables()):
        op.execute(sa.text(
            f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {_COLUMN} "
            "TEXT NOT NULL DEFAULT '{}'"
        ))
