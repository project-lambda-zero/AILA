"""146 -- drop n-day-only columns from ``vr_findings``.

``advisory_json`` and ``obligations_json`` were written only by the deleted
dedicated n-day pipeline (``vr.nday.v1`` advisory state). N-day work now runs on
the default VR investigation hub, which never writes either column, so they are
dead. Table-existence guarded to match the codebase's migration style.

Revision ID: 146_drop_vr_finding_nday_columns
Revises:     145_llm_cost_module_id
Create Date: 2026-11-03
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "146_drop_vr_finding_nday_columns"
down_revision: str | None = "145_llm_cost_module_id"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "vr_findings"
_COLUMNS: tuple[str, ...] = ("advisory_json", "obligations_json")


def _table_present() -> bool:
    """True when ``vr_findings`` exists in the bound DB."""
    inspector = sa.inspect(op.get_bind())
    return _TABLE in set(inspector.get_table_names())


def upgrade() -> None:
    if not _table_present():
        return
    for column in _COLUMNS:
        op.execute(sa.text(f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS {column}"))


def downgrade() -> None:
    if not _table_present():
        return
    for column in _COLUMNS:
        op.execute(sa.text(
            f"ALTER TABLE {_TABLE} ADD COLUMN IF NOT EXISTS {column} "
            "TEXT NOT NULL DEFAULT '{}'"
        ))
