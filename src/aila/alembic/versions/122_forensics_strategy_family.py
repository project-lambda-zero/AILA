"""122 -- add strategy_family to forensics_investigations (persona-spawn fallback).

Platform ``persona_spawn`` (RFC-13/03) reads ``SELECT strategy_family FROM
forensics_investigations`` as the fallback family when a primary branch was
INSERTed without one. The forensics ``InvestigationRunRecord`` does NOT extend
:class:`InvestigationRecordBase` (it carries a different column shape -- the
same reason migration 115 landed ``prompt_pins_json`` directly), so the column
never existed on this table and the query raised ``UndefinedColumnError``. The
persona-panel spawn then failed for every forensics investigation whose primary
branch lacked a family.

Lands the column directly with ``NOT NULL DEFAULT 'generic'`` so existing rows
migrate cleanly and new rows match the SQLModel default. ``generic`` is the
forensics investigator's own fallback family.

Table-existence guarded: a schema state where ``forensics_investigations`` is
absent (partial test bootstraps, an environment without the forensics module
deployed) becomes a no-op instead of a crash. Same pattern as migration 115.

Revision ID: 122_forensics_strategy_family
Revises:     121_backfill_investigation_cost
Create Date: 2026-08-13
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "122_forensics_strategy_family"
down_revision: str | None = "121_backfill_investigation_cost"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "forensics_investigations"


def _table_present() -> bool:
    """True when ``forensics_investigations`` exists in the bound DB."""
    inspector = sa.inspect(op.get_bind())
    return _TABLE in set(inspector.get_table_names())


def upgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} "
        "ADD COLUMN IF NOT EXISTS strategy_family VARCHAR(64) NOT NULL "
        "DEFAULT 'generic'"
    ))


def downgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS strategy_family"
    ))
