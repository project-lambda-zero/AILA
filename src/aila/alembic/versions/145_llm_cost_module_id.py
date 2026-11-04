"""145 -- add ``module_id`` to ``llm_cost_records`` (#287).

Adds a nullable, indexed ``module_id`` column so LLM spend can be attributed
per module. :func:`aila.platform.llm.cost.persist_cost_record` stamps the
ambient ``current_module_id()`` on every new row: the owning module's id for a
call made inside a module runtime, or the ``_no_module`` sentinel for a call
made outside one.

The column is nullable + no server default so:

* Pre-existing rows migrate cleanly. NULL ``module_id`` means "written before
  module attribution existed"; per-module filters skip those rows instead of
  guessing an owner for them.
* New rows never write NULL, so the sentinel keeps "no module" selectable.

Table-existence guarded to match the codebase's migration style: an
environment that has not yet created ``llm_cost_records`` becomes a no-op
instead of a crash.

Revision ID: 145_llm_cost_module_id
Revises:     144_drop_vr_cve_feed_state
Create Date: 2026-11-01
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "145_llm_cost_module_id"
down_revision: str | None = "144_drop_vr_cve_feed_state"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "llm_cost_records"
_INDEX_MODULE_ID: str = "ix_llm_cost_records_module_id"


def _table_present() -> bool:
    """True when ``llm_cost_records`` exists in the bound DB."""
    inspector = sa.inspect(op.get_bind())
    return _TABLE in set(inspector.get_table_names())


def upgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} "
        "ADD COLUMN IF NOT EXISTS module_id VARCHAR"
    ))
    op.execute(sa.text(
        f"CREATE INDEX IF NOT EXISTS {_INDEX_MODULE_ID} "
        f"ON {_TABLE} (module_id)"
    ))


def downgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(f"DROP INDEX IF EXISTS {_INDEX_MODULE_ID}"))
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS module_id"
    ))
