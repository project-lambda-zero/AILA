"""125 -- perf indexes for hot list/aggregation endpoints (#176 / #204).

Backfills the indexes the model side is now expected to carry so the
production endpoints touched by the #176 / #204 peer-review batch stop
sequential-scanning growing tables.

Indexes added (all created ``IF NOT EXISTS`` and ``CONCURRENTLY`` so a
live table is not write-locked; each ``CREATE`` is table-guarded so an
environment missing a table becomes a no-op instead of a crash):

* ``ix_llmcostrecord_created_at`` on ``llm_cost_records(created_at)`` --
  the admin god-tier cost history/roi queries filter by ``created_at``
  alone (no ``team_id``), which cannot use the pre-existing compound
  ``ix_llmcostrecord_team_created`` index. The compound stays for the
  team-scoped path.
* ``ix_auditeventrecord_team_created`` on ``auditeventrecord(team_id,
  created_at)`` -- the audit list is ordered by ``created_at`` scoped to
  a team; the pre-existing standalone ``created_at`` index still serves
  admin-tier scans.
* ``ix_finding_workflow_state_created`` on
  ``finding_workflow_records(current_state, created_at)`` -- MTTR
  aggregation on the dashboard filters on ``current_state`` and orders /
  buckets by ``created_at``.
* ``ix_workflowrunrecord_completed_at`` on
  ``workflowrunrecord(completed_at)`` -- the systems scan_map DISTINCT ON
  query orders by ``completed_at DESC`` per system-name match; the
  pre-existing compound ``(status, completed_at)`` does not help when
  the query filters on the JSONB substring instead of ``status``.

Revision ID: 125_perf_indexes
Revises:     124_llm_cost_user_id
Create Date: 2026-08-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "125_perf_indexes"
down_revision: str | None = "124_llm_cost_user_id"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


# (index_name, table, column-expression). Column-expression is passed
# verbatim into the ``CREATE INDEX`` statement so composite indexes work.
_INDEXES: tuple[tuple[str, str, str], ...] = (
    ("ix_llmcostrecord_created_at", "llm_cost_records", "created_at"),
    ("ix_auditeventrecord_team_created", "auditeventrecord", "team_id, created_at"),
    ("ix_finding_workflow_state_created", "finding_workflow_records", "current_state, created_at"),
    ("ix_workflowrunrecord_completed_at", "workflowrunrecord", "completed_at"),
)


def _existing_tables() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return set(inspector.get_table_names())


def upgrade() -> None:
    tables = _existing_tables()
    with op.get_context().autocommit_block():
        for index_name, table, column_expr in _INDEXES:
            if table not in tables:
                # Table-guarded per repo convention (mirror
                # 115_forensics_prompt_pins.py) -- environments where the
                # table is absent silently skip instead of crashing.
                continue
            op.execute(
                f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {index_name} "
                f"ON {table} ({column_expr})"
            )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        for index_name, _table, _column_expr in reversed(_INDEXES):
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {index_name}")
