"""119 -- RFC-13/03 branch strategy_family backfill.

The 2026-08 dormancy audit found all 351 live rows in
``vr_investigation_branches`` and ``malware_investigation_branches``
carrying ``strategy_family = NULL``. The API-side primary-branch INSERT
never set the column; only ``BranchPool.spawn_strategy`` did. The
grouping consumed by ``BranchPool.list_active_by_strategy`` therefore
collapsed every live branch into the empty-string bucket, hiding them
from every strategy-family dispatch pass.

This migration is the one-shot data backfill that matches the code
changes landed in the same slice (branch_pool.fork / merge, the
investigation-setup fresh-primary self-heal, the promote-primary
block, and the persona_spawn INSERT + reactivation path all now
populate ``strategy_family`` at write time). Rows created after this
migration will always carry a family; this migration heals the
pre-2026-08 population.

For each module's branch table the migration:

* verifies the table exists on the bound schema (a fresh test DB
  where ``create_all`` has not yet installed the module's tables
  skips the UPDATE cleanly),
* verifies the ``strategy_family`` column exists on the branch table
  AND on the matching ``<module>_investigations`` table (the source
  of truth for the correlated subquery),
* runs a single correlated ``UPDATE`` that copies each
  investigation's ``strategy_family`` into every branch whose column
  is currently NULL or the empty string.

Existence-guarded per the pattern established by 118: every op is
preceded by an ``sa.inspect`` check so partially-migrated databases
and fresh test databases both survive the upgrade path.

``downgrade()`` is a NO-OP. A data backfill is not reversible without
capturing the prior NULL state per row before overwriting it, and the
prior state carried zero information (the whole column was a dormant
NULL). Rolling back the schema-level revision to 118 leaves the
back-filled values in place; that is intentional -- the values are
correct data that was silently missing before, not a schema change to
undo.

Revision ID: 119_branch_strategy_bf
Revises: 118_mcp_trust_gate
Create Date: 2026-08-07
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "119_branch_strategy_bf"
down_revision: str | None = "118_mcp_trust_gate"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


# (branches_table, investigations_table) pairs to back-fill. One entry
# per module that carries the branch model; keeping the list explicit
# means adding a new module means editing this file once (rather than
# reflecting the schema and guessing at naming conventions).
_BACKFILL_PAIRS: tuple[tuple[str, str], ...] = (
    ("vr_investigation_branches", "vr_investigations"),
    ("malware_investigation_branches", "malware_investigations"),
)


def _column_names(inspector: sa.engine.reflection.Inspector, table: str) -> set[str]:
    """Return the current column names for ``table``, or an empty set.

    Empty set when the table is missing entirely so callers skip both
    the column check and the follow-up UPDATE (the fresh-test-DB path
    where ``create_all`` has not yet touched a module's tables).
    """
    if table not in set(inspector.get_table_names()):
        return set()
    return {col["name"] for col in inspector.get_columns(table)}


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())

    for branches_table, inv_table in _BACKFILL_PAIRS:
        branch_columns = _column_names(inspector, branches_table)
        inv_columns = _column_names(inspector, inv_table)

        if "strategy_family" not in branch_columns:
            # Branch table is absent OR the column has not been added
            # yet (pre-GA-50 schema on some historical fixture). Nothing
            # to back-fill; leave the row set untouched.
            continue
        if "strategy_family" not in inv_columns:
            # Correlated subquery has no source column to read; skip
            # rather than raise so a stripped test schema still upgrades.
            continue

        # Correlated UPDATE. ``strategy_family = ''`` is treated the same
        # as NULL because a handful of legacy fixtures wrote empty
        # strings into the column; both count as dormant for the
        # dispatch grouping and both should heal to the investigation's
        # family.
        op.execute(sa.text(
            f"UPDATE {branches_table} "
            f"SET strategy_family = ("
            f"    SELECT strategy_family FROM {inv_table} "
            f"    WHERE {inv_table}.id = {branches_table}.investigation_id"
            f") "
            f"WHERE strategy_family IS NULL OR strategy_family = ''",
        ))


def downgrade() -> None:
    """No-op. Data backfill is not reversible; the prior state was NULL.

    Rolling back the schema-level revision to 118 leaves the back-filled
    ``strategy_family`` values in place. This is intentional -- the
    values are correct data that was silently missing before, not a
    schema change that needs unwinding. See the module docstring for the
    full rationale.
    """
