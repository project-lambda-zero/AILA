"""123 -- link vr_fuzz_campaigns back to its source investigation (#173/#148).

Adds three nullable columns to ``vr_fuzz_campaigns``:

* ``source_investigation_id`` -- the VRInvestigation whose outcome
  proposed this campaign (populated by the proposal-accept flow).
  Indexed so the register_crash + patch_campaign feedback path can
  cheaply look up "which investigation asked for this?" per campaign
  row.
* ``source_outcome_id`` -- the outcome id inside that investigation
  that originated the proposal (audit trail; not indexed -- the
  feedback path only needs the investigation FK).
* ``last_coverage_emitted_pct`` -- coverage_pct value the coverage-delta
  emitter last posted a fuzz.coverage_delta event for. NULL until the
  first emit; patch_campaign updates in the same UoW as it writes the
  event message so the two never drift.

All three columns are nullable + no server default: pre-existing rows
migrate cleanly, and the SQLModel ``default=None`` matches what a fresh
INSERT sees.

Table-existence guarded (same pattern as migration 115 /
122_forensics_strategy_family): a schema state where
``vr_fuzz_campaigns`` is absent (partial test bootstraps, an environment
that never deployed the VR module) becomes a no-op instead of a crash.

Revision ID: 123_vr_fuzz_source_investigation
Revises:     122_forensics_strategy_family
Create Date: 2026-08-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "123_vr_fuzz_source_investigation"
down_revision: str | None = "122_forensics_strategy_family"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "vr_fuzz_campaigns"
_INDEX_SRC_INV: str = "ix_vr_fuzz_campaigns_source_investigation_id"


def _table_present() -> bool:
    """True when ``vr_fuzz_campaigns`` exists in the bound DB."""
    inspector = sa.inspect(op.get_bind())
    return _TABLE in set(inspector.get_table_names())


def upgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} "
        "ADD COLUMN IF NOT EXISTS source_investigation_id VARCHAR(64)"
    ))
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} "
        "ADD COLUMN IF NOT EXISTS source_outcome_id VARCHAR(64)"
    ))
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} "
        "ADD COLUMN IF NOT EXISTS last_coverage_emitted_pct DOUBLE PRECISION"
    ))
    op.execute(sa.text(
        f"CREATE INDEX IF NOT EXISTS {_INDEX_SRC_INV} "
        f"ON {_TABLE} (source_investigation_id)"
    ))


def downgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(f"DROP INDEX IF EXISTS {_INDEX_SRC_INV}"))
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS last_coverage_emitted_pct"
    ))
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS source_outcome_id"
    ))
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS source_investigation_id"
    ))
