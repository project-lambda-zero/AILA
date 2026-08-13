"""121 -- backfill investigation cost_actual_usd from recorded LLM spend.

RFC-208 P1 (#135), option (a): the live accrual writeback in
``persist_cost_record`` keeps ``cost_actual_usd`` correct going forward, but
every investigation that ran before the writeback existed still reads the
never-written column as $0.00. This one-time data migration sets
``cost_actual_usd`` and ``llm_tokens_cost_usd`` on each existing
investigation row to the sum of its recorded ``llm_cost_records`` (joined on
``run_id`` -- the value the reasoning engine threads as the investigation
id, the same join used by ``compute_live_investigation_cost``).

Idempotent: re-running assigns the same aggregate. ``downgrade()`` is a
no-op -- the values are harmless, and the ongoing writeback would re-diverge
a reset immediately while also discarding spend recorded after this ran.
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "121_backfill_investigation_cost"
down_revision: str | None = "120_team_id_specialist_findings"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None

# The two production investigation tables at head 120 (vr migration 044,
# malware migration 068). The _template scaffold table is intentionally
# excluded -- it is never applied on a real database.
_INVESTIGATION_TABLES = ("vr_investigations", "malware_investigations")


def upgrade() -> None:
    for table in _INVESTIGATION_TABLES:
        # Guard: skip a table that a partial-state database has not created.
        exists = op.get_bind().execute(
            sa.text("SELECT to_regclass(:t)"), {"t": table},
        ).scalar()
        if exists is None:
            continue
        op.execute(
            sa.text(
                f"""
                UPDATE {table} AS inv
                SET cost_actual_usd = agg.total,
                    llm_tokens_cost_usd = agg.total
                FROM (
                    SELECT run_id, COALESCE(SUM(cost_usd), 0.0) AS total
                    FROM llm_cost_records
                    GROUP BY run_id
                ) AS agg
                WHERE agg.run_id = inv.id
                  AND agg.total > 0.0
                """,  # noqa: S608 -- table names are fixed module constants
            ),
        )


def downgrade() -> None:
    raise NotImplementedError(
        "121 is irreversible: cost_actual_usd now has a live writer (the "
        "#135 accrual writeback shipped in the same release), so the "
        "pre-backfill zeros cannot be restored without discarding real "
        "accrued spend.",
    )
