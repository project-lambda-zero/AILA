"""vr_targets.analysis_stages_json -- per-stage durable analysis state.

Adds:
  - `analysis_stages_json` TEXT NOT NULL DEFAULT '{}' on `vr_targets`

Backfill rule:
  - existing `analysis_state` and `analysis_completed_at` map onto the
    THREE stages (ingestion, capability_profile, function_ranking) so
    no operator-visible UI regression on first deploy:

    state=ready    -> all three stages set DONE (completed_at = row.completed_at)
    state=failed   -> ingestion FAILED with the existing
                       analysis_state_message; downstream stages PENDING
    state=ingesting -> ingestion RUNNING with started_at = row.started_at
                       (the reaper will later flip it to FAILED:timeout
                       if it's stuck); downstream PENDING
    state=pending  -> all three PENDING

This way the moment the migration lands every target has a valid stages
struct, services that haven't been upgraded yet keep working (they read
the rolled-up `analysis_state`), and upgraded services start using the
per-stage tracker.

See `aila.platform.contracts.target_stages` for the canonical schema.
"""
from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "060_vr_target_analysis_stages"
down_revision = "059_vr_findings_poc_skip_reason"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vr_targets",
        sa.Column(
            "analysis_stages_json",
            sa.Text(),
            nullable=False,
            server_default="{}",
        ),
    )

    # Backfill existing rows in bounded ID-ordered chunks. The stage-mapping
    # logic stays in one place (``_stages_from_legacy``) so the on-disk
    # payload matches the runtime contract bit-for-bit, but we never hold
    # more than ``_BACKFILL_CHUNK_ROWS`` in memory and every chunk's writes
    # travel as a single ``executemany`` round-trip instead of a per-row
    # UPDATE. Cursor-paginated by primary key so a table with millions of
    # rows completes without touching migration-time RAM or blowing the
    # statement round-trip budget. Rows created after the migration starts
    # already have the ``server_default`` of ``'{}'`` so they need no
    # backfill; the ``WHERE id > :last_id`` cursor naturally excludes them.
    conn = op.get_bind()
    select_stmt = sa.text(
        "SELECT id, analysis_state, analysis_state_message, "
        "       analysis_started_at, analysis_completed_at "
        "FROM vr_targets "
        "WHERE id > :last_id "
        "ORDER BY id "
        "LIMIT :chunk_rows",
    )
    update_stmt = sa.text(
        "UPDATE vr_targets SET analysis_stages_json = :payload "
        "WHERE id = :id",
    )
    last_id = 0
    while True:
        rows = conn.execute(
            select_stmt,
            {"last_id": last_id, "chunk_rows": _BACKFILL_CHUNK_ROWS},
        ).all()
        if not rows:
            break
        payloads = [
            {
                "id": row[0],
                "payload": json.dumps(
                    _stages_from_legacy(
                        state=row[1] or "pending",
                        message=row[2],
                        started_at=row[3],
                        completed_at=row[4],
                    ),
                ),
            }
            for row in rows
        ]
        # SQLAlchemy 2.x issues a single executemany round-trip when the
        # bind is a list of parameter dicts.
        conn.execute(update_stmt, payloads)
        last_id = rows[-1][0]
        if len(rows) < _BACKFILL_CHUNK_ROWS:
            break


# Chunk size for the ID-cursored backfill loop above. Sized to keep the
# in-memory row buffer well below 10 MB even for pathological state-message
# payloads while still amortising the SELECT round-trip cost.
_BACKFILL_CHUNK_ROWS = 500


def downgrade() -> None:
    op.drop_column("vr_targets", "analysis_stages_json")


def _iso(ts) -> str | None:
    if ts is None:
        return None
    if hasattr(ts, "isoformat"):
        return ts.isoformat()
    return str(ts)


def _empty_stage() -> dict[str, object]:
    return {
        "state": "pending",
        "started_at": None,
        "completed_at": None,
        "attempts": 0,
        "error": None,
    }


def _stages_from_legacy(
    *,
    state: str,
    message: str | None,
    started_at,
    completed_at,
) -> dict[str, object]:
    """Map legacy single-column state into the three-stage struct."""
    ingestion = _empty_stage()
    capability = _empty_stage()
    ranking = _empty_stage()

    if state == "ready":
        for stage in (ingestion, capability, ranking):
            stage["state"] = "done"
            stage["attempts"] = 1
            stage["started_at"] = _iso(started_at)
            stage["completed_at"] = _iso(completed_at)
    elif state == "failed":
        # We can't tell which stage failed without a stage tag on
        # analysis_state_message; assume ingestion (the first stage)
        # since it's the most common failure point. Operator can re-
        # run analysis to actually find out via the new tracker.
        ingestion["state"] = "failed"
        ingestion["attempts"] = 1
        ingestion["started_at"] = _iso(started_at)
        ingestion["completed_at"] = _iso(completed_at)
        ingestion["error"] = message or "(legacy migration: stage unknown)"
    elif state == "ingesting":
        # Anything running at migration time will be picked up by the
        # reaper if it actually stalled. We default to RUNNING since
        # the legacy code has it as the in-flight marker.
        ingestion["state"] = "running"
        ingestion["attempts"] = 1
        ingestion["started_at"] = _iso(started_at)
    # state == "pending" → all three stay pending (default empty)
    return {
        "ingestion": ingestion,
        "capability_profile": capability,
        "function_ranking": ranking,
    }
