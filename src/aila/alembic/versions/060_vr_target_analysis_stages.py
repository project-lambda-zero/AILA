"""vr_targets.analysis_stages_json — per-stage durable analysis state.

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

See `aila.modules.vr.contracts.target_stages` for the canonical schema.
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

    # Backfill existing rows. We deliberately go row-by-row in Python
    # rather than a single UPDATE so the schema-mapping logic lives in
    # one place (here) and matches the runtime contract bit-for-bit.
    conn = op.get_bind()
    rows = conn.execute(
        sa.text(
            "SELECT id, analysis_state, analysis_state_message, "
            "       analysis_started_at, analysis_completed_at "
            "FROM vr_targets",
        ),
    ).all()
    for row in rows:
        target_id = row[0]
        state = row[1] or "pending"
        message = row[2]
        started_at = row[3]
        completed_at = row[4]
        stages = _stages_from_legacy(
            state=state,
            message=message,
            started_at=started_at,
            completed_at=completed_at,
        )
        conn.execute(
            sa.text(
                "UPDATE vr_targets SET analysis_stages_json = :payload "
                "WHERE id = :id",
            ),
            {"payload": json.dumps(stages), "id": target_id},
        )


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
