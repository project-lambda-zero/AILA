"""026 — drop taskrecord.poison_attempts + checkpoint_json (Phase 179).

v5.0 migration. Runs AFTER marking all non-terminal TaskRecord rows as
FAILED (they cannot use the new workflow cursor table; operators must
resubmit). Irreversible: ``poison_attempts`` was an ephemeral counter;
``checkpoint_json`` is replaced by ``workflow_state_cursor`` (migration 023).
``downgrade()`` raises.

Revision ID: 026_drop_legacy_task_columns
Revises: 025_workflow_run_plan_json
Create Date: 2026-04-12
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "026_drop_legacy_task_columns"
down_revision: str | None = "025_workflow_run_plan_json"
branch_labels = None
depends_on = None

# D-26: rows in these statuses at migration time cannot be resumed under
# the new workflow cursor table. Mark them FAILED with a distinctive error
# so operators see what was in flight and can resubmit.
NON_TERMINAL_STATUSES: tuple[str, ...] = ("queued", "waiting", "running", "paused")
MIGRATION_ERROR: str = "v5.0 migration — resubmit"


def upgrade() -> None:
    conn = op.get_bind()
    # Step 1: bulk-mark non-terminal rows as FAILED (D-26). Use a bound
    # parameter with expanding=True for the IN clause so the query is safe
    # across dialects.
    conn.execute(
        sa.text(
            "UPDATE taskrecord "
            "SET status = :new_status, "
            "    error = :msg, "
            "    completed_at = (NOW() AT TIME ZONE 'UTC'), "
            "    updated_at = (NOW() AT TIME ZONE 'UTC'), "
            "    version = version + 1 "
            "WHERE status IN :non_terminal"
        ).bindparams(
            sa.bindparam("non_terminal", expanding=True),
        ),
        {
            "new_status": "failed",
            "msg": MIGRATION_ERROR,
            "non_terminal": list(NON_TERMINAL_STATUSES),
        },
    )

    # Step 2: drop the legacy poison_attempts index, then the column.
    op.drop_index("ix_taskrecord_poison_attempts", table_name="taskrecord")
    op.drop_column("taskrecord", "poison_attempts")

    # Step 3: drop checkpoint_json (no index).
    op.drop_column("taskrecord", "checkpoint_json")


def downgrade() -> None:
    raise NotImplementedError(
        "026 is irreversible: poison_attempts was an ephemeral counter, "
        "and checkpoint_json is replaced by workflow_state_cursor "
        "(migration 023). Manual data reconstruction is not supported.",
    )
