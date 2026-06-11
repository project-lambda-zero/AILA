"""067 — workflow_state_cursor archived_state column for Phase B pause SSOT.

Phase B (per docs/MY_VIOLATIONS.md tail + docs/CUTOVER_DEPS.md §2) promotes
``workflow_state_cursor`` to the single source of truth for "is this
investigation paused right now". The cursor table gains one nullable
column, ``archived_state``, which preserves the prior ``current_state``
across a pause/resume cycle.

Pause protocol (single atomic txn):
    SELECT cursors FOR UPDATE WHERE run_id IN (...)
    UPDATE workflow_state_cursor
       SET archived_state = current_state,
           current_state  = '__paused__',
           updated_at     = now(),
           version        = version + 1
     WHERE run_id = :rid;

Resume protocol (single atomic txn, complement of pause):
    SELECT cursors FOR UPDATE WHERE current_state = '__paused__';
    UPDATE workflow_state_cursor
       SET current_state  = archived_state,
           archived_state = NULL,
           updated_at     = now(),
           version        = version + 1
     WHERE run_id = :rid;

The column is bounded at 128 chars matching ``current_state`` (Phase 178
security constraint). Backward compatible: existing cursors without
``archived_state`` resume from ``investigation_setup`` (or whatever the
caller passes as fallback) as today.

Revision ID: 067_workflow_state_cursor_archived_state
Revises: 066_task_records_status_check
Create Date: 2026-06-11
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "067_workflow_state_cursor_archived_state"
down_revision: str | None = "066_task_records_status_check"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "workflow_state_cursor",
        sa.Column("archived_state", sa.String(128), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("workflow_state_cursor", "archived_state")
