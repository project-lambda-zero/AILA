"""024 -- workflow_state_transitions (Phase 178).

Append-only audit/replay log for the durable workflows engine. Every
``entered`` / ``exited:*`` event writes one row. Composite primary key
(run_id, seq) -- the implicit PK index covers (run_id, seq) lookups, so
no redundant ``ix_wst_run_id`` is declared (minor-flag #1).

Secondary index ``ix_wst_to_state_happened_at`` on
``(to_state, happened_at DESC)`` (D-43) serves admin UI queries in Phase
181 and the engine-internal ``has_state_ever_completed`` lookup planned
for Phase 180 module handlers. The DESC direction is expressed here via
raw SQL because ``op.create_index`` did not support per-column direction
in older Alembic releases.

Orphan ``entered`` rows with no matching ``exited:*`` are the intentional
crash signal (D-41) -- they are NOT cleaned up. Operators see them as
"we entered this state and died before leaving".

Revision ID: 024_workflow_state_transitions
Revises: 023_workflow_state_cursor
Create Date: 2026-04-12
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "024_workflow_state_transitions"
down_revision: str | None = "023_workflow_state_cursor"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workflow_state_transitions",
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        # State/event identifiers bounded at 128 chars (Phase 178 security
        # fix: prevents unbounded audit-row writes via crafted state names).
        sa.Column("from_state", sa.String(128), nullable=False),
        sa.Column("to_state", sa.String(128), nullable=False),
        sa.Column("event", sa.String(64), nullable=False),
        sa.Column("input_hash", sa.String(64), nullable=True),
        sa.Column("output_hash", sa.String(64), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error_class", sa.String(128), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "happened_at",
            sa.DateTime(timezone=True),
            nullable=False,
            # server_default must be a literal SQL fragment, not a Function
            # clause (Phase 178 fix pass).
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("run_id", "seq"),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["workflowrunrecord.id"],
            name="fk_workflow_state_transitions_run_id",
        ),
    )
    # D-43: DESC index for admin-query reverse-chronological walks.
    op.execute(
        "CREATE INDEX ix_wst_to_state_happened_at "
        "ON workflow_state_transitions (to_state, happened_at DESC)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_wst_to_state_happened_at")
    op.drop_table("workflow_state_transitions")
