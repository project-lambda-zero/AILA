"""025 — workflow_run_records.plan_json (Phase 178).

Adds a nullable JSONB column to the ``workflowrunrecord`` table. Phase 178
does NOT populate this column; Phase 179's ``@platform_task`` wrapper will
write the frozen plan at the start of every run (D-07, D-38).

Why add it now? Adding a nullable column is a zero-downtime schema change
and lets Phase 179 land without schema churn. The engine itself does not
read or write this column.

Revision ID: 025_workflow_run_plan_json
Revises: 024_workflow_state_transitions
Create Date: 2026-04-12
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "025_workflow_run_plan_json"
down_revision: str | None = "024_workflow_state_transitions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "workflowrunrecord",
        sa.Column("plan_json", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("workflowrunrecord", "plan_json")
