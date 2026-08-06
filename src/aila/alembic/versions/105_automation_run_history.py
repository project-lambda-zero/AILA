"""105 -- automation_run_records table for #46 exactly-once + run-history.

Adds ``automation_run_records`` with a ``UNIQUE(schedule_id,
occurrence_at)`` constraint. The uniqueness is both the run-history
contract AND the second-order distributed-lock backstop when the
Redis lock backend (``platform/automation/lock.py``) is unavailable:
the runner degrades to inserting the row directly and whichever
process wins the INSERT owns the occurrence -- every peer sees
``IntegrityError`` and skips.

The constraint name is module-prefixed per CLAUDE.md common mistake #21
(constraint names are unique per schema, not per table).

Revision ID: 105_automation_run_history
Revises: 104_workflowrun_json_validity_check
Create Date: 2026-07-27
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "105_automation_run_history"
down_revision: str | None = "104_workflowrun_json_validity_check"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.create_table(
        "automation_run_records",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("schedule_id", sa.Text(), nullable=False, index=True),
        sa.Column("occurrence_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("task_id", sa.Text(), nullable=True),
        sa.Column("runner_id", sa.Text(), nullable=True),
        sa.UniqueConstraint(
            "schedule_id",
            "occurrence_at",
            name="uq_automation_run_schedule_occurrence",
        ),
    )
    op.create_index(
        "ix_automation_run_records_started_at",
        "automation_run_records",
        ["started_at"],
    )
    # Grant to aila_app if the role exists (mirrors migration 012 shape so
    # the operator dashboard behind the app role can read run-history).
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aila_app') THEN
                EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON automation_run_records TO aila_app';
            END IF;
        END
        $$;
    """))


def downgrade() -> None:
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aila_app') THEN
                EXECUTE 'REVOKE SELECT, INSERT, UPDATE, DELETE ON automation_run_records FROM aila_app';
            END IF;
        END
        $$;
    """))
    op.drop_index(
        "ix_automation_run_records_started_at",
        table_name="automation_run_records",
    )
    op.drop_table("automation_run_records")
