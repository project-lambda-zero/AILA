"""023 -- workflow_state_cursor (Phase 178).

Creates the cursor table that holds the active state for each workflow run.
One row per run_id. Atomic updates via optimistic ``version`` lock:

    UPDATE workflow_state_cursor
       SET current_state = :s,
           state_input   = :i,
           retries_in_state = :r,
           definition_id = :d,
           version       = version + 1
     WHERE run_id = :rid
       AND version = :loaded_version;

A 0-row UPDATE means another worker advanced the cursor first; the engine
raises ``WorkflowConflictError`` (D-32), propagates to ARQ, which retries
the whole job. Next attempt reloads the cursor with the new version.

``run_id`` FKs to ``workflowrunrecord.id`` which is declared as a ``str``
SQLModel field and stored as VARCHAR at the PostgreSQL level; the FK
column type matches (D-42, minor-flag #2).

Revision ID: 023_workflow_state_cursor
Revises: 022_task_poison_attempts
Create Date: 2026-04-12
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "023_workflow_state_cursor"
down_revision: str | None = "022_task_poison_attempts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workflow_state_cursor",
        sa.Column("run_id", sa.String(), nullable=False),
        # State/definition identifiers are bounded at 128 chars (Phase 178
        # security fix): prevents unbounded writes to audit/cursor columns
        # that could amplify storage-based DoS. Pre-deletion migration, so
        # no data-migration path is required here.
        sa.Column("current_state", sa.String(128), nullable=False),
        sa.Column("state_input", postgresql.JSONB(), nullable=False),
        sa.Column(
            "retries_in_state",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("definition_id", sa.String(128), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            # server_default must be a literal SQL fragment (text()), not a
            # Function clause; Alembic/SQLAlchemy DDL rendering expects
            # `str | sa.text(...) | FetchedValue` here. See Phase 178 fix pass.
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "version",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.PrimaryKeyConstraint("run_id"),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["workflowrunrecord.id"],
            name="fk_workflow_state_cursor_run_id",
        ),
    )


def downgrade() -> None:
    op.drop_table("workflow_state_cursor")
