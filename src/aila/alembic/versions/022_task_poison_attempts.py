"""022 -- taskrecord.poison_attempts + dead_letter status (Phase 178).

Adds a single integer counter to TaskRecord tracking how many times a job has
failed with an exception. The worker bumps this counter each time
execute_task_job catches an unhandled exception; when it crosses the
configured threshold (default 3), the task moves to the terminal ``dead_letter``
status and a copy of its enqueue payload is written to the Redis sorted set
``arq:dead-letter:{track}`` for later inspection or manual requeue.

No data migration is required: existing rows default to 0 and all new tasks
start at 0. The column is NOT NULL with a server-side default so in-flight
migrations remain backwards-compatible with older worker binaries (which
simply ignore the column).

Revision ID: 022_task_poison_attempts
Revises: 021_team_records
Create Date: 2026-04-12
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "022_task_poison_attempts"
down_revision: Union[str, None] = "021_team_records"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "taskrecord",
        sa.Column(
            "poison_attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.create_index(
        "ix_taskrecord_poison_attempts",
        "taskrecord",
        ["poison_attempts"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_taskrecord_poison_attempts", table_name="taskrecord")
    op.drop_column("taskrecord", "poison_attempts")
