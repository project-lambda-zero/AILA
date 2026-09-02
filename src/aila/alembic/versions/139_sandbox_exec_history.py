"""139 -- sandbox_exec_history table for req 33.

Adds ``sandbox_exec_history`` -- one row per successful admin sandbox
exec dispatch, capturing argv, exit code, timing, and result flags for
the RecentExecutionsPanel readout. The table records the shape of the
call and the acting admin; stdin, stdout, and stderr are never stored.

The admin sandbox is a shared platform resource, so the table is not
team-scoped. Grants mirror migration 105 so the operator dashboard
running under the ``aila_app`` role can read the history.

Revision ID: 139_sandbox_exec_history
Revises: 138_managed_system_role
Create Date: 2026-08-25
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "139_sandbox_exec_history"
down_revision: str | None = "138_managed_system_role"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.create_table(
        "sandbox_exec_history",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("actor_user_id", sa.Text(), nullable=True),
        sa.Column("argv", postgresql.JSONB(), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("duration_s", sa.Float(), nullable=False),
        sa.Column("timed_out", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("oom", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_sandbox_exec_history_created_at",
        "sandbox_exec_history",
        ["created_at"],
    )
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aila_app') THEN
                EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON sandbox_exec_history TO aila_app';
            END IF;
        END
        $$;
    """))


def downgrade() -> None:
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aila_app') THEN
                EXECUTE 'REVOKE SELECT, INSERT, UPDATE, DELETE ON sandbox_exec_history FROM aila_app';
            END IF;
        END
        $$;
    """))
    op.drop_index(
        "ix_sandbox_exec_history_created_at",
        table_name="sandbox_exec_history",
    )
    op.drop_table("sandbox_exec_history")
