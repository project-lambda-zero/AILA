"""137 -- add ``actions_json`` to ``session_message_records`` (req 25).

The platform ``dante`` console agent proposes zero or more DanteAction
objects on each assistant turn. The router persists them alongside
the reply text in a new nullable Text column, ``actions_json``, that
holds the JSON-encoded action list. Legacy rows (and user turns) keep
NULL; the frontend treats NULL as an empty list.

Both the ADD and DROP steps are guarded via
``sa.inspect(...).has_table(...)`` + a column-name scan so a re-run,
or a deployment where migration 136 has not been applied, is a
graceful no-op instead of a hard error.

Revision ID: 137_session_message_actions
Revises:     136_consolidate_mcp_call_log
Create Date: 2026-08-25
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "137_session_message_actions"
down_revision: str | None = "136_consolidate_mcp_call_log"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "session_message_records"
_COLUMN: str = "actions_json"


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _has_column(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(table):
        return False
    return any(col["name"] == column for col in inspector.get_columns(table))


def upgrade() -> None:
    if not _has_table(_TABLE):
        return
    if _has_column(_TABLE, _COLUMN):
        return
    op.add_column(
        _TABLE,
        sa.Column(_COLUMN, sa.Text(), nullable=True),
    )


def downgrade() -> None:
    if not _has_column(_TABLE, _COLUMN):
        return
    op.drop_column(_TABLE, _COLUMN)
