"""138 -- add ``managedsystemrecord.role``.

Adds a NOT NULL ``TEXT`` column (default '') so the platform-owned
managed systems registry can carry a free-text role/kind
(examples: vuln-scan/analysis/poc/fuzz/forensics/sandbox) that a
module picker can filter on. An index on ``role`` supports the
list-endpoint filter added alongside this column.

Table-existence is guarded via ``sa.inspect`` to mirror the pattern
in 115 / 126 / 127 so a fresh test bootstrap without
``managedsystemrecord`` becomes a no-op instead of a crash.

Revision ID: 138_managed_system_role
Revises:     137_session_message_actions
Create Date: 2026-08-25
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "138_managed_system_role"
down_revision: str | None = "137_session_message_actions"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "managedsystemrecord"
_COLUMN: str = "role"
_INDEX: str = "ix_managedsystemrecord_role"


def _table_present() -> bool:
    inspector = sa.inspect(op.get_bind())
    return _TABLE in set(inspector.get_table_names())


def upgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} ADD COLUMN IF NOT EXISTS {_COLUMN} TEXT NOT NULL DEFAULT ''"
    ))
    op.execute(sa.text(
        f"CREATE INDEX IF NOT EXISTS {_INDEX} ON {_TABLE} ({_COLUMN})"
    ))


def downgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(
        f"DROP INDEX IF EXISTS {_INDEX}"
    ))
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS {_COLUMN}"
    ))
