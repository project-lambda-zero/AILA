"""127 -- add ``managedsystemrecord.private_key_passphrase_secret_id``.

Adds a nullable ``TEXT`` column that stores the SecretRecord id for
the SSH private-key passphrase entered when registering or updating a
system. Prior to this migration the API accepted a ``private_key_passphrase``
field on ``SystemCreateRequest`` / ``SystemUpdateRequest`` but silently
dropped it -- no column existed to hold the secret pointer, so
encrypted PEMs that required a passphrase could never be unlocked by
``paramiko.SSHClient.connect`` and every scan against such a system
failed at auth time.

Nullable so that existing rows (which store no passphrase) survive the
upgrade untouched. Table-existence is guarded via ``sa.inspect`` to
mirror the pattern in 115 / 126 so a fresh test bootstrap without
``managedsystemrecord`` becomes a no-op instead of a crash.

Revision ID: 127_managed_system_passphrase_secret
Revises:     126_drop_result_path
Create Date: 2026-08-16
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "127_managed_system_passphrase_secret"
down_revision: str | None = "126_drop_result_path"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "managedsystemrecord"
_COLUMN: str = "private_key_passphrase_secret_id"


def _table_present() -> bool:
    inspector = sa.inspect(op.get_bind())
    return _TABLE in set(inspector.get_table_names())


def upgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} ADD COLUMN IF NOT EXISTS {_COLUMN} TEXT"
    ))


def downgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS {_COLUMN}"
    ))
