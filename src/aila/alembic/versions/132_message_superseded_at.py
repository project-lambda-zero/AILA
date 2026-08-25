"""132 -- add superseded_at to investigation message tables (req 26).

Soft-supersede support: reset / re-enqueue / loser-branch cleanup stamp
``superseded_at`` instead of hard-deleting message rows, so an investigation's
transcript survives for display and audit while agent-context reads
reconstruct a clean slate by filtering ``superseded_at IS NULL``.

Additive and nullable, so existing rows read as active (NULL). Applied to the
three module message tables a migration creates; the ``_template`` scaffold's
message table is never created by any migration (its model carries the column
only for create_all-built scaffolds), so it is not touched here.

Revision ID: 132_message_superseded_at
Revises: 131_drop_sbd_nfr
Create Date: 2026-08-25
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "132_message_superseded_at"
down_revision: str | None = "131_drop_sbd_nfr"
branch_labels = None
depends_on = None

_MESSAGE_TABLES: tuple[str, ...] = (
    "vr_investigation_messages",
    "malware_investigation_messages",
    "forensics_investigation_messages",
)


def upgrade() -> None:
    for table in _MESSAGE_TABLES:
        op.add_column(
            table,
            sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index(
            f"ix_{table}_superseded_at", table, ["superseded_at"],
        )


def downgrade() -> None:
    for table in _MESSAGE_TABLES:
        op.drop_index(f"ix_{table}_superseded_at", table_name=table)
        op.drop_column(table, "superseded_at")
