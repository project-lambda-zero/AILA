"""vr_auto_steering_dedup_key -- exact-key dedup column for auto-steering messages.

Adds:
  - ``vr_investigation_messages.auto_steering_key`` (nullable VARCHAR(128))
  - ``ix_vr_investigation_messages_auto_steering_key``
    (composite index on ``(investigation_id, auto_steering_key)`` for the
    dedup query in :func:`aila.modules.vr.agents.auto_steering._already_posted`)
  - ``uq_vr_investigation_messages_auto_steering_key``
    UNIQUE constraint on ``(investigation_id, auto_steering_key)`` so the
    fire-then-check race (§338) collapses to ``ON CONFLICT DO NOTHING`` at
    insert time. NULL values are excluded via the partial-index clause so
    regular operator/engine messages (no ``auto_steering_key``) are not
    constrained.

Closes §331, §332 (dedup window was LIMIT 40 -- too small for 6-branch
fan-out; now exact-match indexed lookup is O(log n)) and §338 (race
between ``_already_posted`` and ``_post`` for two concurrent rule hits
on the same key).

Pre-existing rows are unaffected -- the column defaults NULL.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "063_vr_auto_steering_dedup_key"
down_revision = "062_vr_outcome_review"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vr_investigation_messages",
        sa.Column("auto_steering_key", sa.String(length=128), nullable=True),
    )
    # Composite index for the dedup query: exact-match on
    # (investigation_id, auto_steering_key) is O(log n) on this index.
    op.create_index(
        "ix_vr_investigation_messages_auto_steering_key",
        "vr_investigation_messages",
        ["investigation_id", "auto_steering_key"],
    )
    # Partial unique constraint: only enforce uniqueness when the column
    # is set. Regular messages (NULL) are not constrained. PostgreSQL
    # honours WHERE clauses on UNIQUE indexes; on SQLite the WHERE clause
    # is also accepted (tests use SQLite in-memory). MySQL does not
    # support partial indexes -- this codebase targets PostgreSQL.
    op.create_index(
        "uq_vr_investigation_messages_auto_steering_key",
        "vr_investigation_messages",
        ["investigation_id", "auto_steering_key"],
        unique=True,
        postgresql_where=sa.text("auto_steering_key IS NOT NULL"),
        sqlite_where=sa.text("auto_steering_key IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_vr_investigation_messages_auto_steering_key",
        table_name="vr_investigation_messages",
    )
    op.drop_index(
        "ix_vr_investigation_messages_auto_steering_key",
        table_name="vr_investigation_messages",
    )
    op.drop_column("vr_investigation_messages", "auto_steering_key")
