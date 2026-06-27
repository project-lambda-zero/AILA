"""task_records_input_hash_unique -- close §72.

Adds a partial UNIQUE index on ``taskrecord.input_hash`` so the SHA-256
dedup at ``platform/tasks/queue.py:submit`` is enforced by Postgres, not
just by the SELECT-then-INSERT TOCTOU read above the INSERT.

Two concurrent ``submit()`` calls with identical fn+kwargs both used to
compute the same input_hash, both saw "no existing row" in their own
dedup session, and both inserted. Result: two duplicate ARQ jobs for
the same workflow; the operator paid for the loser before the engine's
optimistic-lock filtered it at cursor-advance time.

The index is PARTIAL -- it only enforces uniqueness for rows in active
states (``queued``, ``running``, ``waiting``). Terminal tasks may carry
the same hash legitimately because the operator re-submitted the same
work after the prior task completed.

queue.py catches IntegrityError at INSERT time and treats it as a dedup
hit (returns the existing TaskHandle for the concurrent submitter), so
no operator-facing error surfaces from the constraint.

Pairs with §73 (queue.py drops ``default=str`` so two semantically
different kwargs sets cannot stringify-collide into the same hash).
"""
from __future__ import annotations

from alembic import op

revision = "065_task_records_input_hash_unique"
down_revision = "064_vr_branch_persona_voice_not_null"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Partial unique index -- Postgres-only syntax via raw SQL. The
    # SQLAlchemy ORM doesn't model partial uniqueness portably, so we
    # drive it with op.execute and a stable index name the cursor
    # reaper / orphan-queued sweep can reason about.
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_task_records_input_hash_unique "
        "ON taskrecord (input_hash) "
        "WHERE input_hash IS NOT NULL "
        "AND status IN ('queued', 'running', 'waiting')",
    )


def downgrade() -> None:
    op.execute(
        "DROP INDEX IF EXISTS ix_task_records_input_hash_unique",
    )
