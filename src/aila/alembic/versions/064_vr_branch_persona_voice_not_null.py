"""vr_branch_persona_voice_not_null — close §180.

Backfills NULL ``vr_investigation_branches.persona_voice`` rows with the
structural marker ``'unspecified'`` and adds a NOT NULL constraint.

Closes §180 (DB-level guarantee that every branch row carries either a
real persona (halvar/maddie/yuki/renzo/noor/wei) or a structural marker
(``primary``/``fork_unnamed``/``merge_result``/``unspecified``)).

Pairs with §177 + §178 (commit ``beb2d31``) which made the Python
writers never emit NULL for new rows. This migration retrofits the
constraint at the schema level so a future writer regression cannot
silently insert NULL again — Postgres rejects it at INSERT time.

The default literal stays at the column level so any ORM caller that
omits ``persona_voice`` ends up with ``'unspecified'`` rather than a
constraint violation. Operator runs the migration; this file only
declares it.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "064_vr_branch_persona_voice_not_null"
down_revision = "063_vr_auto_steering_dedup_key"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Backfill existing NULL rows. A branch that pre-dates §177/§178
    #    will have persona_voice=NULL. ``'unspecified'`` is the catch-all
    #    marker — distinct from ``'fork_unnamed'`` (caller forgot to
    #    pass one) and ``'merge_result'`` (structural merge child) so
    #    the operator can grep historical leakage.
    op.execute(
        "UPDATE vr_investigation_branches "
        "SET persona_voice = 'unspecified' "
        "WHERE persona_voice IS NULL",
    )

    # 2. Tighten to NOT NULL with a server-side default so any future
    #    INSERT that omits the column lands on ``'unspecified'`` instead
    #    of failing. The Python writers (§177/§178) always supply a
    #    value, but a defensive server_default catches schema-bypass
    #    INSERTs (raw SQL fixtures, future bulk-loaders).
    op.alter_column(
        "vr_investigation_branches",
        "persona_voice",
        existing_type=sa.String(length=32),
        nullable=False,
        server_default=sa.text("'unspecified'"),
    )


def downgrade() -> None:
    # Drop the NOT NULL + server_default. Pre-existing 'unspecified'
    # backfill rows are NOT reverted to NULL — that's lossy and the
    # marker is semantically meaningful.
    op.alter_column(
        "vr_investigation_branches",
        "persona_voice",
        existing_type=sa.String(length=32),
        nullable=True,
        server_default=None,
    )
