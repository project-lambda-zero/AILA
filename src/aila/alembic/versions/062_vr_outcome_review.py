"""vr_outcome_review -- sibling-corroborated draft outcome workflow.

Two schema changes for the draft-outcome lifecycle:

(1) ``vr_investigation_outcomes.state`` -- new column.
    Values: 'draft' | 'approved' | 'rejected' | 'dispatched'.
    New rows default to 'draft'. Pre-migration rows are backfilled to
    'dispatched' (legacy semantics: once a row existed in the old world
    it was already shipped, so the new gate must not retroactively
    block it). The column is nullable purely so the backfill UPDATE can
    run before the NOT NULL constraint is set.

(2) ``vr_outcome_reviews`` -- new table.
    One row per sibling review of a draft outcome.
    Vote enum: 'approve' | 'reject' | 'request_edit' | 'abstain'.
    UNIQUE(outcome_id, reviewer_branch_id) prevents a single branch
    from voting twice on the same outcome -- the latest vote replaces
    the prior one via UPSERT in the application layer.

    suggested_edits_json carries free-form proposed changes to the
    outcome payload (e.g. ``{"confidence": "weak"}``,
    ``{"claims[0].file_path": "actual/path.c"}``). Operator visibility
    only in v1 -- application of edits is operator-initiated, not
    automatic.

The dispatch gate (OutcomeDispatcher) refuses any outcome whose
state != 'approved'. The quorum evaluator flips state to 'approved'
once a configurable threshold of approve votes lands with zero
reject votes; a single reject flips state to 'rejected'. See
``aila.modules.vr.services.outcome_review`` for thresholds.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "062_vr_outcome_review"
down_revision = "061_llm_idempotency_cache"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # (1) Add state column nullable, backfill, then enforce NOT NULL.
    op.add_column(
        "vr_investigation_outcomes",
        sa.Column("state", sa.String(length=16), nullable=True),
    )
    op.execute(
        "UPDATE vr_investigation_outcomes SET state = 'dispatched' "
        "WHERE state IS NULL"
    )
    op.alter_column(
        "vr_investigation_outcomes",
        "state",
        existing_type=sa.String(length=16),
        nullable=False,
        server_default="draft",
    )
    op.create_index(
        "ix_vr_outcomes_state",
        "vr_investigation_outcomes",
        ["state"],
    )

    # (2) Create reviews table.
    op.create_table(
        "vr_outcome_reviews",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "outcome_id",
            sa.String(length=36),
            sa.ForeignKey(
                "vr_investigation_outcomes.id",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column(
            "reviewer_branch_id",
            sa.String(length=36),
            sa.ForeignKey(
                "vr_investigation_branches.id",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("reviewer_persona", sa.String(length=64), nullable=False),
        sa.Column("vote", sa.String(length=16), nullable=False),
        sa.Column("comment", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "suggested_edits_json",
            sa.Text(),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint(
            "outcome_id", "reviewer_branch_id",
            name="uq_vr_outcome_reviews_outcome_reviewer",
        ),
    )
    op.create_index(
        "ix_vr_outcome_reviews_outcome",
        "vr_outcome_reviews",
        ["outcome_id"],
    )
    op.create_index(
        "ix_vr_outcome_reviews_vote",
        "vr_outcome_reviews",
        ["vote"],
    )


def downgrade() -> None:
    op.drop_index("ix_vr_outcome_reviews_vote", table_name="vr_outcome_reviews")
    op.drop_index(
        "ix_vr_outcome_reviews_outcome", table_name="vr_outcome_reviews",
    )
    op.drop_table("vr_outcome_reviews")
    op.drop_index("ix_vr_outcomes_state", table_name="vr_investigation_outcomes")
    op.drop_column("vr_investigation_outcomes", "state")
