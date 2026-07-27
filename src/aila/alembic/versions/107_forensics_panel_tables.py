"""107 -- forensics panel spine tables (#18).

Creates four new tables that give the forensics module the same
panel-of-roles + sibling-review-quorum spine that VR and malware run on
(RFC-02 / RFC-04). Prior to this migration the forensics module drove
its investigations as a bare Think-Act-Observe loop
(``HonestInvestigator``) with no per-role branching and no
quorum-gated draft outcomes.

  * ``forensics_investigation_branches`` -- one panel branch per role
    (researcher / critic / implementer), analogous to
    ``vr_investigation_branches``.
  * ``forensics_investigation_messages`` -- system / operator / engine
    messages on a panel branch (draft-review requests, quorum notices).
  * ``forensics_investigation_outcomes`` -- typed outcomes emitted by a
    branch; carries the ``state`` lifecycle (draft / approved /
    rejected / dispatched) migration 062 introduced for VR.
  * ``forensics_outcome_reviews`` -- one row per sibling vote on a draft
    outcome; ``UNIQUE(outcome_id, reviewer_branch_id)`` guarantees one
    vote per (outcome, branch).

Every constraint carries a ``forensics_`` prefix so it never collides
with the identically shaped VR / malware objects (RFC-00 Common Mistake
#21). The parent investigation row keeps living on the pre-existing
``forensics_investigations`` table -- the panel just spawns branches
against it.

Revision ID: 107_forensics_panel_tables
Revises:     106_workflowrun_json_to_jsonb
Create Date: 2026-07-27
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "107_forensics_panel_tables"
down_revision: str | None = "106_workflowrun_json_to_jsonb"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.create_table(
        "forensics_investigation_branches",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("forensics_investigations.id"),
            nullable=False,
        ),
        sa.Column(
            "parent_branch_id",
            sa.String(64),
            sa.ForeignKey("forensics_investigation_branches.id"),
            nullable=True,
        ),
        sa.Column(
            "merged_into_branch_id",
            sa.String(64),
            sa.ForeignKey("forensics_investigation_branches.id"),
            nullable=True,
        ),
        sa.Column(
            "status", sa.String(32), nullable=False, server_default="active",
        ),
        sa.Column(
            "persona_voice",
            sa.String(32),
            nullable=False,
            server_default="unspecified",
        ),
        sa.Column("strategy_family", sa.String(128), nullable=True),
        sa.Column("fork_reason", sa.Text(), nullable=True, server_default=""),
        sa.Column("fork_at_turn", sa.Integer(), nullable=True),
        sa.Column(
            "case_state_json", sa.Text(), nullable=True, server_default="{}",
        ),
        sa.Column(
            "branch_cost_usd", sa.Float(), nullable=False, server_default="0.0",
        ),
        sa.Column("turn_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("closed_reason", sa.Text(), nullable=True, server_default=""),
        sa.Column(
            "promoted", sa.Boolean(), nullable=False, server_default=sa.false(),
        ),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_forensics_branches_investigation_id",
        "forensics_investigation_branches",
        ["investigation_id"],
    )
    op.create_index(
        "ix_forensics_branches_parent",
        "forensics_investigation_branches",
        ["parent_branch_id"],
    )
    op.create_index(
        "ix_forensics_branches_merged_into",
        "forensics_investigation_branches",
        ["merged_into_branch_id"],
    )
    op.create_index(
        "ix_forensics_branches_status",
        "forensics_investigation_branches",
        ["status"],
    )
    op.create_index(
        "ix_forensics_branches_strategy_family",
        "forensics_investigation_branches",
        ["strategy_family"],
    )

    op.create_table(
        "forensics_investigation_messages",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("forensics_investigations.id"),
            nullable=False,
        ),
        sa.Column(
            "branch_id",
            sa.String(64),
            sa.ForeignKey("forensics_investigation_branches.id"),
            nullable=False,
        ),
        sa.Column("sender_kind", sa.String(16), nullable=False),
        sa.Column("sender_id", sa.String(64), nullable=True),
        sa.Column("payload_kind", sa.String(32), nullable=False),
        sa.Column(
            "payload_json", sa.Text(), nullable=True, server_default="{}",
        ),
        sa.Column("operator_intent", sa.String(32), nullable=True),
        sa.Column("at_turn", sa.Integer(), nullable=True),
        sa.Column(
            "evidence_refs_json", sa.Text(), nullable=True, server_default="[]",
        ),
        sa.Column("auto_steering_key", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_forensics_messages_investigation_id",
        "forensics_investigation_messages",
        ["investigation_id"],
    )
    op.create_index(
        "ix_forensics_messages_branch_id",
        "forensics_investigation_messages",
        ["branch_id"],
    )
    op.create_index(
        "ix_forensics_messages_payload_kind",
        "forensics_investigation_messages",
        ["payload_kind"],
    )
    op.create_index(
        "ix_forensics_messages_created_at",
        "forensics_investigation_messages",
        ["created_at"],
    )

    op.create_table(
        "forensics_investigation_outcomes",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("forensics_investigations.id"),
            nullable=False,
        ),
        sa.Column(
            "branch_id",
            sa.String(64),
            sa.ForeignKey("forensics_investigation_branches.id"),
            nullable=False,
        ),
        sa.Column("outcome_kind", sa.String(32), nullable=False),
        sa.Column(
            "payload_json", sa.Text(), nullable=True, server_default="{}",
        ),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column(
            "evidence_refs_json", sa.Text(), nullable=True, server_default="[]",
        ),
        sa.Column(
            "accepted_by_operator",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "state",
            sa.String(16),
            nullable=False,
            server_default="draft",
        ),
        sa.Column(
            "dispatch_status",
            sa.String(16),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("dispatch_target", sa.String(128), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_forensics_outcomes_investigation_id",
        "forensics_investigation_outcomes",
        ["investigation_id"],
    )
    op.create_index(
        "ix_forensics_outcomes_branch_id",
        "forensics_investigation_outcomes",
        ["branch_id"],
    )
    op.create_index(
        "ix_forensics_outcomes_kind",
        "forensics_investigation_outcomes",
        ["outcome_kind"],
    )
    op.create_index(
        "ix_forensics_outcomes_state",
        "forensics_investigation_outcomes",
        ["state"],
    )
    op.create_index(
        "ix_forensics_outcomes_dispatch_status",
        "forensics_investigation_outcomes",
        ["dispatch_status"],
    )

    op.create_table(
        "forensics_outcome_reviews",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "outcome_id",
            sa.String(length=36),
            sa.ForeignKey(
                "forensics_investigation_outcomes.id",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column(
            "reviewer_branch_id",
            sa.String(length=36),
            sa.ForeignKey(
                "forensics_investigation_branches.id",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("reviewer_persona", sa.String(length=64), nullable=False),
        sa.Column("vote", sa.String(length=16), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True, server_default=""),
        sa.Column(
            "suggested_edits_json",
            sa.Text(),
            nullable=True,
            server_default="{}",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint(
            "outcome_id",
            "reviewer_branch_id",
            name="uq_forensics_outcome_reviews_outcome_reviewer",
        ),
    )
    op.create_index(
        "ix_forensics_outcome_reviews_outcome",
        "forensics_outcome_reviews",
        ["outcome_id"],
    )
    op.create_index(
        "ix_forensics_outcome_reviews_vote",
        "forensics_outcome_reviews",
        ["vote"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_forensics_outcome_reviews_vote",
        table_name="forensics_outcome_reviews",
    )
    op.drop_index(
        "ix_forensics_outcome_reviews_outcome",
        table_name="forensics_outcome_reviews",
    )
    op.drop_table("forensics_outcome_reviews")

    op.drop_index(
        "ix_forensics_outcomes_dispatch_status",
        table_name="forensics_investigation_outcomes",
    )
    op.drop_index(
        "ix_forensics_outcomes_state",
        table_name="forensics_investigation_outcomes",
    )
    op.drop_index(
        "ix_forensics_outcomes_kind",
        table_name="forensics_investigation_outcomes",
    )
    op.drop_index(
        "ix_forensics_outcomes_branch_id",
        table_name="forensics_investigation_outcomes",
    )
    op.drop_index(
        "ix_forensics_outcomes_investigation_id",
        table_name="forensics_investigation_outcomes",
    )
    op.drop_table("forensics_investigation_outcomes")

    op.drop_index(
        "ix_forensics_messages_created_at",
        table_name="forensics_investigation_messages",
    )
    op.drop_index(
        "ix_forensics_messages_payload_kind",
        table_name="forensics_investigation_messages",
    )
    op.drop_index(
        "ix_forensics_messages_branch_id",
        table_name="forensics_investigation_messages",
    )
    op.drop_index(
        "ix_forensics_messages_investigation_id",
        table_name="forensics_investigation_messages",
    )
    op.drop_table("forensics_investigation_messages")

    op.drop_index(
        "ix_forensics_branches_strategy_family",
        table_name="forensics_investigation_branches",
    )
    op.drop_index(
        "ix_forensics_branches_status",
        table_name="forensics_investigation_branches",
    )
    op.drop_index(
        "ix_forensics_branches_merged_into",
        table_name="forensics_investigation_branches",
    )
    op.drop_index(
        "ix_forensics_branches_parent",
        table_name="forensics_investigation_branches",
    )
    op.drop_index(
        "ix_forensics_branches_investigation_id",
        table_name="forensics_investigation_branches",
    )
    op.drop_table("forensics_investigation_branches")
