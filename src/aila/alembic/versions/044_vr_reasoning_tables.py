"""044 — VR reasoning subsystem foundation (M3.R-1).

Creates four new tables for the reasoning subsystem:
  vr_investigations          — one operator-initiated reasoning session
  vr_investigation_branches  — per-investigation hypothesis branches (D-41)
  vr_investigation_messages  — conversational messages (D-43)
  vr_investigation_outcomes  — typed outcomes (D-43, 11 kinds)

Audit memos (D-38) do NOT get a dedicated table — they ride on the
existing platform KnowledgeEntryRecord (pgvector 384-dim + HNSW +
tsvector FTS) via namespace ``vr.audit_memo.<scope>``. No new vector
store.

Revision ID: 044_vr_reasoning_tables
Revises: 043_vr_projects_target_fk
Create Date: 2026-05-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "044_vr_reasoning_tables"
down_revision: str | None = "043_vr_projects_target_fk"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vr_investigations",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("team_id", sa.Text(), nullable=True),
        sa.Column("project_id", sa.String(64), nullable=True),
        sa.Column(
            "parent_investigation_id", sa.String(64),
            sa.ForeignKey("vr_investigations.id"), nullable=True,
        ),
        sa.Column(
            "target_id", sa.String(64),
            sa.ForeignKey("vr_targets.id"), nullable=False,
        ),
        sa.Column("secondary_target_refs_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("kind", sa.String(32), nullable=False, server_default="discovery"),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("initial_question", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(32), nullable=False, server_default="created"),
        sa.Column("pause_reason", sa.String(32), nullable=True),
        sa.Column("auto_pilot", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "strategy_family", sa.String(64), nullable=False,
            server_default="vulnerability_research.discovery_research",
        ),
        sa.Column("persona_dispatch_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("cost_budget_usd", sa.Float(), nullable=False, server_default="50.0"),
        sa.Column("cost_actual_usd", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("llm_tokens_cost_usd", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("mcp_calls_cost_usd", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("fuzz_infra_cost_usd", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("primary_outcome_id", sa.String(64), nullable=True),
        sa.Column("linked_campaign_ids_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("linked_finding_ids_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stopped_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vr_investigations_team_id", "vr_investigations", ["team_id"])
    op.create_index("ix_vr_investigations_project_id", "vr_investigations", ["project_id"])
    op.create_index("ix_vr_investigations_parent", "vr_investigations", ["parent_investigation_id"])
    op.create_index("ix_vr_investigations_target_id", "vr_investigations", ["target_id"])
    op.create_index("ix_vr_investigations_kind", "vr_investigations", ["kind"])
    op.create_index("ix_vr_investigations_status", "vr_investigations", ["status"])

    op.create_table(
        "vr_investigation_branches",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "investigation_id", sa.String(64),
            sa.ForeignKey("vr_investigations.id"), nullable=False,
        ),
        sa.Column(
            "parent_branch_id", sa.String(64),
            sa.ForeignKey("vr_investigation_branches.id"), nullable=True,
        ),
        sa.Column(
            "merged_into_branch_id", sa.String(64),
            sa.ForeignKey("vr_investigation_branches.id"), nullable=True,
        ),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("persona_voice", sa.String(32), nullable=True),
        sa.Column("fork_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("fork_at_turn", sa.Integer(), nullable=True),
        sa.Column("case_state_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("branch_cost_usd", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("turn_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("closed_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("promoted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vr_branches_investigation_id", "vr_investigation_branches", ["investigation_id"])
    op.create_index("ix_vr_branches_parent", "vr_investigation_branches", ["parent_branch_id"])
    op.create_index("ix_vr_branches_merged_into", "vr_investigation_branches", ["merged_into_branch_id"])
    op.create_index("ix_vr_branches_status", "vr_investigation_branches", ["status"])

    op.create_table(
        "vr_investigation_messages",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "investigation_id", sa.String(64),
            sa.ForeignKey("vr_investigations.id"), nullable=False,
        ),
        sa.Column(
            "branch_id", sa.String(64),
            sa.ForeignKey("vr_investigation_branches.id"), nullable=False,
        ),
        sa.Column("sender_kind", sa.String(16), nullable=False),
        sa.Column("sender_id", sa.String(64), nullable=True),
        sa.Column("payload_kind", sa.String(32), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("operator_intent", sa.String(32), nullable=True),
        sa.Column("at_turn", sa.Integer(), nullable=True),
        sa.Column("evidence_refs_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vr_messages_investigation_id", "vr_investigation_messages", ["investigation_id"])
    op.create_index("ix_vr_messages_branch_id", "vr_investigation_messages", ["branch_id"])
    op.create_index("ix_vr_messages_payload_kind", "vr_investigation_messages", ["payload_kind"])
    op.create_index("ix_vr_messages_created_at", "vr_investigation_messages", ["created_at"])

    op.create_table(
        "vr_investigation_outcomes",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "investigation_id", sa.String(64),
            sa.ForeignKey("vr_investigations.id"), nullable=False,
        ),
        sa.Column(
            "branch_id", sa.String(64),
            sa.ForeignKey("vr_investigation_branches.id"), nullable=False,
        ),
        sa.Column("outcome_kind", sa.String(32), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("evidence_refs_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("accepted_by_operator", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dispatch_status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("dispatch_target", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vr_outcomes_investigation_id", "vr_investigation_outcomes", ["investigation_id"])
    op.create_index("ix_vr_outcomes_branch_id", "vr_investigation_outcomes", ["branch_id"])
    op.create_index("ix_vr_outcomes_kind", "vr_investigation_outcomes", ["outcome_kind"])
    op.create_index("ix_vr_outcomes_dispatch_status", "vr_investigation_outcomes", ["dispatch_status"])


def downgrade() -> None:
    op.drop_index("ix_vr_outcomes_dispatch_status", table_name="vr_investigation_outcomes")
    op.drop_index("ix_vr_outcomes_kind", table_name="vr_investigation_outcomes")
    op.drop_index("ix_vr_outcomes_branch_id", table_name="vr_investigation_outcomes")
    op.drop_index("ix_vr_outcomes_investigation_id", table_name="vr_investigation_outcomes")
    op.drop_table("vr_investigation_outcomes")

    op.drop_index("ix_vr_messages_created_at", table_name="vr_investigation_messages")
    op.drop_index("ix_vr_messages_payload_kind", table_name="vr_investigation_messages")
    op.drop_index("ix_vr_messages_branch_id", table_name="vr_investigation_messages")
    op.drop_index("ix_vr_messages_investigation_id", table_name="vr_investigation_messages")
    op.drop_table("vr_investigation_messages")

    op.drop_index("ix_vr_branches_status", table_name="vr_investigation_branches")
    op.drop_index("ix_vr_branches_merged_into", table_name="vr_investigation_branches")
    op.drop_index("ix_vr_branches_parent", table_name="vr_investigation_branches")
    op.drop_index("ix_vr_branches_investigation_id", table_name="vr_investigation_branches")
    op.drop_table("vr_investigation_branches")

    op.drop_index("ix_vr_investigations_status", table_name="vr_investigations")
    op.drop_index("ix_vr_investigations_kind", table_name="vr_investigations")
    op.drop_index("ix_vr_investigations_target_id", table_name="vr_investigations")
    op.drop_index("ix_vr_investigations_parent", table_name="vr_investigations")
    op.drop_index("ix_vr_investigations_project_id", table_name="vr_investigations")
    op.drop_index("ix_vr_investigations_team_id", table_name="vr_investigations")
    op.drop_table("vr_investigations")
