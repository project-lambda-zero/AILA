"""055 -- VR fuzz campaign proposals (operator-in-the-loop, pre-prepared).

Adds ``vr_fuzz_campaign_proposals`` -- the operator-facing queue of
fuzz suggestions emitted by reasoning agents. The audit-first
reasoning loop NEVER spins up a fuzz campaign on its own. When the
model identifies a function or region worth runtime exercise it emits
a CAMPAIGN_LAUNCH outcome carrying EVERYTHING the operator would
otherwise have to write by hand:

  - profile + rationale + confidence
  - target_descriptor (which function / harness identifier)
  - suggested engine + strategy + duration + engine_config
  - harness_source (full C/C++ wrapper code)
  - harness_build_command (compiler invocation that produces the
    binary the fuzzer drives)
  - harness_target_path (where the built binary lives on the
    workstation after build -- fed into engine_config.target_binary)
  - seed_corpus_json ([{filename, content_base64}, …])
  - dictionary_content (optional AFL/libfuzzer .dict body)

Lifecycle:
  pending  ─ operator approves ─→ accepted (ProposalPreparer SSHes
                                    the workstation, writes harness +
                                    seeds + dict, builds, creates
                                    campaign row, optionally launches)
           ─ operator rejects  ─→ rejected (reason captured)
           ─ superseded by a newer proposal targeting the same
             function → superseded
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "055_vr_fuzz_proposals"
down_revision: str | None = "054_vr_campaign_system_fk"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vr_fuzz_campaign_proposals",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(length=64),
            sa.ForeignKey("vr_investigations.id"),
            nullable=False,
        ),
        sa.Column(
            "outcome_id",
            sa.String(length=64),
            sa.ForeignKey("vr_investigation_outcomes.id"),
            nullable=False,
        ),
        sa.Column(
            "target_id",
            sa.String(length=64),
            sa.ForeignKey("vr_targets.id"),
            nullable=False,
        ),
        sa.Column(
            "workspace_id",
            sa.String(length=64),
            sa.ForeignKey("vr_workspaces.id"),
            nullable=False,
        ),
        sa.Column("team_id", sa.String(length=64), nullable=True),
        sa.Column("profile", sa.String(length=128), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "confidence", sa.String(length=24),
            nullable=False, server_default="medium",
        ),
        sa.Column(
            "target_descriptor_json", sa.Text(),
            nullable=False, server_default="{}",
        ),
        # Suggested campaign config (operator may override on accept).
        sa.Column("suggested_engine_id", sa.String(length=32), nullable=True),
        sa.Column(
            "suggested_engine_config_json", sa.Text(),
            nullable=False, server_default="{}",
        ),
        sa.Column("suggested_strategy_id", sa.String(length=32), nullable=True),
        sa.Column("suggested_duration_hours", sa.Integer(), nullable=True),
        # PRE-FUZZ PREP -- the model fills these so the operator does
        # not write the harness, build, or seed corpus by hand. On
        # accept the ProposalPreparer SCPs everything to the
        # workstation and runs the build.
        sa.Column("harness_source", sa.Text(), nullable=True),
        sa.Column("harness_language", sa.String(length=16), nullable=True),
        sa.Column("harness_build_command", sa.Text(), nullable=True),
        sa.Column("harness_target_path", sa.String(length=1024), nullable=True),
        sa.Column(
            "seed_corpus_json", sa.Text(),
            nullable=False, server_default="[]",
        ),
        sa.Column("dictionary_content", sa.Text(), nullable=True),
        # Lifecycle.
        sa.Column(
            "status", sa.String(length=24),
            nullable=False, server_default="pending",
        ),
        sa.Column(
            "accepted_campaign_id", sa.String(length=64),
            sa.ForeignKey("vr_fuzz_campaigns.id"), nullable=True,
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_by", sa.String(length=64), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column(
            "prepare_log", sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_vr_fuzz_proposals_investigation_id",
        "vr_fuzz_campaign_proposals", ["investigation_id"],
    )
    op.create_index(
        "ix_vr_fuzz_proposals_target_id",
        "vr_fuzz_campaign_proposals", ["target_id"],
    )
    op.create_index(
        "ix_vr_fuzz_proposals_workspace_id",
        "vr_fuzz_campaign_proposals", ["workspace_id"],
    )
    op.create_index(
        "ix_vr_fuzz_proposals_team_id",
        "vr_fuzz_campaign_proposals", ["team_id"],
    )
    op.create_index(
        "ix_vr_fuzz_proposals_status",
        "vr_fuzz_campaign_proposals", ["status"],
    )


def downgrade() -> None:
    for idx in (
        "ix_vr_fuzz_proposals_status",
        "ix_vr_fuzz_proposals_team_id",
        "ix_vr_fuzz_proposals_workspace_id",
        "ix_vr_fuzz_proposals_target_id",
        "ix_vr_fuzz_proposals_investigation_id",
    ):
        op.drop_index(idx, "vr_fuzz_campaign_proposals")
    op.drop_table("vr_fuzz_campaign_proposals")
