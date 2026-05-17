"""053 — VR v0.5 promise-audit closure schema additions.

Adds columns required to close the remaining gap clusters from
``docs/VR_FRONTEND_PROMISE_AUDIT.md``:

- ``vr_projects.created_by`` — string id of the operator that opened
  the project. Populated from ``AuthContext.user_id`` on
  POST /vr/projects. Renders avatars on the project list (§1.1).
- ``vr_disclosure_submissions.sections_json`` — structured advisory
  body with named sections (summary / technical / reproduction /
  patches / references). Powers the §1.8 structured editor.
- ``vr_disclosure_submissions.regenerated_from_finding_at`` —
  timestamp of the most recent "regenerate from exploit" action.
- ``vr_fuzz_crashes.reproducer_head_hex`` + helpers — first N bytes
  of the reproducer file inlined for the §1.6 hex-view preview
  without round-tripping the analysis workstation.
- ``vr_fuzz_crashes.llm_summary`` + ``triage_chain_json`` — §1.6
  triage chain (per-event ordered list) and one-line LLM summary.
- ``vr_fuzz_telemetry`` — §1.5 per-measurement time-series for
  fuzz campaigns. Workers POST measurements, the UI reads back the
  series for sparklines + stuck detection.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "053_vr_v05_closure"
down_revision: str | None = "052_vr_mcp_call_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vr_projects",
        sa.Column("created_by", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_vr_projects_created_by",
        "vr_projects",
        ["created_by"],
    )
    op.add_column(
        "vr_disclosure_submissions",
        sa.Column("sections_json", sa.Text(), nullable=True),
    )
    op.add_column(
        "vr_disclosure_submissions",
        sa.Column(
            "regenerated_from_finding_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "vr_fuzz_crashes",
        sa.Column("reproducer_head_hex", sa.Text(), nullable=True),
    )
    op.add_column(
        "vr_fuzz_crashes",
        sa.Column(
            "reproducer_head_truncated_size",
            sa.Integer(),
            nullable=True,
        ),
    )
    op.add_column(
        "vr_fuzz_crashes",
        sa.Column("llm_summary", sa.Text(), nullable=True),
    )
    op.add_column(
        "vr_fuzz_crashes",
        sa.Column(
            "triage_chain_json",
            sa.Text(),
            nullable=False,
            server_default="[]",
        ),
    )
    op.create_table(
        "vr_fuzz_telemetry",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "campaign_id",
            sa.String(length=64),
            sa.ForeignKey("vr_fuzz_campaigns.id"),
            nullable=False,
        ),
        sa.Column(
            "measured_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("execs_per_sec", sa.Float(), nullable=True),
        sa.Column("total_execs", sa.BigInteger(), nullable=True),
        sa.Column("corpus_size", sa.Integer(), nullable=True),
        sa.Column("coverage_pct", sa.Float(), nullable=True),
        sa.Column("crashes_found", sa.Integer(), nullable=True),
    )
    op.create_index(
        "ix_vr_fuzz_telemetry_campaign_id",
        "vr_fuzz_telemetry",
        ["campaign_id"],
    )
    op.create_index(
        "ix_vr_fuzz_telemetry_measured_at",
        "vr_fuzz_telemetry",
        ["measured_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_vr_fuzz_telemetry_measured_at", "vr_fuzz_telemetry")
    op.drop_index("ix_vr_fuzz_telemetry_campaign_id", "vr_fuzz_telemetry")
    op.drop_table("vr_fuzz_telemetry")
    op.drop_column("vr_fuzz_crashes", "triage_chain_json")
    op.drop_column("vr_fuzz_crashes", "llm_summary")
    op.drop_column("vr_fuzz_crashes", "reproducer_head_truncated_size")
    op.drop_column("vr_fuzz_crashes", "reproducer_head_hex")
    op.drop_column(
        "vr_disclosure_submissions", "regenerated_from_finding_at",
    )
    op.drop_column("vr_disclosure_submissions", "sections_json")
    op.drop_index("ix_vr_projects_created_by", "vr_projects")
    op.drop_column("vr_projects", "created_by")
