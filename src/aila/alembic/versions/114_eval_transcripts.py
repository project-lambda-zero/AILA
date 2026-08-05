"""114 -- eval_transcripts (RFC-08 record-replay backbone).

Adds ``eval_transcripts``, the frozen-inputs record of a single already-run
turn used by the record-replay decision harness (``platform/eval/replay.py``).
One row captures the recorded clock, retrieval hits, tool outputs, LLM
request/response, and the parsed decision -- everything needed for a
downstream replay under a different candidate prompt version so ONLY the
prompt varies. Rows are reconstructed post-hoc from already-persisted data
(``llm_idempotency_cache`` + ``llm_cost_records`` + ``platform_journal``)
via :class:`TranscriptRecorder.record_from_history`; nothing on the live
turn hot path writes here.

Indexes:
    * (investigation_id, branch_id, turn_number) -- unique key of a turn
      when composing lookups by identity.
    * (prompt_key, prompt_version) -- cheap slicing by rendered prompt.
    * created_at -- audit ordering.

Constraint / index names are prefixed ``eval_transcripts_`` to stay unique
in the database-scoped Postgres namespace.

Revision ID: 114_eval_transcripts
Revises:     113_pattern_trust_provenance
Create Date: 2026-08-05
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "114_eval_transcripts"
down_revision: str | None = "113_pattern_trust_provenance"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.create_table(
        "eval_transcripts",
        sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("investigation_id", sa.String(length=64), nullable=False),
        sa.Column("branch_id", sa.String(length=64), nullable=True),
        sa.Column("turn_number", sa.Integer(), nullable=False),
        sa.Column("module_id", sa.String(length=64), nullable=False),
        sa.Column(
            "recorded_clock",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("retrieval_hits_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("tool_outputs_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("llm_request_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("llm_response_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("recorded_decision_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("prompt_key", sa.String(length=256), nullable=False),
        sa.Column("prompt_version", sa.String(length=32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_eval_transcripts_turn",
        "eval_transcripts",
        ["investigation_id", "branch_id", "turn_number"],
    )
    op.create_index(
        "ix_eval_transcripts_prompt",
        "eval_transcripts",
        ["prompt_key", "prompt_version"],
    )
    op.create_index(
        "ix_eval_transcripts_created_at",
        "eval_transcripts",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_eval_transcripts_created_at", table_name="eval_transcripts")
    op.drop_index("ix_eval_transcripts_prompt", table_name="eval_transcripts")
    op.drop_index("ix_eval_transcripts_turn", table_name="eval_transcripts")
    op.drop_table("eval_transcripts")
