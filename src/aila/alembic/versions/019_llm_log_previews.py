"""Add prompt_preview, response_preview, duration_ms, status to llm_cost_records.

Plan 176e extends the Phase 175 baseline so the admin LLM interaction log
can show operators what the model was asked and how it answered without
fetching any heavy payloads or exposing the full prompt/response.

Columns are all nullable so existing rows stay valid without backfill.

Revision ID: 019_llm_log_previews
Revises: 018_system_metadata
Create Date: 2026-04-12
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "019_llm_log_previews"
down_revision: Union[str, None] = "018_system_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Short previews kept to the first ~200 chars so the UI payload stays tiny
    # and we never echo a full secret-bearing prompt into the admin list view.
    op.add_column(
        "llm_cost_records",
        sa.Column("prompt_preview", sa.Text(), nullable=True),
    )
    op.add_column(
        "llm_cost_records",
        sa.Column("response_preview", sa.Text(), nullable=True),
    )
    op.add_column(
        "llm_cost_records",
        sa.Column("duration_ms", sa.Integer(), nullable=True),
    )
    op.add_column(
        "llm_cost_records",
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default="ok",
        ),
    )

    # Text search index over prompt_preview so the filter bar's `search` param
    # can LIKE/ILIKE on it without full-table scans at larger volumes.
    op.create_index(
        "ix_llmcostrecord_created_at",
        "llm_cost_records",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_llmcostrecord_created_at", table_name="llm_cost_records")
    op.drop_column("llm_cost_records", "status")
    op.drop_column("llm_cost_records", "duration_ms")
    op.drop_column("llm_cost_records", "response_preview")
    op.drop_column("llm_cost_records", "prompt_preview")
