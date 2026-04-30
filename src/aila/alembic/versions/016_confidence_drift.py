"""Create confidence_drift_records table (LLM-SEC-04).

Tracks per-(target_name, task_type) confidence drift using a sliding window
of numeric scores.  Enables detection of model degradation, prompt drift,
or adversarial manipulation over time.

Revision ID: 016_confidence_drift
Revises: 015_seal_key_id_encryption
Create Date: 2026-04-11
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "016_confidence_drift"
down_revision: Union[str, None] = "015_seal_key_id_encryption"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "confidence_drift_records",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("target_name", sa.Text(), nullable=False, index=True),
        sa.Column("task_type", sa.Text(), nullable=False, index=True),
        sa.Column("window_size", sa.Integer(), nullable=False),
        sa.Column("confidence_scores_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("mean_confidence", sa.Float(), nullable=False),
        sa.Column("std_deviation", sa.Float(), nullable=False),
        sa.Column("drift_status", sa.Text(), nullable=False),
        sa.Column("alert_fired", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("confidence_drift_records")
