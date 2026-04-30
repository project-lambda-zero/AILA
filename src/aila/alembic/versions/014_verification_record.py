"""Create verification_records table (LLM-SEC-01).

Cross-model verification results for the LLM pipeline.  Stores both
models' evidence and verdicts when second-model blind verification
is triggered by low confidence scores.

Revision ID: 014_verification_record
Revises: 013_audit_seal_posture
Create Date: 2026-04-11
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "014_verification_record"
down_revision: Union[str, None] = "013_audit_seal_posture"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "verification_records",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("run_id", sa.Text(), nullable=False, index=True),
        sa.Column("task_type", sa.Text(), nullable=False, index=True),
        # First model
        sa.Column("first_model_id", sa.Text(), nullable=False),
        sa.Column("first_verdict", sa.Text(), nullable=False),
        sa.Column("first_confidence", sa.Float(), nullable=False),
        sa.Column("first_evidence", sa.Text(), nullable=False),
        # Second model (blind assessment)
        sa.Column("second_model_id", sa.Text(), nullable=False),
        sa.Column("second_verdict", sa.Text(), nullable=False),
        sa.Column("second_confidence", sa.Float(), nullable=False),
        sa.Column("second_evidence", sa.Text(), nullable=False),
        # Resolution
        sa.Column("agreement", sa.Boolean(), nullable=False),
        sa.Column("disposition", sa.Text(), nullable=False),
        sa.Column("final_verdict", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("verification_records")
