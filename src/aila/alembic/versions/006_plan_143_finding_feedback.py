"""Phase 143 Plan 02 — create finding_feedbacks table.

Revision ID: 006_plan_143_finding_feedback
Revises: 005_plan_143_findings_kev_workflow
Create Date: 2026-04-10

Adds:
- finding_feedbacks table for operator feedback on individual findings (FIND-10)

Feedback reasons: incorrect | doesnt_apply
Feedback records are append-only — operators cannot delete their own feedback.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "006_plan_143_finding_feedback"
down_revision: Union[str, None] = "005_plan_143_findings_kev_workflow"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_VALID_REASONS = "('incorrect', 'doesnt_apply')"


def upgrade() -> None:
    op.create_table(
        "finding_feedbacks",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("finding_id", sa.Integer, nullable=False, index=True),
        sa.Column("user_id", sa.Text, nullable=False, index=True),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("notes", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            f"reason IN {_VALID_REASONS}",
            name="ck_feedback_reason",
        ),
    )


def downgrade() -> None:
    op.drop_table("finding_feedbacks")
