"""049 -- Branch strategy_family column (v0.4 GA-50).

Multi-strategy parallel branches. A v0.4 investigation can run N
strategy branches in parallel (discovery_research + variant_hunt +
patch_diff_analysis). Each branch tags its strategy on the row so the
engine can pick its per-turn prompt + the orchestrator can dispatch
turns to the right strategy.

Revision ID: 049_vr_branch_strategy_family
Revises: 048_vr_investigation_targets
Create Date: 2026-05-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "049_vr_branch_strategy_family"
down_revision: str | None = "048_vr_investigation_targets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vr_investigation_branches",
        sa.Column("strategy_family", sa.String(128), nullable=True),
    )
    op.create_index(
        "ix_vr_investigation_branches_strategy_family",
        "vr_investigation_branches",
        ["strategy_family"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_vr_investigation_branches_strategy_family",
        table_name="vr_investigation_branches",
    )
    op.drop_column("vr_investigation_branches", "strategy_family")
