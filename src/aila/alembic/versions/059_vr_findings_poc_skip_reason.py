"""059 — add poc_skip_reason to vr_findings.

Set by run_vr_draft_poc when the task bails without producing PoC code
(e.g. because the investigation's verifier_report verdict is 'refuted'
— writing a PoC for a refuted finding wastes LLM tokens on code that
cannot reproduce a non-bug).

Nullable; existing rows backfill cleanly. Indexed sparsely for the
list page's "skipped" filter.

Revision: 059_vr_findings_poc_skip_reason
Revises:  058_vr_investigation_favorite
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "059_vr_findings_poc_skip_reason"
down_revision: str | None = "058_vr_investigation_favorite"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.add_column(
        "vr_findings",
        sa.Column("poc_skip_reason", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vr_findings", "poc_skip_reason")
