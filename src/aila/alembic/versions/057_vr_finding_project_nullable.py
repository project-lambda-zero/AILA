"""057 — make vr_findings.project_id nullable.

Standalone investigations (no project_id on VRInvestigationRecord)
previously had their DIRECT_FINDING outcomes silently SKIPPED by
the dispatcher because creating a VRFindingRecord row required a
non-null project_id. That left the outcome data on the outcome row
but never materialized as a finding — which in turn meant the
variant-child auto-PoC pipeline (which hooks off finding creation)
never fired, and the /vr/findings listings missed every standalone
investigation.

This migration relaxes the NOT NULL on project_id. The dispatcher
update in the same commit drops the SKIPPED path. Existing rows
keep their project_id; future rows from standalone investigations
get NULL and still materialize.

The associated index on project_id stays. PostgreSQL handles NULL
in indexed columns natively (NULLs simply don't appear in
equality scans), so the listing queries that filter by
``project_id == X`` still work for project-linked findings and
NULL findings get surfaced via a separate ``project_id IS NULL``
filter when the operator views the orphan-findings page.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "057_vr_finding_project_nullable"
down_revision: str | None = "056_vr_investigation_cve_intel"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.alter_column(
        "vr_findings",
        "project_id",
        existing_type=sa.String(length=64),
        nullable=True,
    )


def downgrade() -> None:
    # Downgrade is best-effort: rows created under the nullable
    # regime may have NULL project_id, which violates the
    # post-downgrade NOT NULL constraint. Set them to a sentinel
    # marker before re-tightening so the column can return to NOT
    # NULL without breaking the migration.
    op.execute(
        "UPDATE vr_findings SET project_id = '__orphan__' WHERE project_id IS NULL",
    )
    op.alter_column(
        "vr_findings",
        "project_id",
        existing_type=sa.String(length=64),
        nullable=False,
    )
