"""056 -- persist CVE intel on the investigation row.

The reasoning loop extracts every CVE id from the operator's question
and resolves it via the vulnerability module's IntelService at
``state_investigation_setup``. Result was passed through workflow
state but never written to the DB, so a worker restart lost it and
every re-run hit NVD again.

This migration adds ``vr_investigations.cve_intel_json`` (jsonb-as-
text). Setup writes the resolved list to it on first run and reads
back on subsequent runs -- no second NVD call needed.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "056_vr_investigation_cve_intel"
down_revision: str | None = "055_vr_fuzz_proposals"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vr_investigations",
        sa.Column(
            "cve_intel_json",
            sa.Text(),
            nullable=False,
            server_default="[]",
        ),
    )


def downgrade() -> None:
    op.drop_column("vr_investigations", "cve_intel_json")
