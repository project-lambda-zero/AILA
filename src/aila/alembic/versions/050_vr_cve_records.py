"""050 — VR CVE records + feed state (v0.4 GA-51).

vr_cve_records — one row per ingested CVE (NVD / GHSA / MITRE / manual)
vr_cve_feed_state — per-source poller checkpoint

Revision ID: 050_vr_cve_records
Revises: 049_vr_branch_strategy_family
Create Date: 2026-05-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "050_vr_cve_records"
down_revision: str | None = "049_vr_branch_strategy_family"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vr_cve_records",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("title", sa.String(512), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cwe_ids_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("references_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column(
            "affected_components_json", sa.Text(),
            nullable=False, server_default="[]",
        ),
        sa.Column("raw_payload_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column(
            "invalidations_triggered", sa.Integer(),
            nullable=False, server_default="0",
        ),
        sa.Column(
            "ingested_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("cve_id", name="uq_vr_cve_records_cve_id"),
    )
    op.create_index("ix_vr_cve_records_cve_id", "vr_cve_records", ["cve_id"])
    op.create_index("ix_vr_cve_records_source", "vr_cve_records", ["source"])
    op.create_index(
        "ix_vr_cve_records_published_at", "vr_cve_records", ["published_at"],
    )
    op.create_index("ix_vr_cve_records_cvss_score", "vr_cve_records", ["cvss_score"])
    op.create_index(
        "ix_vr_cve_records_ingested_at", "vr_cve_records", ["ingested_at"],
    )

    op.create_table(
        "vr_cve_feed_state",
        sa.Column("source", sa.String(16), primary_key=True),
        sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_cursor", sa.String(256), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "consecutive_errors", sa.Integer(),
            nullable=False, server_default="0",
        ),
        sa.Column("records_ingested", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("vr_cve_feed_state")
    for ix in (
        "ix_vr_cve_records_ingested_at",
        "ix_vr_cve_records_cvss_score",
        "ix_vr_cve_records_published_at",
        "ix_vr_cve_records_source",
        "ix_vr_cve_records_cve_id",
    ):
        op.drop_index(ix, table_name="vr_cve_records")
    op.drop_table("vr_cve_records")
