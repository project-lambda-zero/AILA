"""020 — extended OIDC providers (Phase 177, narrowed scope).

Extends ``oidc_provider_records`` to support Google + generic OIDC alongside
the existing Microsoft integration. ``tenant_id`` is kept nullable because
only the Microsoft provider uses it; Google and generic providers carry
``issuer_url`` instead. The unique constraint on ``provider_name`` is
dropped so operators can register multiple generic providers, each with a
distinct display name.

NOTE: Firewall-probe columns originally planned for this migration were
explicitly vetoed (see feedback_no_firewall_collection). The filename is
retained for migration-chain stability but the firewall section has been
removed.

Revision ID: 020_firewall_oidc_ext
Revises: 019_llm_log_previews
Create Date: 2026-04-12
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "020_firewall_oidc_ext"
down_revision: Union[str, None] = "019_llm_log_previews"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- oidc_provider_records: extended provider support -----------------
    # Drop the legacy unique index on provider_name so operators can register
    # multiple providers (e.g. two different generic OIDC issuers).
    with op.batch_alter_table("oidc_provider_records") as batch_op:
        # The original migration created an implicit unique index via
        # Field(..., unique=True). Drop defensively.
        try:
            batch_op.drop_index("ix_oidc_provider_records_provider_name")
        except sa.exc.SQLAlchemyError:
            # Index may not exist on older DBs created before unique=True was added;
            # any DB-level error during the drop attempt is treated as already-absent.
            pass

    op.add_column(
        "oidc_provider_records",
        sa.Column("display_name", sa.Text(), nullable=True),
    )
    op.add_column(
        "oidc_provider_records",
        sa.Column(
            "provider_type",
            sa.Text(),
            nullable=False,
            server_default="microsoft",
        ),
    )
    op.add_column(
        "oidc_provider_records",
        sa.Column("issuer_url", sa.Text(), nullable=True),
    )
    op.add_column(
        "oidc_provider_records",
        sa.Column(
            "scopes_json",
            sa.Text(),
            nullable=False,
            server_default='["openid","email","profile"]',
        ),
    )

    # Make tenant_id nullable — Google/generic providers do not use it.
    with op.batch_alter_table("oidc_provider_records") as batch_op:
        batch_op.alter_column(
            "tenant_id",
            existing_type=sa.Text(),
            nullable=True,
        )

    # Create a non-unique index on provider_name for lookups.
    op.create_index(
        "ix_oidc_provider_records_provider_name",
        "oidc_provider_records",
        ["provider_name"],
        unique=False,
    )


def downgrade() -> None:
    try:
        op.drop_index("ix_oidc_provider_records_provider_name", table_name="oidc_provider_records")
    except sa.exc.SQLAlchemyError:
        # Index may already be absent on databases that never ran the upgrade;
        # treat any DB-level error as already-dropped to keep downgrade idempotent.
        pass

    op.drop_column("oidc_provider_records", "scopes_json")
    op.drop_column("oidc_provider_records", "issuer_url")
    op.drop_column("oidc_provider_records", "provider_type")
    op.drop_column("oidc_provider_records", "display_name")

    with op.batch_alter_table("oidc_provider_records") as batch_op:
        batch_op.alter_column(
            "tenant_id",
            existing_type=sa.Text(),
            nullable=False,
        )

    op.create_index(
        "ix_oidc_provider_records_provider_name",
        "oidc_provider_records",
        ["provider_name"],
        unique=True,
    )
