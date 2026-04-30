"""Plan A auth tables — user accounts, groups, OIDC provider, refresh tokens.

Revision ID: 002_plan_a_auth_tables
Revises: 001_baseline
Create Date: 2026-04-09

Creates:
- user_records: username/password (argon2id) user accounts (D-13/D-17/D-18/D-20)
- user_group_records: team groups with module-level access control (D-18)
- oidc_provider_records: Microsoft OIDC provider configuration (D-15)
- refresh_token_records: refresh token hashes for session management (D-14)
- Adds user_id column to apikeyrecord for legacy key migration (D-16/D-43)
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002_plan_a_auth_tables"
down_revision: Union[str, None] = "001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # user_group_records: team groups with module-level access control
    op.create_table(
        "user_group_records",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("allowed_modules_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index("ix_user_group_records_name", "user_group_records", ["name"], unique=True)

    # user_records: username/password user accounts with argon2id hashing
    op.create_table(
        "user_records",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("username", sa.Text, nullable=False),
        sa.Column("email", sa.Text, nullable=True),
        sa.Column("hashed_password", sa.Text, nullable=True),
        sa.Column("role", sa.Text, nullable=False, server_default="operator"),
        sa.Column("group_id", sa.Text, nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("oidc_sub", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_user_records_username", "user_records", ["username"], unique=True)
    op.create_index("ix_user_records_email", "user_records", ["email"])
    op.create_index("ix_user_records_role", "user_records", ["role"])
    op.create_index("ix_user_records_group_id", "user_records", ["group_id"])
    op.create_index("ix_user_records_is_active", "user_records", ["is_active"])
    op.create_index("ix_user_records_oidc_sub", "user_records", ["oidc_sub"])

    # oidc_provider_records: Microsoft OIDC provider config (D-15)
    op.create_table(
        "oidc_provider_records",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("provider_name", sa.Text, nullable=False, server_default="microsoft"),
        sa.Column("tenant_id", sa.Text, nullable=False),
        sa.Column("client_id", sa.Text, nullable=False),
        sa.Column("client_secret_encrypted", sa.Text, nullable=False),
        sa.Column("is_enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index(
        "ix_oidc_provider_records_provider_name",
        "oidc_provider_records",
        ["provider_name"],
        unique=True,
    )

    # refresh_token_records: hashed refresh tokens for session management (D-14)
    op.create_table(
        "refresh_token_records",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("user_id", sa.Text, nullable=False),
        sa.Column("token_hash", sa.Text, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.UniqueConstraint("token_hash", name="uq_refresh_token_records_token_hash"),
    )
    op.create_index("ix_refresh_token_records_user_id", "refresh_token_records", ["user_id"])

    # Add user_id to apikeyrecord for legacy key -> user migration (D-16/D-43)
    op.add_column(
        "apikeyrecord",
        sa.Column("user_id", sa.Text, nullable=True),
    )
    op.create_index("ix_apikeyrecord_user_id", "apikeyrecord", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_apikeyrecord_user_id", table_name="apikeyrecord")
    op.drop_column("apikeyrecord", "user_id")

    op.drop_index("ix_refresh_token_records_user_id", table_name="refresh_token_records")
    op.drop_table("refresh_token_records")

    op.drop_index(
        "ix_oidc_provider_records_provider_name", table_name="oidc_provider_records"
    )
    op.drop_table("oidc_provider_records")

    op.drop_index("ix_user_records_username", table_name="user_records")
    op.drop_index("ix_user_records_email", table_name="user_records")
    op.drop_index("ix_user_records_role", table_name="user_records")
    op.drop_index("ix_user_records_group_id", table_name="user_records")
    op.drop_index("ix_user_records_is_active", table_name="user_records")
    op.drop_index("ix_user_records_oidc_sub", table_name="user_records")
    op.drop_table("user_records")

    op.drop_index("ix_user_group_records_name", table_name="user_group_records")
    op.drop_table("user_group_records")
