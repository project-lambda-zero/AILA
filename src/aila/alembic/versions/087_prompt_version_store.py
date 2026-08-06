"""087 -- prompt version store tables (RFC-09 step 4).

Creates the immutable prompt-version store, the mutable release-alias
pointers, and the append-only alias-change audit log. Columns match the
SQLModel definitions in platform/prompts/version_models.py so create_all
(tests, fresh installs) matches the migrated schema. IF NOT EXISTS guarded
so a re-run or a fresh create_all database is a no-op.

Revision ID: 087_prompt_version_store
Revises:     086_llm_cost_prompt_content_hash
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "087_prompt_version_store"
down_revision: str | None = "086_llm_cost_prompt_content_hash"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS prompt_versions (
            id VARCHAR NOT NULL PRIMARY KEY,
            key VARCHAR(256) NOT NULL,
            version VARCHAR(32) NOT NULL,
            content_hash VARCHAR(64) NOT NULL,
            body TEXT NOT NULL,
            author VARCHAR(128) NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_prompt_versions_key_version UNIQUE (key, version),
            CONSTRAINT uq_prompt_versions_key_content_hash UNIQUE (key, content_hash)
        );
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_prompt_versions_key "
        "ON prompt_versions (key);"
    ))
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS prompt_aliases (
            id VARCHAR NOT NULL PRIMARY KEY,
            key VARCHAR(256) NOT NULL,
            alias VARCHAR(32) NOT NULL,
            version VARCHAR(32) NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT uq_prompt_aliases_key_alias UNIQUE (key, alias)
        );
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_prompt_aliases_key "
        "ON prompt_aliases (key);"
    ))
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS prompt_alias_changes (
            id VARCHAR NOT NULL PRIMARY KEY,
            key VARCHAR(256) NOT NULL,
            alias VARCHAR(32) NOT NULL,
            from_version VARCHAR(32),
            to_version VARCHAR(32) NOT NULL,
            actor VARCHAR(128) NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_prompt_alias_changes_key_alias "
        "ON prompt_alias_changes (key, alias);"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS prompt_alias_changes;"))
    op.execute(sa.text("DROP TABLE IF EXISTS prompt_aliases;"))
    op.execute(sa.text("DROP TABLE IF EXISTS prompt_versions;"))
