"""116 -- agent-config bundle columns on prompt_versions (RFC-09 Amendment 2).

The versioned unit is now the agent-config bundle: prompt body + persona
roster + per-task_type model routing + exemplars. This migration adds the
three bundle-extras columns to the existing ``prompt_versions`` table so
:class:`PromptVersionRecord` can carry the roster / routing / exemplars
alongside the body without a new table (the bundle IS the version).

Bundle identity on the cost + seal path stays the existing
``prompt_version`` + ``prompt_content_hash`` pair (migrations 086, 089,
094): the amendment redefines ``content_hash`` as the sha256 of the
canonical ``{body, roster, routing, exemplars}`` json, so those two
columns already identify a bundle end-to-end. No new ``bundle_id``
column is added.

Empty-default backfill: existing rows (every prompt-only version
registered pre-amendment) get ``{}`` / ``{}`` / ``[]`` so the resolve
path decodes to \"no extras\" and produces byte-identical behaviour
downstream. The safety invariant is that any bundle whose extras are
empty behaves exactly like the pre-amendment prompt-only path -- a
non-empty roster / routing / exemplars is the ONLY thing that flips
behaviour, and only for NEW investigations (pinning is per-
investigation: a live bundle-version flip never mutates an in-flight
investigation).

Table-existence guard: on a fresh install or a repo checkout that has
not yet been migrated to 087 the ``prompt_versions`` table may not
exist at upgrade time. Guard the ALTER on ``inspect(bind).get_table_names()``
so the migration is a no-op on that path (create_all in tests + fresh
DB init already produces the current column set through the updated
SQLModel).

Revision ID: 116_prompt_bundle_columns
Revises:     115_forensics_prompt_pins
Create Date: 2026-08-06
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "116_prompt_bundle_columns"
down_revision: str | None = "115_forensics_prompt_pins"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def _has_prompt_versions_table() -> bool:
    bind = op.get_bind()
    return "prompt_versions" in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    if not _has_prompt_versions_table():
        # Fresh install: create_all built prompt_versions with the new
        # columns already; nothing to alter here.
        return
    op.execute(sa.text(
        "ALTER TABLE prompt_versions "
        "ADD COLUMN IF NOT EXISTS roster_json TEXT NOT NULL DEFAULT '{}'"
    ))
    op.execute(sa.text(
        "ALTER TABLE prompt_versions "
        "ADD COLUMN IF NOT EXISTS routing_json TEXT NOT NULL DEFAULT '{}'"
    ))
    op.execute(sa.text(
        "ALTER TABLE prompt_versions "
        "ADD COLUMN IF NOT EXISTS exemplars_json TEXT NOT NULL DEFAULT '[]'"
    ))


def downgrade() -> None:
    if not _has_prompt_versions_table():
        return
    op.execute(sa.text(
        "ALTER TABLE prompt_versions DROP COLUMN IF EXISTS exemplars_json"
    ))
    op.execute(sa.text(
        "ALTER TABLE prompt_versions DROP COLUMN IF EXISTS routing_json"
    ))
    op.execute(sa.text(
        "ALTER TABLE prompt_versions DROP COLUMN IF EXISTS roster_json"
    ))
