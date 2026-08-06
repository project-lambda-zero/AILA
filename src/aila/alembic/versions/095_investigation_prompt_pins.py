"""095 -- add prompt_pins_json to investigations (RFC-09 criterion 4).

Pins the prompt versions a running investigation resolved on its first
turn, so a later production-alias flip does not re-route an in-flight
investigation to a different prompt. The column lives on the shared
InvestigationRecordBase, so both module investigation tables receive it.
It maps prompt-key -> resolved version string; the resolve path reads the
pin and resolves that exact version instead of the live alias, persisting
the pin lazily on first resolve. The SQLModel base is updated in the same
commit so create_all (tests, fresh installs) matches the migrated schema.

NOT NULL with a server default of '{}' so the add backfills existing rows
without a data migration. Guarded with IF NOT EXISTS.

Revision ID: 095_investigation_prompt_pins
Revises:     094_prompt_version_attribution
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "095_investigation_prompt_pins"
down_revision: str | None = "094_prompt_version_attribution"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text(
        "ALTER TABLE vr_investigations "
        "ADD COLUMN IF NOT EXISTS prompt_pins_json TEXT NOT NULL DEFAULT '{}'"
    ))
    op.execute(sa.text(
        "ALTER TABLE malware_investigations "
        "ADD COLUMN IF NOT EXISTS prompt_pins_json TEXT NOT NULL DEFAULT '{}'"
    ))


def downgrade() -> None:
    op.execute(sa.text(
        "ALTER TABLE malware_investigations "
        "DROP COLUMN IF EXISTS prompt_pins_json"
    ))
    op.execute(sa.text(
        "ALTER TABLE vr_investigations DROP COLUMN IF EXISTS prompt_pins_json"
    ))
