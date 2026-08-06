"""115 -- add prompt_pins_json (+ updated_at) to forensics_investigations.

RFC-09 criterion 4 activation for the forensics module. Migration 095
added ``prompt_pins_json`` to ``vr_investigations`` and
``malware_investigations`` because both tables extend
:class:`InvestigationRecordBase`. The forensics ``InvestigationRunRecord``
does NOT extend that base (it carries a different column shape), so this
migration lands the same column directly on ``forensics_investigations``
so the shared :func:`aila.platform.prompts.pinning.resolve_pinned_prompt`
helper resolves through the pin-per-investigation rule for forensics too.

``updated_at`` is added at the same time because
:func:`resolve_pinned_prompt` stamps ``row.updated_at = utc_now()`` when
it persists a fresh pin. Without the column SQLModel raises on setattr
for an unmapped attribute under Pydantic v2, which would block the very
first turn of every forensics investigation once the pin path is wired
in. Nullable + no server default so existing rows migrate cleanly (new
rows use the SQLModel ``default_factory=utc_now`` at INSERT time).

Table-existence guarded: a schema state where ``forensics_investigations``
is absent (partial test bootstraps, an environment without the forensics
module deployed) becomes a no-op instead of a crash. Same pattern
migration 113 established after the RFC-08 ``_template`` scaffold-table
lesson.

Revision ID: 115_forensics_prompt_pins
Revises:     114_eval_transcripts
Create Date: 2026-08-06
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "115_forensics_prompt_pins"
down_revision: str | None = "114_eval_transcripts"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "forensics_investigations"


def _table_present() -> bool:
    """True when ``forensics_investigations`` exists in the bound DB."""
    inspector = sa.inspect(op.get_bind())
    return _TABLE in set(inspector.get_table_names())


def upgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} "
        "ADD COLUMN IF NOT EXISTS prompt_pins_json TEXT NOT NULL DEFAULT '{}'"
    ))
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} "
        "ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE"
    ))


def downgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS updated_at"
    ))
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS prompt_pins_json"
    ))
