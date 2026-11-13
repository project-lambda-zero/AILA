"""150 -- drop the module scoped ``llm_model`` config rows.

``ModuleConfigBase`` declared an ``llm_model`` field that no code read (#452);
LLM model routing uses the platform per task type keys. ``ConfigRegistry``
persisted the field's default as a ``configentryrecord`` row under every module
namespace on registration. The field is removed, so those rows name a key no
schema declares: the config API would list them but reject every write. No
schema in any namespace declares a key named exactly ``llm_model``, so every
such row is deleted.

Revision ID: 150_drop_module_llm_model_config
Revises:     149_forensics_inv_lifecycle_cols
Create Date: 2026-11-13
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "150_drop_module_llm_model_config"
down_revision: str | None = "149_forensics_inv_lifecycle_cols"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "configentryrecord"


def upgrade() -> None:
    if _TABLE in sa.inspect(op.get_bind()).get_table_names():
        op.execute(sa.text(f"DELETE FROM {_TABLE} WHERE key = 'llm_model'"))


def downgrade() -> None:
    """No-op. Code at the prior revision declares the field again, and
    ``ConfigRegistry.register`` inserts the default row for any declared key
    that has none, so the rows return on the next module registration.
    Operator-set values are not restored; no code read them.
    """
