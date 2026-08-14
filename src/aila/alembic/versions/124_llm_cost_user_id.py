"""124 -- add ``user_id`` to ``llm_cost_records`` (#124).

Adds a nullable, indexed ``user_id`` column so the admin ``/admin/llm-log``
endpoint's ``user=`` filter can honestly filter on the user attribution
captured at write time. The prior filter compared the query param against
``WorkflowRunRecord.team_id`` -- returning wrong or empty results and
misrepresenting itself as a user filter (:class:`WorkflowRunRecord` has no
``user_id`` column).

The column is nullable + no server default so:

* Pre-existing rows migrate cleanly (NULL user_id = "no attribution
  captured at write time"; the filter simply skips them).
* Worker-triggered LLM writes (agent turns, background scans, scheduled
  reports) that have no live user session write NULL, which is honest.
* API-triggered writes flow user_id from the auth context via
  ``current_user_id()`` (populated by ``require_user_or_api_key``).

Table-existence guarded to match the codebase's migration style: an
environment that has not yet created ``llm_cost_records`` becomes a
no-op instead of a crash.

Revision ID: 124_llm_cost_user_id
Revises:     123_vr_fuzz_source_investigation
Create Date: 2026-08-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "124_llm_cost_user_id"
down_revision: str | None = "123_vr_fuzz_source_investigation"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "llm_cost_records"
_INDEX_USER_ID: str = "ix_llm_cost_records_user_id"


def _table_present() -> bool:
    """True when ``llm_cost_records`` exists in the bound DB."""
    inspector = sa.inspect(op.get_bind())
    return _TABLE in set(inspector.get_table_names())


def upgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} "
        "ADD COLUMN IF NOT EXISTS user_id VARCHAR"
    ))
    op.execute(sa.text(
        f"CREATE INDEX IF NOT EXISTS {_INDEX_USER_ID} "
        f"ON {_TABLE} (user_id)"
    ))


def downgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(f"DROP INDEX IF EXISTS {_INDEX_USER_ID}"))
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS user_id"
    ))
