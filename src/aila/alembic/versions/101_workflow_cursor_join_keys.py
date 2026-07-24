"""101 -- add investigation/branch join keys to workflow_state_cursor (RFC-02).

Closes the cursor-keying Class-A defect: cursor rows are keyed by the
random ARQ task uuid, so the lifecycle service's investigation-scoped
pause/resume queries matched zero rows and fell through to weaker
fallbacks. The engine now denormalizes investigation_id + branch_id onto
each cursor at creation, and the lifecycle service queries by them (with
the run_id ANY(...) legacy fallback kept for pre-existing rows). Columns
match WorkflowStateCursor in db_models.py so create_all (tests, fresh
installs) matches the migrated schema. Both nullable -- existing rows stay
NULL and the legacy fallback still matches them; non-investigation
workflows leave both NULL. Guarded with IF NOT EXISTS.

Revision ID: 101_workflow_cursor_join_keys
Revises:     100_knowledge_entry_edges
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "101_workflow_cursor_join_keys"
down_revision: str | None = "100_knowledge_entry_edges"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text(
        "ALTER TABLE workflow_state_cursor "
        "ADD COLUMN IF NOT EXISTS investigation_id VARCHAR"
    ))
    op.execute(sa.text(
        "ALTER TABLE workflow_state_cursor "
        "ADD COLUMN IF NOT EXISTS branch_id VARCHAR"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_workflow_state_cursor_investigation_id "
        "ON workflow_state_cursor (investigation_id)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_workflow_state_cursor_branch_id "
        "ON workflow_state_cursor (branch_id)"
    ))


def downgrade() -> None:
    op.execute(sa.text(
        "DROP INDEX IF EXISTS ix_workflow_state_cursor_branch_id"
    ))
    op.execute(sa.text(
        "DROP INDEX IF EXISTS ix_workflow_state_cursor_investigation_id"
    ))
    op.execute(sa.text(
        "ALTER TABLE workflow_state_cursor DROP COLUMN IF EXISTS branch_id"
    ))
    op.execute(sa.text(
        "ALTER TABLE workflow_state_cursor DROP COLUMN IF EXISTS investigation_id"
    ))
