"""task_records_status_check -- close §75.

Adds a Postgres CHECK constraint to ``taskrecord.status`` so the column
can only carry one of the canonical lifecycle values from the
``TaskStatus`` StrEnum. The column type stays ``Text`` for backward
compatibility, but the constraint forbids drift.

Before this migration, any string survived the INSERT -- test fixtures
that wrote ``status='success'`` (English, not the canonical ``'done'``)
slipped through and every reader that compared against ``TaskStatus.DONE``
treated the row as still RUNNING. The reaper kept flagging it as zombie.

Allowed values (mirrors ``TaskStatus`` exactly):

    queued, waiting, running, paused, done, failed, cancelled, dead_letter

The migration installs the constraint as NOT VALID first, then
validates -- this is the standard pattern to avoid blocking writers
while the existing data is scanned. If a non-canonical row already
exists, ``VALIDATE CONSTRAINT`` raises and the operator must fix the
data before retrying. There should not be any (the application layer
already filters) but operators are warned to grep:

    SELECT status, count(*) FROM taskrecord GROUP BY status;

before applying.
"""
from __future__ import annotations

from alembic import op

revision = "066_task_records_status_check"
down_revision = "065_task_records_input_hash_unique"
branch_labels = None
depends_on = None

_ALLOWED = (
    "queued", "waiting", "running", "paused",
    "done", "failed", "cancelled", "dead_letter",
)
_CONSTRAINT_NAME = "ck_taskrecord_status_canonical"


def upgrade() -> None:
    allowed_sql = ", ".join(f"'{value}'" for value in _ALLOWED)
    op.execute(
        f"ALTER TABLE taskrecord "
        f"ADD CONSTRAINT {_CONSTRAINT_NAME} "
        f"CHECK (status IN ({allowed_sql})) "
        f"NOT VALID",
    )
    op.execute(
        f"ALTER TABLE taskrecord "
        f"VALIDATE CONSTRAINT {_CONSTRAINT_NAME}",
    )


def downgrade() -> None:
    op.execute(
        f"ALTER TABLE taskrecord "
        f"DROP CONSTRAINT IF EXISTS {_CONSTRAINT_NAME}",
    )
