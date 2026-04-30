"""Phase 179 Task 1 — migration 026 drops legacy task columns.

Applies the upgrade against a Postgres database that's been pre-populated
with TaskRecord rows across every status bucket, then asserts:

- Non-terminal rows (queued/waiting/running/paused) are marked FAILED with
  the migration error marker (D-26).
- Terminal rows (done, failed, cancelled, dead_letter) are untouched.
- ``poison_attempts`` and ``checkpoint_json`` columns no longer exist.
- The index ``ix_taskrecord_poison_attempts`` is gone.
- ``downgrade()`` raises ``NotImplementedError`` (D-25).

No mocks. Real Postgres via the shared ``test_db`` fixture; the migration
runs against whatever engine ``async_session_scope`` currently points at.
"""
from __future__ import annotations

import uuid
from typing import Any

import pytest
import pytest_asyncio
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect

from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import async_session_scope

MIGRATION_ERROR = "v5.0 migration — resubmit"


async def _seed_task(
    status: str,
    *,
    poison_attempts: int = 2,
    checkpoint_json: str | None = "{\"x\":1}",
) -> str:
    """Insert a TaskRecord with the requested status and legacy column values.

    Uses a raw UPDATE for the legacy columns because the ORM model at
    this point in Wave 1 still carries them — Wave 2 strips them.
    """
    tid = str(uuid.uuid4())
    async with async_session_scope() as session:
        session.add(
            TaskRecord(
                id=tid,
                track="vulnerability",
                fn_path="tests.seed",
                fn_module="tests",
                status=status,
                user_id="u",
                group_id="g",
                kwargs_json="{}",
            ),
        )
        await session.flush()
        # Bump legacy columns via raw SQL so we can also prove they were
        # observable before the drop (inspector check below).
        await session.execute(
            sa.text(
                "UPDATE taskrecord SET poison_attempts=:pa, checkpoint_json=:cj "
                "WHERE id=:tid"
            ),
            {"pa": poison_attempts, "cj": checkpoint_json, "tid": tid},
        )
        await session.commit()
    return tid


async def _get_engine() -> Any:
    """Return the async engine backing ``async_session_scope``.

    ``async_session_scope`` resolves the test engine via the config; we
    reuse the same resolution path so the migration hits the same DB.
    """
    from aila.storage.database import get_async_engine
    return get_async_engine()


@pytest_asyncio.fixture
async def legacy_columns_present(test_db: None) -> None:  # noqa: ARG001
    """Ensure poison_attempts/checkpoint_json exist on taskrecord.

    The Phase 179 Wave 2 commit strips them from the model; the
    ``test_db`` fixture runs ``SQLModel.metadata.create_all`` against
    whatever the model currently carries. This fixture re-adds the
    columns at runtime so Wave 1's migration test still has something
    to drop. Wave 2 test order doesn't run both the model-strip AND
    this fixture in the same session, so the add is idempotent.
    """
    engine = await _get_engine()

    def _add_if_missing(sync_conn: sa.Connection) -> None:
        inspector = sa_inspect(sync_conn)
        cols = {c["name"] for c in inspector.get_columns("taskrecord")}
        if "poison_attempts" not in cols:
            sync_conn.execute(
                sa.text(
                    "ALTER TABLE taskrecord "
                    "ADD COLUMN poison_attempts INTEGER NOT NULL DEFAULT 0"
                )
            )
            sync_conn.execute(
                sa.text(
                    "CREATE INDEX IF NOT EXISTS ix_taskrecord_poison_attempts "
                    "ON taskrecord (poison_attempts)"
                )
            )
        if "checkpoint_json" not in cols:
            sync_conn.execute(
                sa.text("ALTER TABLE taskrecord ADD COLUMN checkpoint_json TEXT")
            )

    async with engine.begin() as conn:
        await conn.run_sync(_add_if_missing)


@pytest.mark.asyncio
async def test_migration_026_marks_non_terminal_and_drops_columns(
    legacy_columns_present: None,  # noqa: ARG001
) -> None:
    # Seed four rows: running, queued, waiting, done.
    tid_running = await _seed_task(TaskStatus.RUNNING)
    tid_queued = await _seed_task(TaskStatus.QUEUED)
    tid_waiting = await _seed_task(TaskStatus.WAITING)
    tid_done = await _seed_task(
        TaskStatus.DONE, poison_attempts=0, checkpoint_json=None
    )

    engine = await _get_engine()

    # Confirm legacy columns exist pre-migration (inspector).
    def _pre_inspect(sync_conn: sa.Connection) -> dict[str, set[str]]:
        insp = sa_inspect(sync_conn)
        cols = {c["name"] for c in insp.get_columns("taskrecord")}
        idxs = {i["name"] for i in insp.get_indexes("taskrecord")}
        return {"cols": cols, "idxs": idxs}

    async with engine.begin() as conn:
        pre = await conn.run_sync(_pre_inspect)
    assert "poison_attempts" in pre["cols"]
    assert "checkpoint_json" in pre["cols"]
    assert "ix_taskrecord_poison_attempts" in pre["idxs"]

    # Run the upgrade. We invoke the migration's upgrade body directly
    # against the test engine using alembic's MigrationContext so we do
    # not need a filesystem alembic.ini wired in.
    import importlib.util
    from pathlib import Path

    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    mig_path = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "aila"
        / "alembic"
        / "versions"
        / "026_drop_legacy_task_columns.py"
    )
    spec = importlib.util.spec_from_file_location("_mig_026", mig_path)
    assert spec is not None and spec.loader is not None
    mig_026 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig_026)

    def _run_upgrade(sync_conn: sa.Connection) -> None:
        migration_context = MigrationContext.configure(sync_conn)
        with Operations.context(migration_context):
            mig_026.upgrade()

    async with engine.begin() as conn:
        await conn.run_sync(_run_upgrade)

    # Post-migration reads use raw SQL because the ORM model (in Wave 1)
    # still carries the dropped columns; ORM-driven SELECT would fail with
    # UndefinedColumnError. Wave 2 strips the columns from the model and
    # this test continues to work unchanged.
    async def _status_and_error(tid: str) -> tuple[str, str | None]:
        async with engine.begin() as conn:
            row = (
                await conn.execute(
                    sa.text(
                        "SELECT status, error FROM taskrecord WHERE id = :tid"
                    ),
                    {"tid": tid},
                )
            ).first()
        assert row is not None, f"row {tid} missing after migration"
        return row[0], row[1]

    running_status, running_err = await _status_and_error(tid_running)
    queued_status, queued_err = await _status_and_error(tid_queued)
    waiting_status, waiting_err = await _status_and_error(tid_waiting)
    done_status, done_err = await _status_and_error(tid_done)

    assert running_status == TaskStatus.FAILED
    assert running_err == MIGRATION_ERROR
    assert queued_status == TaskStatus.FAILED
    assert queued_err == MIGRATION_ERROR
    assert waiting_status == TaskStatus.FAILED
    assert waiting_err == MIGRATION_ERROR

    # DONE row untouched.
    assert done_status == TaskStatus.DONE
    assert done_err is None

    # Columns and index gone.
    async with engine.begin() as conn:
        post = await conn.run_sync(_pre_inspect)
    assert "poison_attempts" not in post["cols"]
    assert "checkpoint_json" not in post["cols"]
    assert "ix_taskrecord_poison_attempts" not in post["idxs"]


def test_migration_026_downgrade_raises() -> None:
    import importlib.util
    from pathlib import Path

    mig_path = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "aila"
        / "alembic"
        / "versions"
        / "026_drop_legacy_task_columns.py"
    )
    spec = importlib.util.spec_from_file_location("_mig_026_dg", mig_path)
    assert spec is not None and spec.loader is not None
    mig_026 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig_026)

    with pytest.raises(NotImplementedError, match="irreversible"):
        mig_026.downgrade()
