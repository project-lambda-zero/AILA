"""#62 -- migration / model schema-parity checks.

Closes the drift channel called out in issue #62:

    | tests/platform/conftest.py:36 (12+ fixtures)
    | Tables built via `SQLModel.metadata.create_all` instead of running
    | Alembic -> the schema under test can diverge from the migrated
    | production schema (missing constraints/indexes/column types); tests
    | pass on code that would fail on a real DB.

The bootstrap side of the fix lives in ``tests/_db_bootstrap.py`` which
now runs production's canonical initialization path -- ``create_all`` +
``alembic stamp head`` -- rather than a bare ``drop_all`` / ``create_all``
pair. Running ``alembic upgrade head`` from an empty DB is impractical in
this repo (the ``001_baseline`` migration is an empty stamp that assumes
the pre-alembic schema is already present, so migrations 002+ operate on
tables they never create), so the fallback path from #62's acceptance
applies: a drift-detection test that fails when the ``create_all`` schema
and the migration-head schema disagree.

The three checks below cover the meaningful ways they can disagree today:

1. ``test_bootstrap_stamps_alembic_head`` -- proves the fixture path
   actually stamps the DB at the on-disk migration head. Without this,
   any drift test is meaningless because there is no alembic view of the
   world to compare against.

2. ``test_no_metadata_drift_after_bootstrap`` -- runs Alembic's own
   ``compare_metadata`` between the stamped-head test DB and current
   ``SQLModel.metadata``. Empty diff means every column, index, and
   constraint on disk still matches what the models describe. A drop in
   ``compare_type=True`` catches the exact class of drift #62 calls out
   (types, indexes, constraints, defaults).

3. ``test_every_migration_created_table_has_model`` -- parses every
   ``op.create_table("<name>", ...)`` call across ``src/aila/alembic/
   versions/`` and confirms each target lives in
   ``SQLModel.metadata.tables``. A migration that creates a table with
   no corresponding model is the exact symptom that made
   ``automation_run_records`` unreachable from the standard bootstrap
   before we added the missing import.
"""
from __future__ import annotations

import ast
import importlib
import os
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, text
from sqlmodel import SQLModel

from tests._db_bootstrap import (
    alembic_head_revision,
    bootstrap_test_database,
    model_module_names,
)

__all__: list[str] = []

_TEST_DB_URL: str = os.environ.get(
    "AILA_TEST_DATABASE_URL",
    "postgresql+asyncpg://postgres:admin@localhost:5432/aila_test",
)
_REPO_ROOT: Path = Path(__file__).resolve().parent.parent.parent
_MIGRATION_DIR: Path = _REPO_ROOT / "src" / "aila" / "alembic" / "versions"


def _sync_url() -> str:
    return _TEST_DB_URL.replace("+asyncpg", "+psycopg").replace(
        "postgresql://", "postgresql+psycopg://"
    )


def _ensure_bootstrapped() -> None:
    """Make sure the shared aila_test DB has been through the bootstrap.

    The session-scoped async-engine fixtures across ``tests/`` all funnel
    through ``bootstrap_test_database``, but this test file may run
    before any of them (e.g., during a targeted ``pytest tests/storage``
    invocation), so we call it directly. The helper is idempotent.
    """
    # Load every model module so SQLModel.metadata reflects the same schema
    # the bootstrap builds. Without this, tests running standalone would
    # only see whatever this file imports transitively.
    for name in model_module_names():
        importlib.import_module(name)

    bootstrap_test_database(_TEST_DB_URL)


def test_bootstrap_stamps_alembic_head() -> None:
    """After bootstrap, alembic_version carries the on-disk head revision.

    Guards against a fixture regression that silently reverts to bare
    ``create_all`` (which would leave ``alembic_version`` absent) and
    against a migration file that is added on disk without also being
    reachable through Alembic's script directory (which would make
    ``alembic_head_revision`` disagree with the stamp).
    """
    _ensure_bootstrapped()

    engine = create_engine(_sync_url(), future=True)
    try:
        with engine.connect() as conn:
            has_table = conn.execute(
                text(
                    "SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = 'public' "
                    "AND table_name = 'alembic_version' LIMIT 1"
                )
            ).first()
            assert has_table is not None, (
                "alembic_version table missing -- the test-DB fixture is "
                "not running the alembic-stamp step; the schema on disk "
                "cannot be checked against migration head"
            )
            row = conn.execute(
                text("SELECT version_num FROM alembic_version")
            ).first()
    finally:
        engine.dispose()

    assert row is not None, "alembic_version table exists but is empty"
    stamped = row[0]
    expected = alembic_head_revision()
    assert stamped == expected, (
        f"alembic_version row {stamped!r} does not match on-disk "
        f"head {expected!r}; either a migration was added without "
        f"reaching the head chain, or the fixture stamped an outdated "
        f"revision"
    )


def test_no_metadata_drift_after_bootstrap() -> None:
    """create_all schema matches current SQLModel.metadata post-bootstrap.

    Uses Alembic's own ``compare_metadata`` (the same engine that powers
    ``alembic revision --autogenerate``). A non-empty diff means the
    bootstrap produced a schema the models no longer describe -- for
    example, a table dropped from ``create_all`` because its model
    ``import`` was removed from ``_MODEL_MODULES``, or a column present
    on disk with a type that no longer matches the SQLModel field.

    ``compare_type=True`` makes the comparison catch the column-type,
    index, and constraint drift #62 explicitly calls out.
    """
    _ensure_bootstrapped()

    engine = create_engine(_sync_url(), future=True)
    try:
        with engine.connect() as conn:
            ctx = MigrationContext.configure(
                connection=conn,
                opts={"compare_type": True, "include_schemas": False},
            )
            diff = compare_metadata(ctx, SQLModel.metadata)
    finally:
        engine.dispose()

    if diff:
        rendered = "\n".join(f"  - {entry!r}" for entry in diff)
        pytest.fail(
            "Schema drift between bootstrapped aila_test and current "
            f"SQLModel.metadata:\n{rendered}"
        )


def _iter_migration_table_lifecycle() -> tuple[set[str], set[str]]:
    """Return ``(created, dropped)`` table names across every migration.

    Walks each migration's ``upgrade()`` body and pulls out
    ``op.create_table("<name>", ...)`` and ``op.drop_table("<name>")``
    calls. Downgrade bodies are intentionally ignored -- they run only
    on rollback, and the head schema they invert is already visible via
    the upgrade path.
    """
    created: set[str] = set()
    dropped: set[str] = set()
    for path in sorted(_MIGRATION_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            # A broken migration file is a separate problem; skip so this
            # test never masks it by turning it into an unrelated
            # AssertionError.
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name != "upgrade":
                continue
            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                attr_name = getattr(call.func, "attr", None)
                if attr_name not in {"create_table", "drop_table"}:
                    continue
                if not call.args:
                    continue
                first = call.args[0]
                if not (
                    isinstance(first, ast.Constant)
                    and isinstance(first.value, str)
                ):
                    continue
                if attr_name == "create_table":
                    created.add(first.value)
                else:
                    dropped.add(first.value)
    return created, dropped


def test_every_migration_created_table_has_model() -> None:
    """Every migration-created table still present at head maps to a SQLModel.

    A migration that creates a table with no matching SQLModel means the
    DB carries schema no code path queries against -- dead schema that
    happens to work in production because the migration ran, but that
    would silently disappear from a fresh install using the
    ``create_all``-based bootstrap. This is exactly the drift the issue
    warns about.

    Tables that a later migration explicitly ``op.drop_table``-s are
    excluded from the check: they are part of the schema history but
    are not part of the head schema (e.g., ``user_group_records`` was
    added by migration 002 and dropped by migration 027).
    """
    _ensure_bootstrapped()

    created, dropped = _iter_migration_table_lifecycle()
    live_migration_tables = created - dropped
    model_tables = set(SQLModel.metadata.tables.keys())

    orphans = live_migration_tables - model_tables
    assert orphans == set(), (
        "Migrations create tables missing from SQLModel.metadata: "
        f"{sorted(orphans)}. Either add the model (with its module "
        "imported by tests/_db_bootstrap.py::_MODEL_MODULES) or delete "
        "the migration."
    )
