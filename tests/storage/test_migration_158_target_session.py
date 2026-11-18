"""Migration 158: populated target session-mapping upgrade and downgrade coverage."""

from __future__ import annotations

import importlib.util
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from uuid import uuid4

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import Connection, create_engine

from tests.storage import test_migration_156_pentest_evidence as migration_156

_MIGRATION_PATH: Path = (
    Path(__file__).resolve().parents[2]
    / "src" / "aila" / "alembic" / "versions" / "158_pentest_target_session.py"
)

# Post-157 shape of pentest_targets (no 154-157 change touched this table).
_TARGETS_157: str = """
    CREATE TABLE pentest_targets (
        id text PRIMARY KEY,
        team_id text NOT NULL,
        name varchar(120) NOT NULL,
        target_type varchar(40) NOT NULL,
        endpoint_url text NOT NULL,
        model varchar(200),
        prompt_field varchar(80) NOT NULL,
        response_path varchar(200) NOT NULL,
        bearer_secret_id varchar(64),
        canary_secret_id varchar(64),
        created_at timestamptz NOT NULL,
        updated_at timestamptz NOT NULL
    )
"""


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_158", _MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(connection: Connection, step: str) -> None:
    context = MigrationContext.configure(connection)
    with Operations.context(context):
        getattr(_load_migration(), step)()
    connection.commit()


@pytest.fixture
def conn() -> Iterator[Connection]:
    engine = create_engine(migration_156._sync_url())
    schema = f"mig158_{uuid4().hex}"
    connection = engine.connect()
    try:
        connection.exec_driver_sql(f"CREATE SCHEMA {schema}")
        connection.exec_driver_sql(f"SET search_path TO {schema}")
        connection.exec_driver_sql(_TARGETS_157)
        connection.exec_driver_sql(
            "INSERT INTO pentest_targets "
            "(id, team_id, name, target_type, endpoint_url, prompt_field, response_path, "
            "created_at, updated_at) VALUES "
            "('legacy', 'team-a', 'legacy target', 'openai_compatible', "
            "'https://lab.example/v1/chat', 'message', 'response', "
            "TIMESTAMPTZ '2026-11-18 08:00:00+00', TIMESTAMPTZ '2026-11-18 08:00:00+00')",
        )
        connection.commit()
        yield connection
    finally:
        connection.rollback()
        connection.exec_driver_sql(f"DROP SCHEMA {schema} CASCADE")
        connection.commit()
        connection.close()
        engine.dispose()


def test_upgrade_adds_nullable_columns_and_leaves_existing_targets_stateless(
    conn: Connection,
) -> None:
    _run(conn, "upgrade")

    legacy = conn.exec_driver_sql(
        "SELECT id, session_request_field, session_response_path "
        "FROM pentest_targets WHERE id = 'legacy'",
    ).one()
    assert tuple(legacy) == ("legacy", None, None)

    columns = {
        row[0]: (row[1], row[2])
        for row in conn.exec_driver_sql(
            "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = 'pentest_targets' "
            "AND column_name IN ('session_request_field', 'session_response_path')",
        ).all()
    }
    assert columns == {
        "session_request_field": ("character varying", "YES"),
        "session_response_path": ("character varying", "YES"),
    }


def test_upgrade_persists_mapping_on_new_target_and_keeps_legacy_null(conn: Connection) -> None:
    _run(conn, "upgrade")
    conn.exec_driver_sql(
        "INSERT INTO pentest_targets "
        "(id, team_id, name, target_type, endpoint_url, prompt_field, response_path, "
        "session_request_field, session_response_path, created_at, updated_at) VALUES "
        "('managed', 'team-a', 'managed target', 'openai_compatible', "
        "'https://lab.example/v1/chat', 'message', 'response', "
        "'session.id', 'session.id', "
        "TIMESTAMPTZ '2026-11-18 09:00:00+00', TIMESTAMPTZ '2026-11-18 09:00:00+00')",
    )
    conn.commit()

    rows = conn.exec_driver_sql(
        "SELECT id, session_request_field, session_response_path "
        "FROM pentest_targets ORDER BY id",
    ).all()
    assert [tuple(row) for row in rows] == [
        ("legacy", None, None),
        ("managed", "session.id", "session.id"),
    ]


def test_downgrade_drops_columns_and_preserves_target_rows(conn: Connection) -> None:
    _run(conn, "upgrade")
    conn.exec_driver_sql(
        "UPDATE pentest_targets SET session_request_field = 'session.id', "
        "session_response_path = 'session.id' WHERE id = 'legacy'",
    )
    conn.commit()
    _run(conn, "downgrade")

    columns = conn.exec_driver_sql(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND table_name = 'pentest_targets' "
        "AND column_name IN ('session_request_field', 'session_response_path')",
    ).all()
    assert columns == []

    rows = conn.exec_driver_sql(
        "SELECT id, team_id, name, endpoint_url FROM pentest_targets ORDER BY id",
    ).all()
    assert [tuple(row) for row in rows] == [
        ("legacy", "team-a", "legacy target", "https://lab.example/v1/chat"),
    ]
