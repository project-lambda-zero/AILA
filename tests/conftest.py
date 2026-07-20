"""Project-wide pytest fixtures and test-only database shims.

Many legacy unit tests build an in-memory SQLite engine and call
``SQLModel.metadata.create_all`` against the whole metadata. That metadata
contains Postgres-only constructs (JSONB and TSVECTOR columns, and a STORED
generated column computed by ``to_tsvector``) that SQLite cannot render or
execute, so a single incompatible type aborts create_all for every table and
every SQLite-based test fails at setup.

These shims keep production models pure (Postgres still gets JSONB/TSVECTOR and
the real generated column) while letting the shared metadata create_all on a
SQLite test engine:

- ``@compiles(JSONB, "sqlite")`` -> ``JSON`` and ``@compiles(TSVECTOR, "sqlite")``
  -> ``TEXT`` so the column types render on SQLite.
- a ``connect`` shim registers a passthrough ``to_tsvector`` so the knowledge
  table's generated column evaluates on SQLite instead of raising
  ``no such function``.

None of this touches the PostgreSQL path used by the Alembic-driven ``test_db``
fixture.
"""
from __future__ import annotations

from sqlalchemy import event
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.engine import Engine
from sqlalchemy.ext.compiler import compiles


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type, _compiler, **_kw) -> str:
    return "JSON"


@compiles(TSVECTOR, "sqlite")
def _compile_tsvector_sqlite(_type, _compiler, **_kw) -> str:
    return "TEXT"


@event.listens_for(Engine, "connect")
def _register_sqlite_pg_shims(dbapi_connection, _record) -> None:
    """Register Postgres-only functions used in generated columns on SQLite.

    Only SQLite DBAPI connections expose ``create_function``; Postgres drivers
    do not, so this is a no-op there.
    """
    create_function = getattr(dbapi_connection, "create_function", None)
    if create_function is None:
        return
    # search_vector is Computed as to_tsvector('english', content); a passthrough
    # keeps SQLite create_all and inserts working (FTS itself is Postgres-only).
    create_function("to_tsvector", 2, lambda _config, text: text or "", deterministic=True)
