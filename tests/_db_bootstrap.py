"""Alembic-driven test database bootstrap.

Replaces the ad-hoc ``SQLModel.metadata.drop_all`` / ``create_all`` pattern
used by every session-scoped test-DB fixture with production's canonical
initialization path (mirrors ``scripts/db_init.py``):

    1. Drop and recreate the ``public`` schema so the DB starts empty
       (including any leftover ``alembic_version`` row from a previous
       pytest session).
    2. Ensure the ``vector`` extension is present.
    3. Import every model module that owns tables so ``SQLModel.metadata``
       is complete (the standard bootstrap set plus platform-owned model
       modules that live outside ``aila.storage.db_models`` and were
       otherwise reached only via lazy per-test imports).
    4. ``create_all`` the full current schema.
    5. ``alembic stamp head`` so the test DB carries the same
       ``alembic_version`` row a fresh production DB gets after
       ``make db-init``.

Step 5 is the specific piece that closes the drift channel identified in
#62: with the migration head stamped on the test DB, migration-parity
tests (see ``tests/storage/test_migration_schema_parity.py``) compare the
create_all schema against Alembic's understanding of ``head`` without
booting an out-of-band DB, and any drift caused by a model change that
skipped a migration is caught before it reaches production.

Idempotent within a pytest session: the first call for a given URL runs
the full bootstrap; every subsequent call for the same URL short-circuits.
That collapses the redundant work the per-directory conftests each
performed independently against the same ``aila_test`` database.
"""
from __future__ import annotations

import importlib
import os
import threading
from pathlib import Path

from alembic import command
from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlmodel import SQLModel

__all__ = [
    "bootstrap_test_database",
    "alembic_head_revision",
    "model_module_names",
    "reset_bootstrap_cache",
]

_REPO_ROOT: Path = Path(__file__).resolve().parent.parent
_ALEMBIC_INI: Path = _REPO_ROOT / "src" / "aila" / "alembic.ini"
_ALEMBIC_SCRIPTS: Path = _REPO_ROOT / "src" / "aila" / "alembic"

_BOOTSTRAP_LOCK: threading.Lock = threading.Lock()
_BOOTSTRAPPED_URLS: set[str] = set()

# Every module that declares a ``table=True`` SQLModel. Loaded before
# ``create_all`` so ``SQLModel.metadata`` is complete.
#
# The four ``aila.modules.*.db_models`` packages plus ``aila.storage.db_models``
# are the historical bootstrap set. The ``aila.platform.*`` entries below own
# tables that used to be pulled in only by lazy per-test imports; listing them
# here makes the test bootstrap byte-identical to the schema a fresh
# ``make db-init`` produces once those modules are actually loaded.
_MODEL_MODULES: tuple[str, ...] = (
    "aila.modules.forensics.db_models",
    "aila.modules.malware.db_models",
    "aila.modules.vr.db_models",
    "aila.modules.vulnerability.db_models",
    "aila.platform.automation.models",
    "aila.platform.eval.calibration",
    "aila.platform.eval.calibrator",
    "aila.platform.eval.models",
    "aila.platform.eval.retrieval_models",
    "aila.platform.eval.transcript",
    "aila.platform.lifecycle.assignments",
    "aila.platform.lifecycle.models",
    "aila.platform.llm.cost_record",
    "aila.platform.llm.idempotency_cache",
    "aila.platform.mcp.instance_catalog",
    "aila.platform.prompts.version_models",
    "aila.platform.services.knowledge_graph",
    "aila.platform.services.ledger",
    "aila.platform.services.specialist_registry",
    "aila.platform.tasks.models",
    "aila.storage.db_models",
)


def model_module_names() -> tuple[str, ...]:
    """Return the ordered tuple of model modules loaded by bootstrap."""
    return _MODEL_MODULES


def _asyncpg_to_psycopg_url(async_url: str) -> str:
    """Convert an asyncpg URL to a sync psycopg3 URL for Alembic/DDL."""
    return async_url.replace("+asyncpg", "+psycopg").replace(
        "postgresql://", "postgresql+psycopg://"
    )


def _import_all_model_modules() -> None:
    """Import every module in ``_MODEL_MODULES`` for its table-registration side effect."""
    for module_name in _MODEL_MODULES:
        importlib.import_module(module_name)


def _reset_public_schema(sync_url: str) -> None:
    """Drop and recreate ``public`` on the target database.

    Wipes every table, sequence, index, constraint, AND the
    ``alembic_version`` row so the subsequent bootstrap starts from a
    genuinely empty state -- matches ``scripts/db_init.py``'s assumptions
    about a fresh DB.

    Any leftover backend from a previous pytest process (asyncpg pool
    entries kept alive by a prior session, an interrupted worker) is
    terminated first so ``DROP SCHEMA`` doesn't deadlock on somebody
    else's table lock. AUTOCOMMIT is required because ``DROP SCHEMA``
    cannot run inside a transaction that started before the terminate
    call took effect.
    """
    engine = create_engine(sync_url, future=True, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) "
                    "FROM pg_stat_activity "
                    "WHERE datname = current_database() "
                    "AND pid <> pg_backend_pid()"
                )
            )
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
            conn.execute(text("GRANT ALL ON SCHEMA public TO PUBLIC"))
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    finally:
        engine.dispose()


def _create_all(sync_url: str) -> None:
    """Emit the full current schema via SQLModel.metadata.create_all."""
    engine = create_engine(sync_url, future=True)
    try:
        with engine.begin() as conn:
            SQLModel.metadata.create_all(conn)
    finally:
        engine.dispose()


def _stamp_head(async_url: str) -> None:
    """Run ``alembic stamp head`` against the async URL.

    Alembic's env.py reads ``AILA_DATABASE_URL`` and converts asyncpg ->
    psycopg internally, so we set the env var for the duration of the
    stamp call and restore whatever the process had before.
    """
    cfg = AlembicConfig(str(_ALEMBIC_INI))
    cfg.set_main_option("script_location", str(_ALEMBIC_SCRIPTS))

    prior_url = os.environ.get("AILA_DATABASE_URL")
    os.environ["AILA_DATABASE_URL"] = async_url
    try:
        command.stamp(cfg, "head")
    finally:
        if prior_url is None:
            os.environ.pop("AILA_DATABASE_URL", None)
        else:
            os.environ["AILA_DATABASE_URL"] = prior_url


def alembic_head_revision() -> str:
    """Return the current Alembic head revision id (offline read).

    Small helper that lets the parity test verify the stamp matches the
    on-disk migration head without duplicating alembic wiring.
    """
    cfg = AlembicConfig(str(_ALEMBIC_INI))
    cfg.set_main_option("script_location", str(_ALEMBIC_SCRIPTS))
    script = ScriptDirectory.from_config(cfg)
    head = script.get_current_head()
    if head is None:
        raise RuntimeError("alembic migration tree has no head revision")
    return head


def bootstrap_test_database(async_url: str) -> None:
    """Wipe and rebuild the target DB via production's canonical path.

    Executes the same sequence ``scripts/db_init.py`` runs against a fresh
    production database:

        DROP + CREATE public schema -> CREATE EXTENSION vector ->
        SQLModel.metadata.create_all -> alembic stamp head.

    Idempotent per pytest session: the first call for a given URL runs
    the full bootstrap; subsequent calls with the same URL short-circuit
    so overlapping session-scoped fixtures across ``tests/`` don't
    repeatedly re-wipe the shared ``aila_test`` database.
    """
    with _BOOTSTRAP_LOCK:
        if async_url in _BOOTSTRAPPED_URLS:
            return
        sync_url = _asyncpg_to_psycopg_url(async_url)
        _import_all_model_modules()
        _reset_public_schema(sync_url)
        _create_all(sync_url)
        _stamp_head(async_url)
        _BOOTSTRAPPED_URLS.add(async_url)


def reset_bootstrap_cache() -> None:
    """Forget every bootstrapped URL. Test-only escape hatch.

    Used by ``test_migration_schema_parity.py`` so it can force a fresh
    bootstrap of a scratch DB without racing the shared ``aila_test``
    session state.
    """
    with _BOOTSTRAP_LOCK:
        _BOOTSTRAPPED_URLS.clear()
