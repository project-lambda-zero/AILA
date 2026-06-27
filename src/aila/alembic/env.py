"""Alembic env.py -- async-capable migration environment.

Imports all SQLModel table classes so Alembic autogenerate sees every table.
Uses psycopg3 sync driver for migrations (asyncpg is runtime-only).
"""
from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlmodel import SQLModel

from aila._dotenv import load_project_env as _load_project_env

_load_project_env()

# --- Import ALL models so SQLModel.metadata is complete (per D-07) ---
# Platform models
from aila.modules.forensics import db_models as _forensics_models  # noqa: F401
from aila.modules.malware import db_models as _malware_models  # noqa: F401
from aila.modules.vr import db_models as _vr_models  # noqa: F401

# Module models \u2014 add new modules here as they are created.
# Every module with DB tables MUST be imported here AND in scripts/db_init.py,
# otherwise create_all/autogenerate won't see those tables.
from aila.modules.vulnerability import db_models as _vuln_models  # noqa: F401
from aila.storage import db_models as _platform_models  # noqa: F401

target_metadata = SQLModel.metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _get_sync_url() -> str:
    """Return a psycopg3 sync URL for Alembic migrations.

    Reads AILA_DATABASE_URL and replaces +asyncpg with +psycopg.
    Alembic requires a sync connection -- asyncpg cannot be used here.
    """
    url = os.environ.get("AILA_DATABASE_URL", "")
    if not url:
        raise RuntimeError(
            "AILA_DATABASE_URL must be set for Alembic migrations. "
            "Example: postgresql+asyncpg://user:pass@localhost:5432/aila"
        )
    # Convert asyncpg URL to psycopg for sync Alembic operations
    return url.replace("+asyncpg", "+psycopg").replace(
        "postgresql://", "postgresql+psycopg://"
    )


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode -- emit SQL without connecting."""
    url = _get_sync_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode -- connect and execute."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _get_sync_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
