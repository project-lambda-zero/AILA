"""Bootstrap a fresh AILA database (idempotent, safe to re-run).

The Alembic migration tree assumes a pre-existing baseline schema (`001_baseline`
is an empty stamp). For a brand-new database we use SQLModel.metadata, which
already reflects the latest schema (including everything migrations 002..N
would have produced):

  1. Create every table from SQLModel.metadata (full current schema)
  2. Stamp the database at the head Alembic revision (so future migrations
     pick up where the current schema left off)

If the schema is already at head, this script is a fast no-op (single SELECT
against alembic_version) so it's safe to chain into `make backend` as a
pre-flight check.

Usage:
    python scripts/db_init.py
    # or via make:
    make db-init
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from aila._dotenv import load_project_env  # noqa: E402

load_project_env()

from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402
from sqlmodel import SQLModel  # noqa: E402

from aila.modules.forensics import db_models as _forensics_models  # noqa: F401, E402
from aila.modules.malware import db_models as _malware_models  # noqa: F401, E402
from aila.modules.vr import db_models as _vr_models  # noqa: F401, E402
from aila.modules.vulnerability import db_models as _vuln_models  # noqa: F401, E402

# Importing these registers every table on SQLModel.metadata.
# Every module that defines DB tables MUST be added here, otherwise create_all
# won't see those tables and queries against them will fail at runtime with
# "relation 'X' does not exist".
from aila.storage import db_models as _platform_models  # noqa: F401, E402


def _alembic_head_revision() -> str:
    """Return the head revision id from the script directory (offline read)."""
    from alembic.config import Config as AlembicConfig  # type: ignore[import-not-found]
    from alembic.script import ScriptDirectory  # type: ignore[import-not-found]

    cfg = AlembicConfig(str(REPO_ROOT / "src" / "aila" / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "src" / "aila" / "alembic"))
    script = ScriptDirectory.from_config(cfg)
    head = script.get_current_head()
    if head is None:
        raise SystemExit("alembic has no head revision -- migration tree is empty")
    return head


async def _current_db_revision(url: str) -> str | None:
    """Return the alembic revision currently stamped in the DB, or None if uninitialized."""
    engine = create_async_engine(url, echo=False)
    try:
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    text(
                        "SELECT version_num FROM alembic_version "
                        "WHERE EXISTS (SELECT 1 FROM information_schema.tables "
                        "WHERE table_name = 'alembic_version') LIMIT 1"
                    )
                )
            ).first()
            return row[0] if row else None
    except Exception:
        return None
    finally:
        await engine.dispose()


async def _create_all(url: str) -> None:
    engine = create_async_engine(url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    await engine.dispose()


def _stamp_head() -> None:
    from alembic import command  # type: ignore[import-not-found]
    from alembic.config import Config as AlembicConfig  # type: ignore[import-not-found]

    cfg = AlembicConfig(str(REPO_ROOT / "src" / "aila" / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "src" / "aila" / "alembic"))
    command.stamp(cfg, "head")


def main() -> None:
    url = os.environ.get("AILA_DATABASE_URL")
    if not url:
        raise SystemExit("AILA_DATABASE_URL is not set. Set it in .env first.")

    head = _alembic_head_revision()
    current = asyncio.run(_current_db_revision(url))

    # create_all is always safe to run: it skips tables that already exist and
    # creates any new ones. This catches the case where the alembic version is
    # already at head but a module's db_models import was added later, so its
    # tables aren't on disk yet.
    if current is None:
        print("No schema detected. Creating tables from SQLModel.metadata...")
    elif current == head:
        print("Schema is at head -- running create_all to pick up any newly-registered tables...")
    else:
        print(f"Schema at revision {current!r}, head is {head!r} -- running create_all...")

    asyncio.run(_create_all(url))

    if current != head:
        print(f"Stamping database at Alembic head ({head!r})...")
        _stamp_head()

    print("Database initialized. Future migrations apply via 'make migrate'.")


if __name__ == "__main__":
    main()
