"""#452 -- module config namespaces carry no LLM model key.

Model routing is platform-owned (``platform.llm_model_<task_type>``). The
module scoped ``llm_model`` key was accepted but read by nothing, so the module
schemas now reject it and migration 150 removes the rows registration had
persisted for it.
"""
from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from pydantic import BaseModel, ValidationError
from sqlmodel import select

from aila.modules._template.config_schema import TemplateConfigSchema
from aila.modules.forensics.config_schema import ForensicsConfigSchema
from aila.modules.malware.config_schema import MalwareConfigSchema
from aila.modules.vr.config_schema import VRConfigSchema
from aila.modules.vulnerability.config_schema import VulnerabilityConfigSchema
from aila.storage.database import async_session_scope, get_async_engine
from aila.storage.db_models import ConfigEntryRecord

_MIGRATION = (
    Path(__file__).resolve().parents[2]
    / "src" / "aila" / "alembic" / "versions" / "150_drop_module_llm_model_config.py"
)


@pytest.mark.parametrize(
    "schema",
    [VRConfigSchema, MalwareConfigSchema, ForensicsConfigSchema, VulnerabilityConfigSchema, TemplateConfigSchema],
    ids=lambda s: s.__name__,
)
def test_module_schema_rejects_llm_model(schema: type[BaseModel]) -> None:
    with pytest.raises(ValidationError):
        schema(llm_model="provider/model")


async def test_migration_150_deletes_llm_model_rows_only(test_db: None) -> None:
    del test_db
    namespace = f"ns_{uuid.uuid4().hex[:12]}"
    async with async_session_scope() as session:
        session.add(ConfigEntryRecord(namespace=namespace, key="llm_model", value="provider/model"))
        session.add(ConfigEntryRecord(namespace=namespace, key="llm_model_forensics_freeflow", value="provider/model"))
        session.add(ConfigEntryRecord(namespace=namespace, key="max_turns_per_task", value="3", value_type="int"))
        await session.commit()

    spec = importlib.util.spec_from_file_location("_mig_150", _MIGRATION)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    def _upgrade(sync_conn: sa.Connection) -> None:
        with Operations.context(MigrationContext.configure(sync_conn)):
            migration.upgrade()

    async with get_async_engine().begin() as conn:
        await conn.run_sync(_upgrade)

    async with async_session_scope() as session:
        keys = (await session.exec(
            select(ConfigEntryRecord.key)
            .where(ConfigEntryRecord.namespace == namespace)
            .order_by(ConfigEntryRecord.key),
        )).all()
    assert list(keys) == ["llm_model_forensics_freeflow", "max_turns_per_task"]
