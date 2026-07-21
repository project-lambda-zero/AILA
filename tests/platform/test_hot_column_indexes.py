"""#45-3 -- hot query columns carry a DB index.

Regression guard on the indexing contract: workflowrunrecord.module_id and the
created_at columns on auditeventrecord / artifactrecord must be indexed
(index=True on the model; migration 075 backfills existing databases). The
test_db fixture builds the schema via create_all, so if a field loses
index=True the index disappears here and this fails.
"""
from __future__ import annotations

import pytest
from sqlalchemy import text

from aila.platform.uow import UnitOfWork

_EXPECTED: tuple[tuple[str, str], ...] = (
    ("workflowrunrecord", "module_id"),
    ("auditeventrecord", "created_at"),
    ("artifactrecord", "created_at"),
)


@pytest.mark.usefixtures("test_db")
async def test_hot_columns_are_indexed() -> None:
    async with UnitOfWork() as uow:
        result = await uow.session.execute(text(
            "SELECT tablename, indexdef FROM pg_indexes "
            "WHERE schemaname='public' AND tablename IN "
            "('workflowrunrecord','auditeventrecord','artifactrecord')",
        ))
        rows = result.all()

    defs_by_table: dict[str, list[str]] = {}
    for tablename, indexdef in rows:
        defs_by_table.setdefault(tablename, []).append(indexdef)

    for table, column in _EXPECTED:
        defs = defs_by_table.get(table, [])
        assert any(column in d for d in defs), (
            f"{table}.{column} is not indexed -- index=True was dropped from the model"
        )
