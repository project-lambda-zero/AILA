"""Tests for PostgreSQL tsvector full-text search on KnowledgeEntryRecord.

Covers: 124-03-02, DB-07
TDD red phase -- these tests will fail until Plan 03 implements
tsvector column and GIN index on KnowledgeEntryRecord.
"""
from __future__ import annotations

import pytest

__all__: list[str] = []


@pytest.mark.asyncio
async def test_knowledge_record_has_tsvector_column(pg_url):
    """KnowledgeEntryRecord has search_vector tsvector column."""
    from aila.storage.db_models import KnowledgeEntryRecord

    table = KnowledgeEntryRecord.__table__
    col_names = [c.name for c in table.columns]
    assert "search_vector" in col_names, (
        f"search_vector column missing, found: {col_names}"
    )


@pytest.mark.asyncio
async def test_gin_index_on_search_vector(pg_url):
    """GIN index exists on search_vector column."""
    from aila.storage.db_models import KnowledgeEntryRecord

    table = KnowledgeEntryRecord.__table__
    index_names = [i.name for i in table.indexes]
    assert "ix_knowledge_search_vector" in index_names, (
        f"GIN index missing, found: {index_names}"
    )


@pytest.mark.asyncio
async def test_tsvector_fts_query(pg_session):
    """tsvector full-text search returns matching records."""
    from sqlalchemy import func
    from sqlmodel import select

    from aila.storage.database import init_db
    from aila.storage.db_models import KnowledgeEntryRecord

    await init_db()

    # Insert record with searchable content
    record = KnowledgeEntryRecord(
        namespace="test",
        content="PostgreSQL database migration with asyncpg driver",
        embedding=[0.0] * 1024,
        entry_metadata="{}",
    )
    pg_session.add(record)
    await pg_session.commit()

    # FTS query
    ts_query = func.plainto_tsquery("english", "PostgreSQL migration")
    stmt = select(KnowledgeEntryRecord).where(
        KnowledgeEntryRecord.search_vector.op("@@")(ts_query)
    )
    result = await pg_session.execute(stmt)
    rows = result.scalars().all()
    assert len(rows) >= 1, "tsvector FTS should match 'PostgreSQL migration'"
