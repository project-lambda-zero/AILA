"""Tests for pgvector cosine distance query on KnowledgeEntryRecord.

Covers: 124-03-01, DB-04
Exercises the pgvector Vector(1024) column on KnowledgeEntryRecord (BGE-M3).
"""
from __future__ import annotations

import pytest

__all__: list[str] = []


@pytest.mark.asyncio
async def test_knowledge_record_has_vector_column(pg_url):
    """KnowledgeEntryRecord.embedding is Vector(1024)."""
    from aila.storage.db_models import KnowledgeEntryRecord

    table = KnowledgeEntryRecord.__table__
    col = table.c.embedding
    col_type_str = str(col.type)
    assert "1024" in col_type_str, f"Expected Vector(1024), got {col_type_str}"


@pytest.mark.asyncio
async def test_pgvector_insert_and_cosine_query(pg_session):
    """Insert a vector and query by cosine distance."""
    from sqlmodel import select

    from aila.storage.database import init_db
    from aila.storage.db_models import KnowledgeEntryRecord

    # Create tables
    await init_db()

    # Insert test record with 1024-dim embedding
    embedding = [0.1] * 1024
    record = KnowledgeEntryRecord(
        namespace="test",
        content="test knowledge entry",
        embedding=embedding,
        entry_metadata="{}",
    )
    pg_session.add(record)
    await pg_session.commit()

    # Query by cosine distance
    query_embedding = [0.1] * 1024
    stmt = (
        select(KnowledgeEntryRecord)
        .where(KnowledgeEntryRecord.namespace == "test")
        .order_by(
            KnowledgeEntryRecord.embedding.cosine_distance(query_embedding)
        )
        .limit(1)
    )
    result = await pg_session.execute(stmt)
    row = result.scalars().first()
    assert row is not None, (
        "pgvector cosine query should return the inserted record"
    )
    assert row.content == "test knowledge entry"


@pytest.mark.asyncio
async def test_hnsw_index_exists(pg_url):
    """HNSW index is defined on KnowledgeEntryRecord."""
    from aila.storage.db_models import KnowledgeEntryRecord

    table = KnowledgeEntryRecord.__table__
    index_names = [i.name for i in table.indexes]
    assert "ix_knowledge_embedding_hnsw" in index_names, (
        f"HNSW index missing, found: {index_names}"
    )
