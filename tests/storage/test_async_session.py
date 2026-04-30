"""Tests for async_session_scope yielding AsyncSession.

Covers: 124-01-02, DB-01
TDD red phase -- these tests will fail until Plan 01 implements
async_session_scope() in aila.storage.database.
"""
from __future__ import annotations

import pytest

__all__: list[str] = []


@pytest.mark.asyncio
async def test_async_session_scope_yields_session(pg_url):
    """async_session_scope() yields a working AsyncSession."""
    from aila.storage.database import async_session_scope
    from sqlalchemy.ext.asyncio import AsyncSession

    async with async_session_scope() as session:
        assert isinstance(session, AsyncSession)


@pytest.mark.asyncio
async def test_session_can_execute_query(pg_url):
    """Session can execute a simple SQL query."""
    from aila.storage.database import async_session_scope
    from sqlalchemy import text

    async with async_session_scope() as session:
        result = await session.execute(text("SELECT 1"))
        row = result.scalar()
        assert row == 1


@pytest.mark.asyncio
async def test_session_expire_on_commit_false(pg_url):
    """Session is configured with expire_on_commit=False."""
    from aila.storage.database import async_session_scope

    async with async_session_scope() as session:
        # expire_on_commit is on the underlying sync session, not directly on AsyncSession
        assert session.sync_session.expire_on_commit is False
