"""StorageService -- generic CRUD, artifact persistence, file operations per D-02.

Handles: record storage, artifact blob management, generic table operations.
Each method accepts an optional external session (from UoW) for atomicity.
When session is None, creates a short-lived session via async_session_scope (SDA-06).

Auto-stamps team_id on team-scoped records during save/save_many (D-07).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel, select

from ...storage.database import async_session_scope
from ..contracts.persist import PersistContract


@asynccontextmanager
async def _session_or_new(session: AsyncSession | None) -> AsyncGenerator[tuple[AsyncSession, bool], None]:
    """Yield (session, owns_session). If session is None, create a short-lived one."""
    if session is not None:
        yield session, False
    else:
        async with async_session_scope() as new_session:
            yield new_session, True


def _stamp_team_id(session: AsyncSession, record: SQLModel) -> None:
    """Auto-stamp team_id on team-scoped records from session's TeamContext (D-07).

    Rules:
    - Non-admin: ALWAYS stamp with TeamContext.team_id (prevents spoofing)
    - Admin + no explicit team_id on record: leave as None (admin global resource)
    - Admin + explicit team_id on record: keep that team_id (admin creating for team)
    - No TeamContext on session: skip (CLI / migration context)
    """
    if not hasattr(record, "team_id"):
        return  # global model, no team_id column

    ctx = session.info.get("team_context")
    if ctx is None:
        return  # no team context (CLI, migration, etc.)

    if not ctx.is_admin:
        # Non-admin: always overwrite with session team_id (prevents spoofing)
        record.team_id = ctx.team_id
    # Admin: respect what's already on the record (None = global, set = for-team)


class StorageService:
    """Generic CRUD, artifact persistence, file operations per D-02.

    Handles: record storage, artifact blob management, generic table operations.
    """

    def __init__(self) -> None:
        pass

    async def save(
        self,
        record: SQLModel,
        session: AsyncSession | None = None,
    ) -> None:
        """Persist a single record. Auto-stamps team_id for team-scoped records (D-07)."""
        async with _session_or_new(session) as (sess, owns):
            _stamp_team_id(sess, record)
            await PersistContract.upsert(sess, record)
            if owns:
                await sess.commit()

    async def save_many(
        self,
        records: list[SQLModel],
        session: AsyncSession | None = None,
    ) -> None:
        """Batch persist multiple records. Auto-stamps team_id on each (D-07)."""
        async with _session_or_new(session) as (sess, owns):
            for record in records:
                _stamp_team_id(sess, record)
            await PersistContract.upsert_many(sess, records)
            if owns:
                await sess.commit()

    async def fetch_one(
        self,
        model_class: type[SQLModel],
        *filters: Any,
        session: AsyncSession | None = None,
    ) -> SQLModel | None:
        """Fetch a single record by filter criteria."""
        async with _session_or_new(session) as (sess, owns):
            stmt = select(model_class).where(*filters)
            result = (await sess.exec(stmt)).first()
            return result

    async def fetch_all(
        self,
        model_class: type[SQLModel],
        *filters: Any,
        session: AsyncSession | None = None,
    ) -> list[SQLModel]:
        """Fetch all records matching filter criteria."""
        async with _session_or_new(session) as (sess, owns):
            stmt = select(model_class).where(*filters)
            results = (await sess.exec(stmt)).all()
            return list(results)

    async def delete(
        self,
        record: SQLModel,
        session: AsyncSession | None = None,
    ) -> None:
        """Delete a single record."""
        async with _session_or_new(session) as (sess, owns):
            await sess.delete(record)
            if owns:
                await sess.commit()
