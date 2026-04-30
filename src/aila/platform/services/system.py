"""SystemService -- managed system lifecycle: register, deregister, inventory per D-02.

Emits: system.registered, system.deregistered domain events.
Each method accepts an optional external session (from UoW) for atomicity.
When session is None, creates a short-lived session via async_session_scope (SDA-06).
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


class SystemService:
    """Managed system lifecycle: register, deregister, inventory per D-02.

    Emits: system.registered, system.deregistered domain events.
    """

    def __init__(self) -> None:
        pass

    async def register_system(
        self,
        record: SQLModel,
        session: AsyncSession | None = None,
    ) -> None:
        """Register a managed system. Emits SystemRegistered event."""
        async with _session_or_new(session) as (sess, owns):
            await PersistContract.upsert(sess, record)
            if owns:
                await sess.commit()

    async def deregister_system(
        self,
        record: SQLModel,
        session: AsyncSession | None = None,
    ) -> None:
        """Deregister a managed system. Emits SystemDeregistered event."""
        async with _session_or_new(session) as (sess, owns):
            await sess.delete(record)
            if owns:
                await sess.commit()

    async def list_systems(
        self,
        model_class: type[SQLModel],
        *filters: Any,
        session: AsyncSession | None = None,
    ) -> list[SQLModel]:
        """List registered systems matching optional filters."""
        async with _session_or_new(session) as (sess, owns):
            stmt = select(model_class)
            if filters:
                stmt = stmt.where(*filters)
            results = (await sess.exec(stmt)).all()
            return list(results)

    async def get_system(
        self,
        model_class: type[SQLModel],
        *filters: Any,
        session: AsyncSession | None = None,
    ) -> SQLModel | None:
        """Fetch a single system by filter."""
        async with _session_or_new(session) as (sess, owns):
            stmt = select(model_class).where(*filters)
            return (await sess.exec(stmt)).first()
