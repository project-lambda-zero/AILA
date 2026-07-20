"""SystemService -- managed system lifecycle: register, deregister, inventory per D-02.

When an ``EventEmitter`` is supplied at construction time,
:meth:`register_system` and :meth:`deregister_system` emit a
``PlatformEvent`` for ``stage="system"`` with
``action="registered" | "deregistered"``. The emitter drives the
platform's audit_db and Redis SSE destinations. Callers that do not
inject an emitter (the ``ServiceFactory`` default today) do not emit;
the managed-system row still writes through :class:`PersistContract`.

Each method accepts an optional external session (from UoW) for
atomicity. When ``session`` is ``None`` a short-lived session is created
via ``async_session_scope`` (SDA-06).

#52-3.4 status: the emitter injection point exists so a caller can
drive the audit trail through the same emitter fan-out that other
platform sites already use. Full domain-event dispatch (a
``DomainEventBus`` publishing typed :class:`SystemRegistered` /
:class:`SystemDeregistered` payloads into the hash-chained platform
journal) is out of scope for this pure-code pass; wiring
``ServiceFactory`` (and every caller that owns its own session) to
thread an emitter is left as follow-up.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel, select

from ...storage.database import async_session_scope
from ..contracts.persist import PersistContract
from ..events import PlatformEvent

if TYPE_CHECKING:
    from ..events import EventEmitter

__all__ = ["SystemService"]


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

    Emits ``PlatformEvent`` rows (stage=``"system"``, action=``"registered"``
    / ``"deregistered"``) through the injected :class:`EventEmitter`. When
    no emitter is injected, no event is emitted; the row still persists.
    """

    def __init__(self, emitter: EventEmitter | None = None) -> None:
        self._emitter = emitter

    async def register_system(
        self,
        record: SQLModel,
        session: AsyncSession | None = None,
    ) -> None:
        """Register a managed system.

        Persists ``record`` via :class:`PersistContract` upsert. When an
        emitter was injected at construction time, emits a
        ``PlatformEvent(stage="system", action="registered", ...)`` after
        the persist call (and after the short-lived commit when this
        service owns the session). Callers that pass their own
        ``session`` receive the emit before their outer commit -- the
        emitter's audit_db destination is expected to share that session
        so the audit row rides the same transaction.
        """
        async with _session_or_new(session) as (sess, owns):
            await PersistContract.upsert(sess, record)
            if owns:
                await sess.commit()
            if self._emitter is not None:
                self._emitter.emit(_registered_event(record))

    async def deregister_system(
        self,
        record: SQLModel,
        session: AsyncSession | None = None,
    ) -> None:
        """Deregister a managed system.

        Deletes ``record`` through the active session. When an emitter
        was injected at construction time, emits a
        ``PlatformEvent(stage="system", action="deregistered", ...)``
        after the delete (and after the short-lived commit when this
        service owns the session).
        """
        async with _session_or_new(session) as (sess, owns):
            await sess.delete(record)
            if owns:
                await sess.commit()
            if self._emitter is not None:
                self._emitter.emit(_deregistered_event(record))

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


def _system_id_str(record: SQLModel) -> str:
    """Return the record's persistence id as a string, or empty when unset."""
    raw = getattr(record, "id", None)
    return "" if raw is None else str(raw)


def _registered_event(record: SQLModel) -> PlatformEvent:
    """Build the ``system.registered`` PlatformEvent for a persisted record."""
    system_id = _system_id_str(record)
    hostname = str(getattr(record, "host", "") or "")
    name = str(getattr(record, "name", "") or "")
    return PlatformEvent(
        stage="system",
        action="registered",
        key="system.registered",
        message=f"system registered: {name or system_id}",
        details={"system_id": system_id, "hostname": hostname, "name": name},
        run_id=system_id,
    )


def _deregistered_event(record: SQLModel) -> PlatformEvent:
    """Build the ``system.deregistered`` PlatformEvent for a persisted record."""
    system_id = _system_id_str(record)
    hostname = str(getattr(record, "host", "") or "")
    name = str(getattr(record, "name", "") or "")
    return PlatformEvent(
        stage="system",
        action="deregistered",
        key="system.deregistered",
        message=f"system deregistered: {name or system_id}",
        details={"system_id": system_id, "hostname": hostname, "name": name},
        run_id=system_id,
    )
