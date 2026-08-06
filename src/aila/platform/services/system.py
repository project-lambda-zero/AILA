"""SystemService -- managed system lifecycle: register, deregister, inventory per D-02.

:meth:`register_system` and :meth:`deregister_system` publish typed
domain events (:class:`aila.platform.events.SystemRegistered` /
:class:`aila.platform.events.SystemDeregistered`) through the
process-wide :class:`DomainEventBus`. The default subscriber persists
every event to the hash-chained platform journal (kind="domain_event"),
so a system lifecycle transition is durably recorded for #39 replay and
audit without any caller wiring.

When an :class:`EventEmitter` is ALSO injected at construction time,
the legacy ``PlatformEvent`` (stage=``"system"``) is fanned out to the
emitter's destinations (audit_db, Redis SSE) so the operator dashboard
keeps its live stream. ``ServiceFactory`` injects such an emitter in
production (#52); when no emitter is injected the domain-event bus
still fires so the audit trail is not lost.

Each method accepts an optional external session (from UoW) for
atomicity. When ``session`` is ``None`` a short-lived session is created
via ``async_session_scope`` (SDA-06).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel, select

from ...storage.database import async_session_scope
from ..contracts.persist import PersistContract
from ..events import (
    PlatformEvent,
    SystemDeregistered,
    SystemDeregisteredPayload,
    SystemRegistered,
    SystemRegisteredPayload,
    publish,
)

if TYPE_CHECKING:
    from aila.api.auth import TeamContext

    from ..events import EventEmitter

__all__ = ["SystemService"]

_log = logging.getLogger(__name__)


@asynccontextmanager
async def _session_or_new(
    session: AsyncSession | None,
    team_context: TeamContext | None = None,
) -> AsyncGenerator[tuple[AsyncSession, bool], None]:
    """Yield (session, owns_session). If session is None, create a short-lived one.

    ``team_context`` is threaded into ``async_session_scope`` on new-session
    creation (#53) so factory-supplied tenant scope reaches every bare query.
    When ``None`` the session scope falls back to the ambient TeamContext.
    """
    if session is not None:
        yield session, False
    else:
        async with async_session_scope(team_context=team_context) as new_session:
            yield new_session, True


class SystemService:
    """Managed system lifecycle: register, deregister, inventory per D-02.

    Emits ``PlatformEvent`` rows (stage=``"system"``, action=``"registered"``
    / ``"deregistered"``) through the injected :class:`EventEmitter`. When
    no emitter is injected, no event is emitted; the row still persists.
    """

    def __init__(
        self,
        emitter: EventEmitter | None = None,
        *,
        team_context: TeamContext | None = None,
    ) -> None:
        self._emitter = emitter
        # #53: factory-supplied tenant scope threaded through to every
        # short-lived session opened by this service. When None, the
        # ambient TeamContext still applies via async_session_scope.
        self._team_context = team_context

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
        async with _session_or_new(session, self._team_context) as (sess, owns):
            await PersistContract.upsert(sess, record)
            if owns:
                await sess.commit()
            if self._emitter is not None:
                self._emitter.emit(_registered_event(record))
            # #52 / #60: publish the typed DomainEvent on the shared bus so
            # the default journal subscriber (see events/persistence.py)
            # writes a domain_event row. Publishing follows the persist
            # commit so a rolled-back register never leaves a dangling
            # event trail. A failing subscriber is isolated by the bus.
            _publish_system_domain_event(record, action="registered")

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
        async with _session_or_new(session, self._team_context) as (sess, owns):
            # Snapshot the identifying fields BEFORE the delete so the
            # emitted event and DomainEvent both carry the pre-delete
            # state -- some ORMs expire attributes after delete + commit.
            snapshot_id = _system_id_str(record)
            snapshot_name = str(getattr(record, "name", "") or "")
            snapshot_host = str(getattr(record, "host", "") or "")
            await sess.delete(record)
            if owns:
                await sess.commit()
            if self._emitter is not None:
                self._emitter.emit(_deregistered_event_from_snapshot(
                    snapshot_id, snapshot_name, snapshot_host,
                ))
            _publish_system_domain_event_from_snapshot(
                snapshot_id, snapshot_host,
                action="deregistered",
                reason="deregister_system",
            )

    async def list_systems(
        self,
        model_class: type[SQLModel],
        *filters: Any,
        session: AsyncSession | None = None,
    ) -> list[SQLModel]:
        """List registered systems matching optional filters."""
        async with _session_or_new(session, self._team_context) as (sess, owns):
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
        async with _session_or_new(session, self._team_context) as (sess, owns):
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
    return _deregistered_event_from_snapshot(system_id, name, hostname)


def _deregistered_event_from_snapshot(
    system_id: str, name: str, hostname: str,
) -> PlatformEvent:
    """Build the deregistered PlatformEvent from pre-delete field values."""
    return PlatformEvent(
        stage="system",
        action="deregistered",
        key="system.deregistered",
        message=f"system deregistered: {name or system_id}",
        details={"system_id": system_id, "hostname": hostname, "name": name},
        run_id=system_id,
    )


def _publish_system_domain_event(record: SQLModel, *, action: str) -> None:
    """Publish a typed SystemRegistered event on the shared domain bus.

    The bus dispatches synchronously and its default subscriber persists
    to the platform journal via kind="domain_event". A failing
    subscriber is isolated by the bus, so a broken journal never blocks
    the caller's register/deregister transaction. Any exception thrown
    by ``publish`` (e.g. an import-time subscriber-wiring error) is
    logged and absorbed so the business action succeeds even if the
    event trail is temporarily broken.
    """
    system_id = _system_id_str(record)
    hostname = str(getattr(record, "host", "") or "")
    team_id_raw = getattr(record, "team_id", None)
    team_id = None if team_id_raw is None else str(team_id_raw)
    try:
        if action == "registered":
            publish(SystemRegistered(
                team_id=team_id,
                source_module="platform.system",
                payload=SystemRegisteredPayload(
                    system_id=system_id, hostname=hostname,
                ),
            ))
        else:
            publish(SystemDeregistered(
                team_id=team_id,
                source_module="platform.system",
                payload=SystemDeregisteredPayload(
                    system_id=system_id,
                    reason="deregister_system",
                ),
            ))
    except (RuntimeError, OSError, TimeoutError, ValueError, TypeError) as exc:
        _log.warning(
            "system domain-event publish failed action=%s system_id=%s: %s",
            action, system_id, exc,
        )


def _publish_system_domain_event_from_snapshot(
    system_id: str,
    hostname: str,
    *,
    action: str,
    reason: str,
) -> None:
    """Snapshot variant of :func:`_publish_system_domain_event` used by
    :meth:`SystemService.deregister_system` after the ORM row has been
    deleted (attribute access on the expired instance may raise)."""
    try:
        if action == "registered":
            publish(SystemRegistered(
                source_module="platform.system",
                payload=SystemRegisteredPayload(
                    system_id=system_id, hostname=hostname,
                ),
            ))
        else:
            publish(SystemDeregistered(
                source_module="platform.system",
                payload=SystemDeregisteredPayload(
                    system_id=system_id, reason=reason,
                ),
            ))
    except (RuntimeError, OSError, TimeoutError, ValueError, TypeError) as exc:
        _log.warning(
            "system domain-event publish failed action=%s system_id=%s: %s",
            action, system_id, exc,
        )
