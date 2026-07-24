"""UnitOfWork async context manager for atomic multi-table operations.

Wraps async_session_scope so that services sharing a single UoW operate
within the same transaction.  The caller controls commit/rollback;
exception propagation through the underlying session scope handles
automatic rollback.

Optionally carries TeamContext for team-scoped query filtering (D-03)
and auto-stamping (D-07).  When team_context is provided, it is set on
session.info["team_context"] so the do_orm_execute listener and
StorageService._stamp_team_id can read it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..storage.database import async_session_scope

if TYPE_CHECKING:
    from ..api.auth import TeamContext


class UnitOfWorkNotCommittedError(RuntimeError):
    """A UoW body performed writes but exited without calling commit().

    Raised by :meth:`UnitOfWork.__aexit__` on a non-exception exit when the
    session still holds pending inserts, updates, or deletes. The underlying
    ``async_session_scope`` rolls those writes back on close, so a forgotten
    ``await uow.commit()`` silently loses data. This backstop converts that
    silent loss into a named, test-visible failure (C4).
    """


class UnitOfWork:
    """Wraps one AsyncSession for the duration of a caller-controlled transaction.

    Optionally carries TeamContext for team-scoped query filtering (D-03)
    and auto-stamping (D-07).

    Usage::

        async with UnitOfWork(team_context=ctx) as uow:
            await service_a.do_thing(uow.session)
            await service_b.do_other(uow.session)
            await uow.commit()
        # auto-rollback on exception
    """

    def __init__(self, team_context: TeamContext | None = None) -> None:
        self._session: AsyncSession | None = None
        self._cm: Any = None
        self._team_context = team_context

    @property
    def session(self) -> AsyncSession:
        if self._session is None:
            raise RuntimeError("UoW not entered -- use 'async with UnitOfWork()'")
        return self._session

    async def __aenter__(self) -> UnitOfWork:
        self._cm = async_session_scope()
        self._session = await self._cm.__aenter__()
        if self._team_context is not None:
            self._session.info["team_context"] = self._team_context
        return self

    async def __aexit__(
        self,
        exc_type: type | None,
        exc_val: BaseException | None,
        tb: object,
    ) -> None:
        # Capture pending-write state before the inner scope rolls back and
        # expires the session on close.
        uncommitted = (
            exc_type is None
            and self._session is not None
            and bool(self._session.new or self._session.dirty or self._session.deleted)
        )
        try:
            await self._cm.__aexit__(exc_type, exc_val, tb)
        finally:
            self._session = None
            self._cm = None
        if uncommitted:
            raise UnitOfWorkNotCommittedError(
                "UnitOfWork exited with uncommitted writes; call "
                "'await uow.commit()' before the block exits (C4)"
            )

    async def commit(self) -> None:
        """Explicitly commit the current transaction."""
        await self.session.commit()

    async def rollback(self) -> None:
        """Explicitly rollback the current transaction."""
        await self.session.rollback()
