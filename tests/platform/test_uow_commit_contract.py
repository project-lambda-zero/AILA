"""UoW commit-contract backstop tests for #63 (C4).

A UnitOfWork block that performs writes but exits without ``await
uow.commit()`` silently loses data, because the underlying
``async_session_scope`` rolls back on close. The ``__aexit__`` backstop
turns that silent loss into a named ``UnitOfWorkNotCommittedError``.

These tests inject a fake session and context manager to exercise the
exit logic without a live database.
"""
from __future__ import annotations

import pytest

from aila.platform.uow import UnitOfWork, UnitOfWorkNotCommittedError


class _FakeCM:
    def __init__(self) -> None:
        self.exit_args: tuple | None = None

    async def __aexit__(self, exc_type, exc_val, tb) -> bool:
        self.exit_args = (exc_type, exc_val, tb)
        return False


class _FakeSession:
    def __init__(self, new=(), dirty=(), deleted=()) -> None:
        self.new = list(new)
        self.dirty = list(dirty)
        self.deleted = list(deleted)


def _prime(uow: UnitOfWork, session: _FakeSession) -> _FakeCM:
    cm = _FakeCM()
    uow._cm = cm  # type: ignore[assignment]
    uow._session = session  # type: ignore[assignment]
    return cm


async def test_dirty_exit_without_commit_raises() -> None:
    """Pending inserts at a clean exit raise the named backstop error."""
    uow = UnitOfWork()
    cm = _prime(uow, _FakeSession(new=[object()]))
    with pytest.raises(UnitOfWorkNotCommittedError):
        await uow.__aexit__(None, None, None)
    # The inner scope still ran (rolled the write back) and state was reset.
    assert cm.exit_args == (None, None, None)
    assert uow._session is None
    assert uow._cm is None


async def test_dirty_updates_and_deletes_also_raise() -> None:
    """Pending updates or deletes count as writes, not just inserts."""
    uow = UnitOfWork()
    _prime(uow, _FakeSession(dirty=[object()]))
    with pytest.raises(UnitOfWorkNotCommittedError):
        await uow.__aexit__(None, None, None)

    uow2 = UnitOfWork()
    _prime(uow2, _FakeSession(deleted=[object()]))
    with pytest.raises(UnitOfWorkNotCommittedError):
        await uow2.__aexit__(None, None, None)


async def test_clean_exit_no_writes_does_not_raise() -> None:
    """A read-only block (empty pending sets) exits without error."""
    uow = UnitOfWork()
    cm = _prime(uow, _FakeSession())
    await uow.__aexit__(None, None, None)
    assert cm.exit_args == (None, None, None)


async def test_committed_exit_does_not_raise() -> None:
    """After commit the session pending sets are empty, so no backstop fires."""
    uow = UnitOfWork()
    # A committed session has flushed and cleared its pending collections.
    _prime(uow, _FakeSession(new=(), dirty=(), deleted=()))
    await uow.__aexit__(None, None, None)


async def test_exception_exit_propagates_original_not_backstop() -> None:
    """On an exceptional exit the backstop stays silent so the real error wins."""
    uow = UnitOfWork()
    cm = _prime(uow, _FakeSession(new=[object()]))
    # exc_type is set: __aexit__ returns None (does not suppress), and must
    # not raise UnitOfWorkNotCommittedError over the original exception.
    result = await uow.__aexit__(ValueError, ValueError("boom"), None)
    assert result is None
    assert cm.exit_args[0] is ValueError
    assert uow._session is None
