"""Issue #40-6: bounded queries in the task-engine read paths.

Two historical hot spots ran unbounded full-table loads:

* ``TaskRepository.list_for_user`` selected every row visible to the
  caller before paging in Python (or, more often, not at all). On a
  long-lived deployment with hundreds of thousands of terminal rows
  that meant a single admin ``GET /tasks`` call scanned the full
  ``taskrecord`` table.
* ``TaskQueue._validate_dag`` loaded every ``TaskRecord`` on submit so
  it could rebuild the full task graph, even though a live dependency
  cycle can only involve non-terminal rows.

Both are now bounded: ``list_for_user`` accepts ``limit`` / ``offset``
capped at ``LIST_PAGE_MAX``; ``_validate_dag`` scopes to non-terminal
statuses and caps the scan at ``_VALIDATE_DAG_SCAN_LIMIT``. These tests
prove the SQL that reaches the DB carries the bound.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.dialects import postgresql
from sqlmodel import Session

from aila.api.auth import AuthContext
from aila.api.constants import MODULE_ID_PLATFORM, ROLE_ADMIN
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.queue import TaskQueue
from aila.platform.tasks.storage import TaskRepository

from .conftest import _SyncSessionAdapter, sqlite_db_env


def _admin_auth() -> AuthContext:
    return AuthContext(
        user_id="admin",
        role=ROLE_ADMIN,
        auth_type="user",
        team_id=None,
    )


def _insert_terminal(session: Session, status: str) -> str:
    """Insert one TaskRecord in a terminal state and return its id."""
    tid = str(uuid4())
    rec = TaskRecord(
        id=tid,
        track="platform",
        fn_path="aila.platform.tasks.queue.some_fn",
        fn_module="__platform__",
        status=status,
        user_id="u",
        group_id="operator",
        kwargs_json="{}",
        updated_at=datetime.now(UTC),
    )
    session.add(rec)
    session.commit()
    return tid


# ---------------------------------------------------------------------------
# TaskRepository.list_for_user
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_for_user_defaults_to_page_size_and_caps_at_max(
    tmp_path: Any,
) -> None:
    """``list_for_user`` applies ``LIST_PAGE_SIZE`` by default and never
    returns more than ``LIST_PAGE_MAX`` even when the caller asks for a
    larger page (silently capped)."""
    with sqlite_db_env(tmp_path, "list_bound") as (engine, _):
        # Insert more rows than the default page size to prove the LIMIT
        # bites -- use DONE so no terminal filtering path skews the count.
        default_size = TaskRepository.LIST_PAGE_SIZE
        with Session(engine) as s:
            for _ in range(default_size + 25):
                _insert_terminal(s, TaskStatus.DONE)

        with Session(engine) as raw:
            adapter = _SyncSessionAdapter(raw)
            page = await TaskRepository.list_for_user(adapter, _admin_auth())
            assert len(page) == default_size

        # Over-cap request: silently clamped to LIST_PAGE_MAX.
        with Session(engine) as raw:
            adapter = _SyncSessionAdapter(raw)
            oversize = await TaskRepository.list_for_user(
                adapter,
                _admin_auth(),
                limit=TaskRepository.LIST_PAGE_MAX * 10,
            )
            assert len(oversize) <= TaskRepository.LIST_PAGE_MAX


@pytest.mark.asyncio
async def test_list_for_user_offset_pages_through_rows(tmp_path: Any) -> None:
    """``offset`` moves the window; page 2 does not overlap page 1."""
    with sqlite_db_env(tmp_path, "list_offset") as (engine, _):
        ids_in_insertion_order: list[str] = []
        with Session(engine) as s:
            for _ in range(5):
                ids_in_insertion_order.append(_insert_terminal(s, TaskStatus.DONE))

        with Session(engine) as raw:
            adapter = _SyncSessionAdapter(raw)
            page1 = await TaskRepository.list_for_user(
                adapter, _admin_auth(), limit=2, offset=0,
            )
            page2 = await TaskRepository.list_for_user(
                adapter, _admin_auth(), limit=2, offset=2,
            )
        assert len(page1) == 2
        assert len(page2) == 2
        seen = {r.id for r in page1} | {r.id for r in page2}
        assert len(seen) == 4  # no overlap


@pytest.mark.asyncio
async def test_list_for_user_negative_or_zero_limit_falls_back_to_default(
    tmp_path: Any,
) -> None:
    """A misconfigured caller passing ``limit=0`` or a negative value
    falls back to the default page size instead of returning zero rows.
    Prevents ``limit=0`` from silently blanking the tasks page."""
    with sqlite_db_env(tmp_path, "list_neg") as (engine, _):
        with Session(engine) as s:
            for _ in range(3):
                _insert_terminal(s, TaskStatus.DONE)

        with Session(engine) as raw:
            adapter = _SyncSessionAdapter(raw)
            page = await TaskRepository.list_for_user(
                adapter, _admin_auth(), limit=0,
            )
            assert len(page) == 3

        with Session(engine) as raw:
            adapter = _SyncSessionAdapter(raw)
            page_neg = await TaskRepository.list_for_user(
                adapter, _admin_auth(), limit=-5,
            )
            assert len(page_neg) == 3


# ---------------------------------------------------------------------------
# TaskQueue._validate_dag
# ---------------------------------------------------------------------------


def _null_registry() -> MagicMock:
    registry = MagicMock()
    registry.get_sync = MagicMock(return_value=None)
    return registry


class _CapturingResult:
    def __init__(self, rows: list[TaskRecord]) -> None:
        self._rows = rows

    def all(self) -> list[TaskRecord]:
        return list(self._rows)


class _CapturingSession:
    """Records statements passed to ``session.exec`` for later assertion."""

    def __init__(self) -> None:
        self.executed: list[Any] = []

    async def exec(self, stmt: Any) -> _CapturingResult:  # noqa: A003
        self.executed.append(stmt)
        return _CapturingResult([])

    async def __aenter__(self) -> _CapturingSession:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None


@pytest.mark.asyncio
async def test_validate_dag_scopes_to_non_terminal_and_applies_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_validate_dag`` MUST NOT load terminal rows and MUST cap its scan.
    We patch ``async_session_scope`` to return a capturing session that
    records the SELECT statement, then compile it to SQL text and inspect
    the WHERE clause + LIMIT.
    """
    session = _CapturingSession()

    class _CM:
        async def __aenter__(self) -> _CapturingSession:
            return session

        async def __aexit__(self, *_: Any) -> None:
            return None

    monkeypatch.setattr(
        "aila.platform.tasks.queue.async_session_scope", lambda: _CM(),
    )

    tq = TaskQueue(config_registry=_null_registry(), module_id=MODULE_ID_PLATFORM)
    await tq._validate_dag("new-task", ["dep-a"])

    assert len(session.executed) == 1
    stmt = session.executed[0]

    # Compile against Postgres so LIMIT / IN render as text.
    compiled = str(
        stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}),
    )
    normalized = re.sub(r"\s+", " ", compiled)

    # Non-terminal scope: every status listed is a non-terminal one.
    assert "status IN" in normalized or "status in" in normalized.lower()
    for terminal in (
        TaskStatus.DONE,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
        TaskStatus.DEAD_LETTER,
    ):
        assert terminal not in normalized, (
            f"_validate_dag scan must exclude terminal status {terminal!r} "
            f"(saw it in: {normalized})"
        )
    for live in (TaskStatus.WAITING, TaskStatus.QUEUED, TaskStatus.RUNNING, TaskStatus.PAUSED):
        assert live in normalized, (
            f"_validate_dag scan must include non-terminal {live!r}"
        )

    # Explicit LIMIT so a pathological live task-count still terminates.
    assert re.search(r"LIMIT\s+\d+", normalized), (
        f"_validate_dag must emit a LIMIT clause; got: {normalized}"
    )
    assert str(TaskQueue._VALIDATE_DAG_SCAN_LIMIT) in normalized


@pytest.mark.asyncio
async def test_validate_dag_still_detects_cycles_in_live_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bounding the scan does not weaken cycle detection: adding an edge
    that closes a live cycle still raises ``ValueError``.
    """
    a_id, b_id = str(uuid4()), str(uuid4())
    live_rows = [
        TaskRecord(
            id=a_id,
            track="platform",
            fn_path="aila.p.a",
            fn_module="__platform__",
            status=TaskStatus.WAITING,
            user_id="u",
            group_id="operator",
            kwargs_json="{}",
            depends_on_json=f'["{b_id}"]',
        ),
        TaskRecord(
            id=b_id,
            track="platform",
            fn_path="aila.p.b",
            fn_module="__platform__",
            status=TaskStatus.WAITING,
            user_id="u",
            group_id="operator",
            kwargs_json="{}",
            depends_on_json="[]",
        ),
    ]

    class _Session:
        async def exec(self, _stmt: Any) -> _CapturingResult:  # noqa: A003
            return _CapturingResult(live_rows)

    class _CM:
        async def __aenter__(self) -> _Session:
            return _Session()

        async def __aexit__(self, *_: Any) -> None:
            return None

    monkeypatch.setattr(
        "aila.platform.tasks.queue.async_session_scope", lambda: _CM(),
    )

    tq = TaskQueue(config_registry=_null_registry(), module_id=MODULE_ID_PLATFORM)
    # b -> a via the new edge closes the a -> b existing edge into a cycle.
    with pytest.raises(ValueError, match="Circular dependency"):
        await tq._validate_dag(b_id, [a_id])
