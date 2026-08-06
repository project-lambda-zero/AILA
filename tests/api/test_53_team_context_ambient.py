"""#53 targeted tests: ambient TeamContext propagation.

Proves:
 (a) A bare ``UnitOfWork()`` inside ``team_context_scope(team-a)`` filters
     team-a rows and excludes team-b rows.
 (b) An unset ambient yields admin/global (no filter injection).
 (c) ``ReportWriteTool`` rejects a ``run_id`` that would escape the report
     root via ``..``.
 (d) ``AuditLogTool`` ignores an agent-supplied ``user_id`` and takes the
     identity from the ambient task-context ``_current_task_user_id``.

Runs against the Postgres test_db fixture (D-48/D-49) shared with the
existing ``tests/api/test_team_scope_enforcement.py`` suite.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import desc
from sqlmodel import select

from aila.api.auth import TeamContext
from aila.config import get_settings
from aila.platform.exceptions import ValidationError
from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.services.team_scope import (
    current_team_context,
    team_context_scope,
)
from aila.platform.tasks.queue import _current_task_user_id
from aila.platform.tools import reporting as reporting_mod
from aila.platform.tools.audit import AuditLogTool
from aila.platform.tools.reporting import ReportWriteTool
from aila.platform.uow import UnitOfWork
from aila.storage.database import async_session_scope
from aila.storage.db_models import AuditEventRecord


async def _seed_two_teams() -> tuple[str, str]:
    """Insert one LLMCostRecord for team-a and one for team-b.

    Both rows persist because the initial insert uses no team_context
    (admin/global write).
    """
    async with async_session_scope() as session:
        a = LLMCostRecord(model_id="m", team_id="team-a", run_id="ra")
        b = LLMCostRecord(model_id="m", team_id="team-b", run_id="rb")
        session.add(a)
        session.add(b)
        await session.commit()
        return a.id, b.id


# ---------------------------------------------------------------------------
# (a) UnitOfWork ambient scope
# ---------------------------------------------------------------------------


async def test_bare_uow_inherits_ambient_team_context(test_db) -> None:
    """A bare ``UnitOfWork()`` inside ``team_context_scope(team-a)`` filters
    to team-a rows only.
    """
    a_id, b_id = await _seed_two_teams()
    ctx_a = TeamContext(team_id="team-a", is_admin=False)

    with team_context_scope(ctx_a):
        assert current_team_context() is ctx_a
        async with UnitOfWork() as uow:
            ids = {r.id for r in (await uow.session.exec(select(LLMCostRecord))).all()}

    assert a_id in ids
    assert b_id not in ids


async def test_bare_async_session_scope_inherits_ambient(test_db) -> None:
    """A bare ``async_session_scope()`` inside ``team_context_scope`` also
    inherits the ambient tenant scope (mirrors the UoW behavior).
    """
    a_id, b_id = await _seed_two_teams()
    ctx_a = TeamContext(team_id="team-a", is_admin=False)

    with team_context_scope(ctx_a):
        async with async_session_scope() as session:
            ids = {r.id for r in (await session.exec(select(LLMCostRecord))).all()}

    assert a_id in ids
    assert b_id not in ids


# ---------------------------------------------------------------------------
# (b) unset ambient = admin/global (no filter)
# ---------------------------------------------------------------------------


async def test_unset_ambient_is_admin_global(test_db) -> None:
    """No active ``team_context_scope`` means no filter is injected, so a
    bare ``UnitOfWork()`` sees every team's rows (admin bypass preserved).
    """
    a_id, b_id = await _seed_two_teams()

    # Explicit sanity check: ambient is unset at test entry.
    assert current_team_context() is None

    async with UnitOfWork() as uow:
        ids = {r.id for r in (await uow.session.exec(select(LLMCostRecord))).all()}

    assert {a_id, b_id} <= ids


async def test_admin_context_scope_sees_all_teams(test_db) -> None:
    """An explicit admin TeamContext (team_id=None) also yields the global
    view -- the do_orm_execute listener short-circuits on ``ctx.is_admin``.
    """
    a_id, b_id = await _seed_two_teams()
    ctx_admin = TeamContext(team_id=None, is_admin=True)

    with team_context_scope(ctx_admin):
        async with UnitOfWork() as uow:
            ids = {r.id for r in (await uow.session.exec(select(LLMCostRecord))).all()}

    assert {a_id, b_id} <= ids


async def test_scope_exits_restore_previous_ambient(test_db) -> None:
    """Nested ``team_context_scope`` restores the outer binding on exit."""
    outer = TeamContext(team_id="team-outer", is_admin=False)
    inner = TeamContext(team_id="team-inner", is_admin=False)

    with team_context_scope(outer):
        assert current_team_context() is outer
        with team_context_scope(inner):
            assert current_team_context() is inner
        assert current_team_context() is outer
    assert current_team_context() is None


# ---------------------------------------------------------------------------
# (c) ReportWriteTool refuses path traversal
# ---------------------------------------------------------------------------


class _StubReportSettings:
    def __init__(self, report_dir: Path) -> None:
        self.report_dir = report_dir


def test_report_write_tool_rejects_dotdot_run_id(tmp_path: Path) -> None:
    """A ``run_id`` that tries to escape the report root via ``..`` is
    sanitized before it reaches the filesystem, so the resolved output
    path stays inside ``report_dir`` -- the traversal is neutralized, not
    reflected literally.
    """
    settings = _StubReportSettings(tmp_path)
    tool = ReportWriteTool(settings=settings)

    bundle = tool.write_bundle(
        run_id="../etc/passwd",
        report_content="",
        summary_payload={},
    )

    # Path traversal must not escape the report root.
    root = tmp_path.resolve()
    for key in ("report_path", "summary_path"):
        candidate = Path(bundle[key]).resolve()
        assert candidate.is_relative_to(root), (
            f"{key}={candidate!s} escaped root {root!s}"
        )
    # The literal "../" traversal MUST NOT appear in the returned filename;
    # the sanitizer collapses the path separators into an underscore so what
    # lands on disk is a flat filename inside the report root.
    assert ".." not in Path(bundle["report_path"]).name
    assert "/" not in Path(bundle["report_path"]).name
    assert "\\" not in Path(bundle["report_path"]).name


def test_report_write_tool_rejects_extension_with_path_separator(
    tmp_path: Path,
) -> None:
    """A ``report_extension`` that carries a path separator falls back to
    the platform default (``csv``); an escape via ``report_extension`` never
    reaches disk.
    """
    settings = _StubReportSettings(tmp_path)
    tool = ReportWriteTool(settings=settings)
    bundle = tool.write_bundle(
        run_id="run-1",
        report_content="",
        summary_payload={},
        report_extension="../../evil",
    )
    root = tmp_path.resolve()
    candidate = Path(bundle["report_path"]).resolve()
    assert candidate.is_relative_to(root)
    # Fell back to the default (csv), not the malicious value.
    assert candidate.suffix == ".csv"


def test_report_write_tool_confine_raises_on_absolute_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The private ``_confine`` helper raises ``ValidationError`` when a
    caller directly constructs a path outside the root (defense in depth
    for a future call site that bypasses the sanitizer).
    """
    root = tmp_path.resolve()
    with pytest.raises(ValidationError):
        # Absolute path -> ``root / absolute`` collapses to ``absolute``,
        # which won't be relative to ``root``. ``_confine`` MUST reject.
        reporting_mod._confine(root, "/etc/passwd")


# ---------------------------------------------------------------------------
# (d) AuditLogTool ignores agent-supplied user_id
# ---------------------------------------------------------------------------


class _StubPlatformSettings:
    """Minimal PlatformSettings duck-type for AuditLogTool construction.

    AuditLogTool only touches ``settings`` to pass into ``async_session_scope``,
    which reads ``.database_url``. We inherit from the real Settings so all
    other required attributes exist.
    """

    def __init__(self) -> None:
        self._inner = get_settings()

    def __getattr__(self, name: str):  # pragma: no cover - passthrough
        return getattr(self._inner, name)


async def test_audit_log_tool_ignores_agent_user_id(test_db) -> None:
    """The tool's ``forward`` signature does not accept ``user_id`` at all,
    and the persisted row carries the ambient task user (or ``\"system\"``
    when no task is running).
    """
    settings = _StubPlatformSettings()
    tool = AuditLogTool(settings=settings)

    # Sanity: user_id is NOT in the tool's declared input schema.
    assert "user_id" not in tool.inputs

    # A caller who tries to pass user_id as a kwarg gets a TypeError from
    # the ``forward`` signature -- no silent acceptance of the spoofed id.
    with pytest.raises(TypeError):
        await tool.forward(
            action="record",
            run_id="run-x",
            stage="stage-x",
            event_action="action-x",
            user_id="spoofed-attacker",  # type: ignore[call-arg]
        )


async def test_audit_log_tool_binds_ambient_user_id(test_db) -> None:
    """When ``_current_task_user_id`` is set (as the platform_task wrapper
    does), the recorded row carries that identity -- proving the tool
    derives the user from ambient, not from tool input.
    """
    settings = _StubPlatformSettings()
    tool = AuditLogTool(settings=settings)

    token = _current_task_user_id.set("authenticated-user-123")
    try:
        response = await tool.forward(
            action="record",
            run_id="run-inheritance",
            stage="stage-inheritance",
            event_action="action-inheritance",
            details={"note": "test"},
        )
    finally:
        _current_task_user_id.reset(token)

    assert response["user_id"] == "authenticated-user-123"

    async with async_session_scope() as session:
        rows = list(
            (
                await session.exec(
                    select(AuditEventRecord)
                    .where(AuditEventRecord.run_id == "run-inheritance")
                    .order_by(desc(AuditEventRecord.id))
                )
            ).all()
        )
    assert rows, "audit row was not persisted"
    assert rows[0].user_id == "authenticated-user-123"


async def test_audit_log_tool_defaults_user_to_system_when_ambient_unset(
    test_db,
) -> None:
    """Outside a task context (no ``_current_task_user_id`` binding), the
    tool falls back to ``\"system\"``.
    """
    settings = _StubPlatformSettings()
    tool = AuditLogTool(settings=settings)
    # Sanity: nothing bound.
    assert _current_task_user_id.get() is None

    response = await tool.forward(
        action="record",
        run_id="run-nobody",
        stage="stage-nobody",
        event_action="action-nobody",
    )
    assert response["user_id"] == "system"


async def test_audit_log_tool_details_size_cap(test_db) -> None:
    """A ``details`` payload larger than the cap is refused with
    ``ValidationError`` before the DB write.
    """
    settings = _StubPlatformSettings()
    tool = AuditLogTool(settings=settings)
    huge = {"blob": "A" * (64 * 1024)}  # comfortably over the 32KiB cap

    with pytest.raises(ValidationError):
        await tool.forward(
            action="record",
            run_id="run-huge",
            stage="stage-huge",
            event_action="action-huge",
            details=huge,
        )


async def test_audit_log_tool_list_accepts_offset(test_db) -> None:
    """The list action supports an ``offset`` argument for pagination and
    rejects negative offsets."""
    settings = _StubPlatformSettings()
    tool = AuditLogTool(settings=settings)

    # Seed a couple of rows so a list query succeeds.
    async with async_session_scope() as session:
        for i in range(3):
            session.add(
                AuditEventRecord(
                    run_id="run-page",
                    stage="stage-page",
                    action="action-page",
                    status="ok",
                    target="",
                    user_id="system",
                    details_json=None,
                )
            )
        await session.commit()

    page1 = await tool.forward(
        action="list", run_id="run-page", limit=2, offset=0,
    )
    assert page1["returned"] == 2
    assert page1["offset"] == 0

    page2 = await tool.forward(
        action="list", run_id="run-page", limit=2, offset=2,
    )
    assert page2["returned"] == 1
    assert page2["offset"] == 2

    with pytest.raises(ValidationError):
        await tool.forward(
            action="list", run_id="run-page", limit=2, offset=-5,
        )
