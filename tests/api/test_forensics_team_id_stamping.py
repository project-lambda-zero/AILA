"""#53 -- root task submits from forensics HTTP handlers stamp team_id.

TaskQueue.submit inherits team_id from a ContextVar that @platform_task
sets from the running task, so child submits made from workers inherit
the parent's team_id automatically. Root submits from HTTP request
handlers run OUTSIDE any task execution -- the ContextVar is None
there -- so the handler MUST pass team_id=auth.team_id explicitly.

This is the representative test for the forensics module. It patches
aila.api.deps.get_task_queue with an AsyncMock queue, invokes the
trigger_full_analysis handler directly with an explicit AuthContext,
and asserts submit was awaited with team_id forwarded.

Handlers are invoked directly with an explicit AuthContext (the
router-level Depends is not resolved on direct invocation).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from aila.api.auth import AuthContext
from aila.modules.forensics.api_router import create_forensics_router
from aila.modules.forensics.api_router import limiter as _forensics_limiter
from aila.modules.forensics.db_models import ForensicsProjectRecord
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord


@pytest.fixture(autouse=True)
def _disable_forensics_limiter():
    """Disable the module-local slowapi limiter for direct-invocation tests."""
    prev = _forensics_limiter.enabled
    _forensics_limiter.enabled = False
    yield
    _forensics_limiter.enabled = prev


class _Req:
    """Minimal stand-in for FastAPI Request; get_task_queue is patched."""


def _endpoint(path: str, method: str):
    """Look up a route handler by path + method on a fresh router."""
    for route in create_forensics_router().routes:
        methods = getattr(route, "methods", set()) or set()
        if getattr(route, "path", None) == path and method in methods:
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


def _auth(team_id: str) -> AuthContext:
    return AuthContext(
        user_id=f"u-{team_id}",
        role="operator",
        auth_type="user",
        team_id=team_id,
    )


async def _seed_project(suffix: str, team_id: str) -> str:
    """Create a system + team-owned project row and return the project id."""
    async with async_session_scope() as session:
        sys_rec = ManagedSystemRecord(
            name=f"sys-{suffix}", host="10.0.0.1", username="u",
        )
        session.add(sys_rec)
        await session.flush()
        proj = ForensicsProjectRecord(
            name=f"proj-{suffix}",
            system_id=sys_rec.id,
            team_id=team_id,
            evidence_directory=f"/tmp/{suffix}",
        )
        session.add(proj)
        await session.flush()
        pid = proj.id
        await session.commit()
    return pid


async def test_trigger_full_analysis_forwards_team_id(test_db) -> None:
    """The root submit from POST /projects/{id}/full-analysis carries
    team_id=auth.team_id so the ARQ TaskRecord is team-scoped."""
    suffix = uuid4().hex[:8]
    team_id = f"team-{suffix}"
    pid = await _seed_project(suffix, team_id=team_id)

    submit = AsyncMock()
    submit.return_value = MagicMock(task_id="task-under-test")
    fake_queue = MagicMock()
    fake_queue.submit = submit

    handler = _endpoint("/projects/{project_id}/full-analysis", "POST")
    with patch("aila.api.deps.get_task_queue", return_value=fake_queue):
        await handler(_Req(), pid, auth=_auth(team_id))

    submit.assert_awaited_once()
    kwargs = submit.await_args.kwargs
    assert kwargs["team_id"] == team_id, (
        f"root submit MUST forward the caller's team_id so the resulting "
        f"TaskRecord is team-scoped (#53). Got team_id={kwargs.get('team_id')!r}, "
        f"expected {team_id!r}."
    )
    # Sanity: the submit still targets the forensics queue and the analysis fn.
    assert kwargs["track"] == "forensics"
    assert kwargs["kwargs"]["project_id"] == pid
    assert kwargs["user_id"] == f"u-{team_id}"


async def test_trigger_full_analysis_god_tier_forwards_none(test_db) -> None:
    """God-tier admin (team_id=None) also flows through: the kwarg is
    present and explicitly None, matching AuthContext.team_id."""
    suffix = uuid4().hex[:8]
    async with async_session_scope() as session:
        sys_rec = ManagedSystemRecord(
            name=f"sys-{suffix}", host="10.0.0.1", username="u",
        )
        session.add(sys_rec)
        await session.flush()
        proj = ForensicsProjectRecord(
            name=f"proj-{suffix}",
            system_id=sys_rec.id,
            team_id=None,
            evidence_directory=f"/tmp/{suffix}",
        )
        session.add(proj)
        await session.flush()
        pid = proj.id
        await session.commit()

    submit = AsyncMock()
    submit.return_value = MagicMock(task_id="task-god")
    fake_queue = MagicMock()
    fake_queue.submit = submit

    admin = AuthContext(
        user_id="admin", role="admin", auth_type="user", team_id=None,
    )
    handler = _endpoint("/projects/{project_id}/full-analysis", "POST")
    with patch("aila.api.deps.get_task_queue", return_value=fake_queue):
        await handler(_Req(), pid, auth=admin)

    submit.assert_awaited_once()
    kwargs = submit.await_args.kwargs
    assert "team_id" in kwargs, (
        "team_id MUST be passed explicitly even for admin (team_id=None) "
        "so the ContextVar inheritance path is not silently disabled."
    )
    assert kwargs["team_id"] is None
