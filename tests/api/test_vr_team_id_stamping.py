"""#53 -- root task submits from VR HTTP handlers stamp team_id.

TaskQueue.submit inherits team_id from a ContextVar that @platform_task
sets from the running task, so child submits made from workers inherit
the parent's team_id automatically. Root submits from HTTP request
handlers run OUTSIDE any task execution -- the ContextVar is None
there -- so the handler MUST pass team_id=auth.team_id explicitly.

This is the representative test for the vr module. It patches
aila.api.deps.get_task_queue with an AsyncMock queue, invokes the
enqueue_ranking handler directly with an explicit AuthContext, and
asserts submit was awaited with team_id forwarded. Every other root
submit in vr/api_router.py follows the same pattern (14 sites plus this
one, all pass team_id=auth.team_id -- or team_id derived from a
team-filtered inv row -- to the queue).

Handlers are invoked directly with an explicit AuthContext (the
router-level Depends is not resolved on direct invocation).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from aila.api.auth import AuthContext
from aila.api.limiter import limiter as _shared_limiter
from aila.modules.vr.api_router import create_vr_router
from aila.modules.vr.db_models import VRTargetRecord, VRWorkspaceRecord
from aila.storage.database import async_session_scope


@pytest.fixture(autouse=True)
def _disable_shared_limiter():
    """Disable the shared slowapi limiter for direct-invocation tests.

    vr/api_router.py imports the process-wide ``aila.api.limiter.limiter``;
    @limiter.limit(...) inspects request.headers via its key_func, which
    trips on our minimal _Req stand-in. Flip it off for the test's
    duration and restore after.
    """
    prev = _shared_limiter.enabled
    _shared_limiter.enabled = False
    yield
    _shared_limiter.enabled = prev


class _Req:
    """Minimal stand-in for FastAPI Request; get_task_queue is patched."""


def _endpoint(path: str, method: str):
    """Look up a route handler by path + method on a fresh router."""
    for route in create_vr_router().routes:
        methods = getattr(route, "methods", set()) or set()
        if getattr(route, "path", None) == path and method in methods:
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


def _auth(team_id: str | None, *, user_id: str = "u1", role: str = "operator") -> AuthContext:
    return AuthContext(
        user_id=user_id,
        role=role,
        auth_type="user",
        team_id=team_id,
    )


async def _seed_target(suffix: str, team_id: str | None) -> str:
    """Create a workspace + team-owned target row and return the target id."""
    async with async_session_scope() as session:
        ws = VRWorkspaceRecord(
            name=f"ws-{suffix}",
            slug=f"ws-{suffix}",
            description="team_id stamping fixture",
            theme="custom",
            team_id=team_id,
        )
        session.add(ws)
        await session.flush()
        target = VRTargetRecord(
            workspace_id=ws.id,
            team_id=team_id,
            display_name=f"target-{suffix}",
            kind="native_binary",
            descriptor_json="{}",
            primary_language="c",
        )
        session.add(target)
        await session.flush()
        tid = target.id
        await session.commit()
    return tid


async def test_enqueue_ranking_forwards_team_id(test_db) -> None:
    """The root submit from POST /targets/{id}/rank carries
    team_id=auth.team_id so the ARQ TaskRecord is team-scoped (#53)."""
    del test_db
    suffix = uuid4().hex[:8]
    team_id = f"team-{suffix}"
    target_id = await _seed_target(suffix, team_id=team_id)

    submit = AsyncMock()
    submit.return_value = MagicMock(task_id="task-under-test")
    fake_queue = MagicMock()
    fake_queue.submit = submit

    handler = _endpoint("/targets/{target_id}/rank", "POST")
    with patch("aila.api.deps.get_task_queue", return_value=fake_queue):
        await handler(_Req(), target_id, auth=_auth(team_id))

    submit.assert_awaited_once()
    kwargs = submit.await_args.kwargs
    assert kwargs["team_id"] == team_id, (
        f"root submit MUST forward the caller's team_id so the resulting "
        f"TaskRecord is team-scoped (#53). Got team_id={kwargs.get('team_id')!r}, "
        f"expected {team_id!r}."
    )
    # Sanity: the submit still targets the vr queue and the ranking fn.
    assert kwargs["track"] == "vr"
    assert kwargs["kwargs"] == {"target_id": target_id}
    assert kwargs["user_id"] == "u1"


async def test_enqueue_ranking_god_tier_forwards_none(test_db) -> None:
    """God-tier admin (team_id=None) also flows through: the kwarg is
    present and explicitly None, matching AuthContext.team_id. Without
    an explicit None, the ContextVar inheritance path in
    TaskQueue.submit would silently take over -- for root submits from
    request handlers the ContextVar is unset anyway, but the invariant
    'root submits always pass team_id' MUST hold uniformly."""
    del test_db
    suffix = uuid4().hex[:8]
    target_id = await _seed_target(suffix, team_id=None)

    submit = AsyncMock()
    submit.return_value = MagicMock(task_id="task-god")
    fake_queue = MagicMock()
    fake_queue.submit = submit

    admin = _auth(None, user_id="admin", role="admin")
    handler = _endpoint("/targets/{target_id}/rank", "POST")
    with patch("aila.api.deps.get_task_queue", return_value=fake_queue):
        await handler(_Req(), target_id, auth=admin)

    submit.assert_awaited_once()
    kwargs = submit.await_args.kwargs
    assert "team_id" in kwargs, (
        "team_id MUST be passed explicitly even for admin (team_id=None) "
        "so the ContextVar inheritance path is not silently disabled."
    )
    assert kwargs["team_id"] is None
