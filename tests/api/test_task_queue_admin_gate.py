"""Queue depth, drain, and requeue act on every team's tasks (#433).

A team-scoped admin is refused on all three; a god-tier admin keeps access.
"""
from __future__ import annotations

import time
import uuid
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.api.app import create_app
from aila.api.auth import AuthContext, require_user_or_api_key


class _RecordingQueue:
    """Stands in for the platform TaskQueue; records which operations ran."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def depth(self) -> dict[str, int]:
        self.calls.append("depth")
        return {"queued": 2}

    async def drain(self) -> int:
        self.calls.append("drain")
        return 2

    async def requeue_failed(self, *, max_age_hours: int) -> int:
        self.calls.append(f"requeue:{max_age_hours}")
        return 1


@pytest_asyncio.fixture(scope="function")
async def queue_app(test_db):
    queue = _RecordingQueue()
    stub_platform = MagicMock()
    stub_platform.task_queue = queue
    app = create_app()
    app.state.platform = stub_platform
    app.state.start_time = time.monotonic()
    return app, queue


async def _call_queue_endpoints(app, principal: AuthContext) -> list[int]:
    app.dependency_overrides[require_user_or_api_key] = lambda: principal
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        return [
            (await c.get("/tasks/queue-depth")).status_code,
            (await c.post("/tasks/drain")).status_code,
            (await c.post("/tasks/requeue-failed", params={"max_age_hours": 6})).status_code,
        ]


@pytest.mark.asyncio
async def test_team_scoped_admin_cannot_operate_the_shared_queue(queue_app) -> None:
    app, queue = queue_app
    team_admin = AuthContext(user_id="team-admin", role="admin", auth_type="user", team_id=f"team-{uuid.uuid4().hex}")

    assert await _call_queue_endpoints(app, team_admin) == [403, 403, 403]
    assert queue.calls == []


@pytest.mark.asyncio
async def test_god_tier_admin_operates_the_shared_queue(queue_app) -> None:
    app, queue = queue_app
    god_admin = AuthContext(user_id=f"god-{uuid.uuid4().hex}", role="admin", auth_type="user", team_id=None)

    assert await _call_queue_endpoints(app, god_admin) == [200, 200, 200]
    assert queue.calls == ["depth", "drain", "requeue:6"]


@pytest.mark.asyncio
async def test_operator_cannot_operate_the_shared_queue(queue_app) -> None:
    app, queue = queue_app
    operator = AuthContext(user_id="op", role="operator", auth_type="user", team_id=None)

    assert await _call_queue_endpoints(app, operator) == [403, 403, 403]
    assert queue.calls == []
