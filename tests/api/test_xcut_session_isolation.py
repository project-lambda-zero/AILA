"""Cross-cutting verification: session, message, and task isolation (XCUT-06).

Proves that User A's sessions, messages, and tasks are completely invisible
to User B.  Sessions are scoped by user_id (== key.id from JWT), tasks are
scoped by group_id (== key.role) via TaskRepository.

Test matrix:
  1. User A creates session; User B gets 404 on User A's session messages.
  2. User B creates session; User A gets 404 on User B's session messages.
  3. Messages posted in User A's session are absent from User B's query.
  4. User A cannot post messages to User B's session (404).
  5. Tasks with group_id='reader' are invisible to operator; admin sees all.
  6. Tasks with group_id='operator' are invisible to reader.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Session isolation (user_id scoping)
# ---------------------------------------------------------------------------


class TestSessionIsolation:
    """User A cannot see or interact with User B's sessions."""

    @pytest.mark.asyncio
    async def test_user_a_session_invisible_to_user_b(
        self, async_client, admin_token, reader_token,
    ):
        """Admin creates a session; reader cannot read its messages (404)."""
        # Admin creates a session
        resp = await async_client.post(
            "/sessions",
            json={"title": "Admin private session"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 201
        session_id = resp.json()["session_id"]

        # Reader tries to read admin's session messages -> 404
        resp = await async_client.get(
            f"/sessions/{session_id}/messages",
            headers={"Authorization": f"Bearer {reader_token}"},
        )
        assert resp.status_code == 404, (
            f"Reader should not see admin's session; got {resp.status_code}"
        )

    @pytest.mark.asyncio
    async def test_user_b_session_invisible_to_user_a(
        self, async_client, admin_token, reader_token,
    ):
        """Reader creates a session; admin (different user_id) cannot read it."""
        # Reader creates a session
        resp = await async_client.post(
            "/sessions",
            json={"title": "Reader private session"},
            headers={"Authorization": f"Bearer {reader_token}"},
        )
        assert resp.status_code == 201
        session_id = resp.json()["session_id"]

        # Admin tries to read reader's session messages -> 404
        # Admin key.id != reader key.id, so session scoping blocks it
        resp = await async_client.get(
            f"/sessions/{session_id}/messages",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 404, (
            f"Admin should not see reader's session (different user_id); got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# Message isolation
# ---------------------------------------------------------------------------


class TestMessageIsolation:
    """Messages posted in one user's session are invisible to another user."""

    @pytest.mark.asyncio
    async def test_messages_invisible_across_users(
        self, async_client, admin_token, reader_token,
    ):
        """Admin posts a message in own session; reader cannot see it."""
        # Admin creates session and posts a message
        resp = await async_client.post(
            "/sessions",
            json={"title": "Admin msg test"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 201
        admin_session_id = resp.json()["session_id"]

        # Admin posts message (platform is None -> 503, but user msg is persisted
        # before platform check in some code paths). We need to verify the
        # message-list endpoint isolation, so we insert the message directly.
        from aila.storage.database import session_scope
        from aila.storage.db_models import SessionMessageRecord

        def _insert_msg():
            with session_scope() as db:
                msg = SessionMessageRecord(
                    session_id=admin_session_id,
                    role="user",
                    content="Secret admin message",
                    run_id=None,
                )
                db.add(msg)
                db.commit()

        import asyncio
        await asyncio.to_thread(_insert_msg)

        # Admin can see own message
        resp = await async_client.get(
            f"/sessions/{admin_session_id}/messages",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 1
        assert resp.json()["items"][0]["content"] == "Secret admin message"

        # Reader cannot see admin's session at all
        resp = await async_client.get(
            f"/sessions/{admin_session_id}/messages",
            headers={"Authorization": f"Bearer {reader_token}"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_user_cannot_post_to_other_users_session(
        self, async_client, admin_token, reader_token,
    ):
        """Reader cannot post a message into admin's session (404)."""
        # Admin creates session
        resp = await async_client.post(
            "/sessions",
            json={"title": "Admin only session"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 201
        admin_session_id = resp.json()["session_id"]

        # Reader tries to post message to admin's session -> 404
        resp = await async_client.post(
            f"/sessions/{admin_session_id}/messages",
            json={"content": "Unauthorized message"},
            headers={"Authorization": f"Bearer {reader_token}"},
        )
        assert resp.status_code == 404, (
            f"Reader should not post to admin's session; got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# Task isolation (group_id scoping via TaskRepository)
# ---------------------------------------------------------------------------


class TestTaskIsolation:
    """Tasks scoped by group_id: non-admin users see only their group's tasks."""

    @pytest.mark.asyncio
    async def test_reader_cannot_see_operator_tasks(
        self, async_client, reader_token, operator_token, test_db,
    ):
        """Tasks with group_id='operator' are invisible to reader."""
        from aila.platform.tasks.models import TaskRecord, TaskStatus
        from aila.storage.database import session_scope

        import asyncio

        def _seed_operator_task():
            with session_scope() as db:
                task = TaskRecord(
                    track="platform",
                    fn_path="test.fn",
                    fn_module="test",
                    status=TaskStatus.QUEUED,
                    user_id="operator-user",
                    group_id="operator",
                )
                db.add(task)
                db.commit()
                db.refresh(task)
                return task.id

        task_id = await asyncio.to_thread(_seed_operator_task)

        # Reader sees empty task list (no operator group tasks)
        resp = await async_client.get(
            "/tasks",
            headers={"Authorization": f"Bearer {reader_token}"},
        )
        assert resp.status_code == 200
        task_ids = [t["task_id"] for t in resp.json()["tasks"]]
        assert task_id not in task_ids, (
            "Reader should not see operator's task"
        )

        # Reader gets 404 on direct task access
        resp = await async_client.get(
            f"/tasks/{task_id}",
            headers={"Authorization": f"Bearer {reader_token}"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_admin_sees_all_tasks(
        self, async_client, admin_token, test_db,
    ):
        """Admin can see tasks from any group_id."""
        from aila.platform.tasks.models import TaskRecord, TaskStatus
        from aila.storage.database import session_scope

        import asyncio

        def _seed_tasks():
            with session_scope() as db:
                t1 = TaskRecord(
                    track="platform",
                    fn_path="test.fn1",
                    fn_module="test",
                    status=TaskStatus.QUEUED,
                    user_id="user-reader",
                    group_id="reader",
                )
                t2 = TaskRecord(
                    track="platform",
                    fn_path="test.fn2",
                    fn_module="test",
                    status=TaskStatus.QUEUED,
                    user_id="user-operator",
                    group_id="operator",
                )
                db.add(t1)
                db.add(t2)
                db.commit()
                db.refresh(t1)
                db.refresh(t2)
                return t1.id, t2.id

        id1, id2 = await asyncio.to_thread(_seed_tasks)

        # Admin sees both tasks
        resp = await async_client.get(
            "/tasks",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        task_ids = [t["task_id"] for t in resp.json()["tasks"]]
        assert id1 in task_ids, "Admin should see reader's task"
        assert id2 in task_ids, "Admin should see operator's task"

    @pytest.mark.asyncio
    async def test_operator_cannot_see_reader_tasks(
        self, async_client, operator_token, test_db,
    ):
        """Tasks with group_id='reader' are invisible to operator."""
        from aila.platform.tasks.models import TaskRecord, TaskStatus
        from aila.storage.database import session_scope

        import asyncio

        def _seed_reader_task():
            with session_scope() as db:
                task = TaskRecord(
                    track="platform",
                    fn_path="test.fn",
                    fn_module="test",
                    status=TaskStatus.DONE,
                    user_id="user-reader",
                    group_id="reader",
                )
                db.add(task)
                db.commit()
                db.refresh(task)
                return task.id

        task_id = await asyncio.to_thread(_seed_reader_task)

        # Operator cannot see reader's task
        resp = await async_client.get(
            f"/tasks/{task_id}",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert resp.status_code == 404, (
            f"Operator should not see reader's task; got {resp.status_code}"
        )
