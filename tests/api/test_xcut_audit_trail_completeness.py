"""XCUT-15: Audit trail completeness -- every state-changing operation produces an audit event.

Proves:
1. Every POST/PUT/PATCH/DELETE endpoint that modifies state records an audit event
2. Audit events include action type, user ID, timestamp, and affected resource
3. Read-only GET endpoints do NOT produce audit events

Strategy:
- Exercise each mutating endpoint with valid auth and payloads
- Query audit events via DB and verify corresponding records exist
- Verify GET endpoints produce zero audit events
"""
from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.api.constants import (
    AUDIT_ACTION_CONFIG_UPDATE,
    AUDIT_ACTION_CREATE_API_KEY,
    AUDIT_ACTION_FINDING_BULK_UPDATE,
    AUDIT_ACTION_REVOKE_API_KEY,
    AUDIT_ACTION_SCAN_SUBMIT,
    AUDIT_ACTION_SESSION_CREATE,
    AUDIT_ACTION_SESSION_MESSAGE,
    AUDIT_ACTION_SYSTEM_CREATE,
    AUDIT_ACTION_SYSTEM_DELETE,
    AUDIT_ACTION_SYSTEM_UPDATE,
    AUDIT_ACTION_TASK_CANCEL,
    AUDIT_ACTION_TASK_RESUME,
    AUDIT_ACTION_TASK_SUBMIT,
    AUDIT_ACTION_TOKEN_ISSUE,
    AUDIT_ACTION_TOKEN_REFRESH,
    AUDIT_ACTION_TOOL_INVOKE,
)

__all__: list[str] = []


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _get_audit_events(action: str | None = None) -> list[dict]:
    """Query audit events directly from DB, optionally filtered by action."""
    from sqlmodel import select

    from aila.storage.database import session_scope
    from aila.storage.db_models import AuditEventRecord

    with session_scope() as session:
        stmt = select(AuditEventRecord)
        if action:
            stmt = stmt.where(AuditEventRecord.action == action)
        rows = list(session.exec(stmt).all())
        return [
            {
                "action": r.action,
                "user_id": r.user_id,
                "target": r.target,
                "stage": r.stage,
                "status": r.status,
                "details_json": r.details_json,
                "created_at": str(r.created_at),
            }
            for r in rows
        ]


# ─── Fixture: app with mock platform for task/scan submission ───────────────


@pytest_asyncio.fixture(scope="function")
async def audit_client(test_db, admin_key_record) -> AsyncClient:
    """Async client with a stub platform that supports task submission and tool invoke."""
    from aila.api.app import create_app
    from aila.platform.runtime.tools import ToolRegistry
    from aila.storage.registry import ConfigRegistry

    config_registry = ConfigRegistry()
    tool_registry = ToolRegistry()

    # Register a dummy tool for POST /tools/{key}
    dummy_tool = MagicMock()
    dummy_tool.name = "test_tool"
    dummy_tool.description = "A test tool"
    dummy_tool.inputs = {}
    dummy_tool.output_type = "string"
    dummy_tool.forward = MagicMock(return_value="ok")
    tool_registry.register("test.tool", dummy_tool)

    stub_runtime = MagicMock()
    stub_runtime.config_registry = config_registry
    stub_runtime.tool_registry = tool_registry

    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime
    stub_platform.handle = MagicMock(return_value=MagicMock(summary="test response", run_id=None))

    # Mock task_queue.submit for POST /task
    mock_handle = MagicMock()
    mock_handle.task_id = "task-audit-test-001"
    stub_platform.task_queue = MagicMock()
    stub_platform.task_queue.submit = MagicMock(return_value=mock_handle)

    test_app = create_app()
    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client


# ─── Auth endpoints ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_token_issue_produces_audit(audit_client, admin_key_record):
    """POST /auth/token records a token_issue audit event."""
    raw_key = admin_key_record._raw_key
    resp = await audit_client.post("/auth/token", json={"api_key": raw_key})
    assert resp.status_code == 200

    events = _get_audit_events(AUDIT_ACTION_TOKEN_ISSUE)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == admin_key_record.id
    assert event["target"] == admin_key_record.key_prefix
    assert event["stage"] == "auth"
    assert event["created_at"] is not None


@pytest.mark.asyncio
async def test_token_refresh_produces_audit(audit_client, admin_key_record):
    """POST /auth/refresh records a token_refresh audit event."""
    raw_key = admin_key_record._raw_key
    login_resp = await audit_client.post("/auth/token", json={"api_key": raw_key})
    refresh_token = login_resp.json()["refresh_token"]

    resp = await audit_client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200

    events = _get_audit_events(AUDIT_ACTION_TOKEN_REFRESH)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == admin_key_record.id
    assert event["stage"] == "auth"


@pytest.mark.asyncio
async def test_create_api_key_produces_audit(audit_client, admin_token, admin_key_record):
    """POST /auth/keys records a create_api_key audit event."""
    resp = await audit_client.post(
        "/auth/keys",
        json={"label": "audit-test-key", "role": "reader"},
        headers=_auth_header(admin_token),
    )
    assert resp.status_code == 201

    events = _get_audit_events(AUDIT_ACTION_CREATE_API_KEY)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == admin_key_record.id
    assert event["stage"] == "auth"


@pytest.mark.asyncio
async def test_revoke_api_key_produces_audit(audit_client, admin_token, admin_key_record):
    """DELETE /auth/keys/{id} records a revoke_api_key audit event."""
    # Create a key to revoke
    create_resp = await audit_client.post(
        "/auth/keys",
        json={"label": "to-revoke", "role": "reader"},
        headers=_auth_header(admin_token),
    )
    key_id = create_resp.json()["key_id"]

    resp = await audit_client.delete(
        f"/auth/keys/{key_id}",
        headers=_auth_header(admin_token),
    )
    assert resp.status_code == 200

    events = _get_audit_events(AUDIT_ACTION_REVOKE_API_KEY)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == admin_key_record.id
    assert event["stage"] == "auth"


# ─── Session endpoints ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_session_create_produces_audit(audit_client, admin_token, admin_key_record):
    """POST /sessions records a session_create audit event."""
    resp = await audit_client.post(
        "/sessions",
        json={"title": "Audit trail test session"},
        headers=_auth_header(admin_token),
    )
    assert resp.status_code == 201

    events = _get_audit_events(AUDIT_ACTION_SESSION_CREATE)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == admin_key_record.id
    assert event["stage"] == "session"
    details = json.loads(event["details_json"])
    assert details["title"] == "Audit trail test session"


@pytest.mark.asyncio
async def test_session_message_produces_audit(audit_client, admin_token, admin_key_record):
    """POST /sessions/{id}/messages records a session_message audit event."""
    # Create session first
    create_resp = await audit_client.post(
        "/sessions",
        json={"title": "Message audit test"},
        headers=_auth_header(admin_token),
    )
    session_id = create_resp.json()["session_id"]

    resp = await audit_client.post(
        f"/sessions/{session_id}/messages",
        json={"content": "test message for audit"},
        headers=_auth_header(admin_token),
    )
    assert resp.status_code == 200

    events = _get_audit_events(AUDIT_ACTION_SESSION_MESSAGE)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == admin_key_record.id
    assert event["target"] == session_id
    assert event["stage"] == "session"


# ─── System endpoints ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_system_create_produces_audit(audit_client, operator_token, operator_key_record):
    """POST /systems records a system_create audit event."""
    resp = await audit_client.post(
        "/systems",
        json={
            "name": "audit-test-sys",
            "host": "10.0.0.1",
            "username": "root",
            "port": 22,
        },
        headers=_auth_header(operator_token),
    )
    assert resp.status_code == 201

    events = _get_audit_events(AUDIT_ACTION_SYSTEM_CREATE)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == operator_key_record.id
    assert event["target"] == "audit-test-sys"
    assert event["stage"] == "system"


@pytest.mark.asyncio
async def test_system_update_produces_audit(audit_client, operator_token, operator_key_record):
    """PUT /systems/{id} records a system_update audit event."""
    # Create system first
    create_resp = await audit_client.post(
        "/systems",
        json={"name": "update-audit-sys", "host": "10.0.0.2", "username": "root", "port": 22},
        headers=_auth_header(operator_token),
    )
    system_id = create_resp.json()["id"]

    resp = await audit_client.put(
        f"/systems/{system_id}",
        json={"description": "updated for audit test"},
        headers=_auth_header(operator_token),
    )
    assert resp.status_code == 200

    events = _get_audit_events(AUDIT_ACTION_SYSTEM_UPDATE)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == operator_key_record.id
    assert event["stage"] == "system"
    details = json.loads(event["details_json"])
    assert "description" in details["fields"]


@pytest.mark.asyncio
async def test_system_delete_produces_audit(audit_client, operator_token, operator_key_record):
    """DELETE /systems/{id} records a system_delete audit event."""
    # Create system to delete
    create_resp = await audit_client.post(
        "/systems",
        json={"name": "delete-audit-sys", "host": "10.0.0.3", "username": "root", "port": 22},
        headers=_auth_header(operator_token),
    )
    system_id = create_resp.json()["id"]

    resp = await audit_client.delete(
        f"/systems/{system_id}",
        headers=_auth_header(operator_token),
    )
    assert resp.status_code == 204

    events = _get_audit_events(AUDIT_ACTION_SYSTEM_DELETE)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == operator_key_record.id
    assert event["target"] == "delete-audit-sys"
    assert event["stage"] == "system"


# ─── Task endpoints ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_task_submit_produces_audit(audit_client, operator_token, operator_key_record):
    """POST /task records a task_submit audit event."""
    resp = await audit_client.post(
        "/task",
        json={"query_text": "test audit query"},
        headers=_auth_header(operator_token),
    )
    assert resp.status_code == 202

    events = _get_audit_events(AUDIT_ACTION_TASK_SUBMIT)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == operator_key_record.id
    assert event["stage"] == "task"


@pytest.mark.asyncio
async def test_task_cancel_produces_audit(audit_client, operator_token, operator_key_record):
    """POST /tasks/{id}/cancel records a task_cancel audit event when cancel succeeds."""
    from aila.platform.tasks.models import TaskRecord, TaskStatus
    from aila.storage.database import session_scope

    # Seed a QUEUED task that can be cancelled
    task_record = TaskRecord(
        id="cancel-audit-task",
        track="platform",
        status=TaskStatus.QUEUED,
        fn_path="test.func",
        fn_module="test",
        user_id=operator_key_record.id,
        group_id=operator_key_record.role,
    )
    with session_scope() as session:
        session.add(task_record)
        session.commit()

    resp = await audit_client.post(
        "/tasks/cancel-audit-task/cancel",
        headers=_auth_header(operator_token),
    )
    assert resp.status_code == 200

    events = _get_audit_events(AUDIT_ACTION_TASK_CANCEL)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == operator_key_record.id
    assert event["target"] == "cancel-audit-task"
    assert event["stage"] == "task"


@pytest.mark.asyncio
async def test_task_resume_produces_audit(audit_client, operator_token, operator_key_record):
    """POST /tasks/{id}/resume records a task_resume audit event when resume succeeds."""
    from aila.platform.tasks.models import TaskRecord, TaskStatus
    from aila.storage.database import session_scope

    # Seed a PAUSED task that can be resumed
    task_record = TaskRecord(
        id="resume-audit-task",
        track="platform",
        status=TaskStatus.PAUSED,
        fn_path="test.func",
        fn_module="test",
        user_id=operator_key_record.id,
        group_id=operator_key_record.role,
    )
    with session_scope() as session:
        session.add(task_record)
        session.commit()

    resp = await audit_client.post(
        "/tasks/resume-audit-task/resume",
        headers=_auth_header(operator_token),
    )
    assert resp.status_code == 200

    events = _get_audit_events(AUDIT_ACTION_TASK_RESUME)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == operator_key_record.id
    assert event["target"] == "resume-audit-task"
    assert event["stage"] == "task"


# ─── Tool endpoint ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tool_invoke_produces_audit(audit_client, operator_token, operator_key_record):
    """POST /tools/{key} records a tool_invoke audit event."""
    resp = await audit_client.post(
        "/tools/test.tool",
        json={"kwargs": {}},
        headers=_auth_header(operator_token),
    )
    assert resp.status_code == 200

    events = _get_audit_events(AUDIT_ACTION_TOOL_INVOKE)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == operator_key_record.id
    assert event["target"] == "test.tool"
    assert event["stage"] == "tool"


# ─── Config endpoint ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_config_update_produces_audit(test_db, admin_key_record, admin_token):
    """PUT /config/{ns}/{key} records a config_update audit event."""
    from aila.api.app import create_app
    from aila.platform.config import PlatformConfigSchema
    from aila.platform.contracts._common import utc_now
    from aila.storage.database import session_scope
    from aila.storage.db_models import ConfigEntryRecord
    from aila.storage.registry import ConfigRegistry

    # Seed a real platform config entry that PlatformConfigSchema recognizes
    with session_scope() as session:
        session.add(
            ConfigEntryRecord(
                namespace="platform",
                key="user_agent",
                value="AILA/test",
                value_type="str",
                updated_at=utc_now(),
            )
        )
        session.commit()

    config_registry = ConfigRegistry()
    config_registry.register("platform", PlatformConfigSchema)

    stub_runtime = MagicMock()
    stub_runtime.config_registry = config_registry
    stub_runtime.tool_registry = MagicMock()
    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app = create_app()
    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        resp = await client.put(
            "/config/platform/user_agent",
            json={"value": "AILA/audit-test"},
            headers=_auth_header(admin_token),
        )

    assert resp.status_code == 200, f"Config update failed: {resp.text}"

    events = _get_audit_events(AUDIT_ACTION_CONFIG_UPDATE)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == admin_key_record.id
    assert event["stage"] == "config"
    assert event["target"] == "platform/user_agent"


# ─── Scan submission endpoint ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_submit_produces_audit(audit_client, operator_token, operator_key_record):
    """POST /analyze records a scan_submit audit event."""
    with patch("aila.platform.tasks.queue.TaskQueue") as mock_tq_cls:
        mock_handle = MagicMock()
        mock_handle.task_id = "scan-audit-task-001"
        mock_tq_cls.return_value.submit.return_value = mock_handle

        resp = await audit_client.post(
            "/analyze",
            json={"query_text": "scan test for audit", "targets": ["web01"]},
            headers=_auth_header(operator_token),
        )
        assert resp.status_code == 202

    events = _get_audit_events(AUDIT_ACTION_SCAN_SUBMIT)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == operator_key_record.id
    assert event["stage"] == "scan"


# ─── Vulnerability bulk update ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_finding_bulk_update_produces_audit(
    audit_client, operator_token, operator_key_record, seeded_findings,
):
    """PATCH /vulnerability/findings/bulk records a finding_bulk_update audit event."""
    finding_ids = [str(f.id) for f in seeded_findings]

    resp = await audit_client.patch(
        "/vulnerability/findings/bulk",
        json={"finding_ids": finding_ids, "status": "remediated"},
        headers=_auth_header(operator_token),
    )
    assert resp.status_code == 200

    events = _get_audit_events(AUDIT_ACTION_FINDING_BULK_UPDATE)
    assert len(events) >= 1
    event = events[-1]
    assert event["user_id"] == operator_key_record.id
    assert event["stage"] == "finding"
    details = json.loads(event["details_json"])
    assert details["new_status"] == "remediated"
    assert details["count"] == len(finding_ids)


# ─── Negative: GET endpoints produce NO audit ────────────────────────────────


@pytest.mark.asyncio
async def test_get_endpoints_produce_no_audit(audit_client, admin_token, test_db):
    """GET endpoints (read-only) must NOT produce audit events.

    Exercises several GET endpoints and verifies total audit count does not
    increase from those calls alone.
    """
    # Clear any pre-existing audit events and capture baseline count
    before = _get_audit_events()
    baseline = len(before)

    # Exercise GET endpoints
    await audit_client.get("/systems", headers=_auth_header(admin_token))
    await audit_client.get("/tasks", headers=_auth_header(admin_token))
    await audit_client.get("/tools", headers=_auth_header(admin_token))
    await audit_client.get("/audit/events", headers=_auth_header(admin_token))
    await audit_client.get("/auth/keys", headers=_auth_header(admin_token))
    await audit_client.get("/config", headers=_auth_header(admin_token))
    await audit_client.get("/health", headers=_auth_header(admin_token))

    after = _get_audit_events()
    assert len(after) == baseline, (
        f"GET endpoints produced {len(after) - baseline} audit events -- "
        "read-only operations must not create audit records"
    )


# ─── Coverage summary: all mutating actions produce audit ────────────────────


@pytest.mark.asyncio
async def test_all_audit_actions_have_constants():
    """Every audit action constant is a non-empty string and unique."""
    actions = [
        AUDIT_ACTION_TOKEN_ISSUE,
        AUDIT_ACTION_TOKEN_REFRESH,
        AUDIT_ACTION_CREATE_API_KEY,
        AUDIT_ACTION_REVOKE_API_KEY,
        AUDIT_ACTION_CONFIG_UPDATE,
        AUDIT_ACTION_SCAN_SUBMIT,
        AUDIT_ACTION_SESSION_CREATE,
        AUDIT_ACTION_SESSION_MESSAGE,
        AUDIT_ACTION_SYSTEM_CREATE,
        AUDIT_ACTION_SYSTEM_UPDATE,
        AUDIT_ACTION_SYSTEM_DELETE,
        AUDIT_ACTION_TASK_CANCEL,
        AUDIT_ACTION_TASK_RESUME,
        AUDIT_ACTION_TASK_SUBMIT,
        AUDIT_ACTION_TOOL_INVOKE,
        AUDIT_ACTION_FINDING_BULK_UPDATE,
    ]
    for a in actions:
        assert isinstance(a, str) and len(a) > 0
    assert len(set(actions)) == len(actions), "Duplicate audit action constants detected"
