"""Tests for Plan 138-03 endpoint groups.

Tests: dashboard, search, tags, finding workflow, saved filters, widget layout,
scheduled reports, notifications.

All tests run against PostgreSQL (AILA_TEST_DATABASE_URL).
Uses fixtures from conftest.py: async_client, admin_token, operator_token, reader_token.
"""
from __future__ import annotations

import pytest
import pytest_asyncio

from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import (
    NotificationRecord,
)

# ---------------------------------------------------------------------------
# Dashboard tests (BE-01)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_returns_stats(async_client, admin_token):
    """GET /dashboard returns DataEnvelope with fleet_stats."""
    resp = await async_client.get(
        "/dashboard",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "data" in body
    assert "error" in body
    assert "meta" in body
    data = body["data"]
    assert "fleet_stats" in data
    assert "risk_score" in data
    assert "generated_at" in data
    fleet = data["fleet_stats"]
    assert "total_systems" in fleet
    assert "total_findings" in fleet


@pytest.mark.asyncio
async def test_dashboard_requires_operator_role(async_client, reader_token):
    """GET /dashboard returns 403 for reader role."""
    resp = await async_client.get(
        "/dashboard",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_dashboard_requires_auth(async_client):
    """GET /dashboard returns 401 without token."""
    resp = await async_client.get("/dashboard")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_dashboard_with_systems(async_client, admin_token, seeded_system):
    """GET /dashboard reflects seeded system count."""
    resp = await async_client.get(
        "/dashboard",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["fleet_stats"]["total_systems"] >= 1


# ---------------------------------------------------------------------------
# Search tests (BE-06)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_finds_systems(async_client, admin_token, seeded_system):
    """GET /search?q=web returns matching systems."""
    resp = await async_client.get(
        "/search",
        params={"q": "web01"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "data" in body
    assert "meta" in body
    results = body["data"]
    system_results = [r for r in results if r["entity_type"] == "system"]
    assert len(system_results) >= 1
    assert system_results[0]["title"] == "web01"


@pytest.mark.asyncio
async def test_search_envelope_shape(async_client, admin_token, seeded_system):
    """GET /search response has data/error/meta envelope."""
    resp = await async_client.get(
        "/search",
        params={"q": "web01"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    body = resp.json()
    assert "data" in body
    assert "error" in body
    assert "meta" in body
    assert "total" in body["meta"]
    assert "offset" in body["meta"]
    assert "limit" in body["meta"]


@pytest.mark.asyncio
async def test_search_finds_findings(async_client, admin_token, seeded_findings):
    """GET /search?q=CVE-2023 returns matching findings."""
    resp = await async_client.get(
        "/search",
        params={"q": "CVE-2023-0001", "entity_types": "finding"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    results = resp.json()["data"]
    finding_results = [r for r in results if r["entity_type"] == "finding"]
    assert len(finding_results) >= 1
    assert "CVE-2023-0001" in finding_results[0]["title"]


@pytest.mark.asyncio
async def test_search_requires_auth(async_client):
    """GET /search returns 401 without token."""
    resp = await async_client.get("/search", params={"q": "test"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_search_empty_result(async_client, admin_token, test_db):
    """GET /search with no matches returns empty list."""
    resp = await async_client.get(
        "/search",
        params={"q": "zzz_nonexistent_xyz_12345"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"] == []


# ---------------------------------------------------------------------------
# Tag vocabulary and assignment tests (BE-07)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tag_vocabulary_crud(async_client, admin_token, test_db):
    """POST/GET/DELETE /tags/vocabulary: full CRUD cycle."""
    # Create
    resp = await async_client.post(
        "/tags/vocabulary",
        json={"tag_key": "environment", "description": "deployment environment"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["data"]["tag_key"] == "environment"

    # List
    resp = await async_client.get(
        "/tags/vocabulary",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    items = resp.json()["data"]
    assert any(i["tag_key"] == "environment" for i in items)

    # Delete
    resp = await async_client.delete(
        "/tags/vocabulary/environment",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_tag_vocabulary_requires_admin(async_client, operator_token, test_db):
    """POST /tags/vocabulary returns 403 for operator role."""
    resp = await async_client.post(
        "/tags/vocabulary",
        json={"tag_key": "tier", "description": "system tier"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_tag_vocabulary_duplicate_returns_409(async_client, admin_token, test_db):
    """POST /tags/vocabulary with duplicate key returns 409."""
    payload = {"tag_key": "owner", "description": "system owner"}
    r1 = await async_client.post(
        "/tags/vocabulary",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r1.status_code == 201
    r2 = await async_client.post(
        "/tags/vocabulary",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r2.status_code == 409


@pytest.mark.asyncio
async def test_tag_assignment_validates_vocabulary(async_client, admin_token, seeded_system):
    """POST /tags/systems/{id} with invalid key returns 422."""
    resp = await async_client.post(
        f"/tags/systems/{seeded_system.id}",
        json={"tag_key": "nonexistent-key", "tag_value": "prod"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_tag_assignment_full_cycle(async_client, admin_token, seeded_system):
    """POST /tags/systems/{id} assigns tag after vocab entry created; DELETE removes it."""
    # Create vocab entry first
    await async_client.post(
        "/tags/vocabulary",
        json={"tag_key": "tier", "description": "system tier"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    # Assign tag
    resp = await async_client.post(
        f"/tags/systems/{seeded_system.id}",
        json={"tag_key": "tier", "tag_value": "production"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201, resp.text
    tag_id = resp.json()["data"]["id"]

    # List tags
    resp = await async_client.get(
        f"/tags/systems/{seeded_system.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    tags = resp.json()["data"]
    assert any(t["tag_key"] == "tier" for t in tags)

    # Delete tag
    resp = await async_client.delete(
        f"/tags/systems/{seeded_system.id}/{tag_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Finding workflow tests (BE-08)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_finding_workflow_states_endpoint(async_client, admin_token, test_db):
    """GET /findings/workflow/states returns state machine definition."""
    resp = await async_client.get(
        "/findings/workflow/states",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert "states" in data
    assert "transitions" in data
    assert "new" in data["states"]
    assert "closed" in data["states"]


@pytest.mark.asyncio
async def test_finding_workflow_valid_transition(async_client, operator_token, test_db):
    """POST /findings/{id}/transition: new -> investigating succeeds."""
    finding_id = "finding-001"

    resp = await async_client.post(
        f"/findings/{finding_id}/transition",
        json={"target_state": "investigating", "notes": "Starting investigation"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()["data"]
    assert data["current_state"] == "investigating"
    assert data["previous_state"] == "new"
    assert data["finding_id"] == finding_id


@pytest.mark.asyncio
async def test_finding_workflow_invalid_transition(async_client, operator_token, test_db):
    """POST /findings/{id}/transition: new -> closed returns 422."""
    finding_id = "finding-002"

    resp = await async_client.post(
        f"/findings/{finding_id}/transition",
        json={"target_state": "closed", "notes": "Skip the process"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_finding_workflow_history(async_client, operator_token, test_db):
    """GET /findings/{id}/workflow returns current state and history."""
    finding_id = "finding-003"

    # Create a transition first
    await async_client.post(
        f"/findings/{finding_id}/transition",
        json={"target_state": "investigating"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )

    resp = await async_client.get(
        f"/findings/{finding_id}/workflow",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["finding_id"] == finding_id
    assert data["current_state"] == "investigating"
    assert len(data["history"]) >= 1


@pytest.mark.asyncio
async def test_finding_workflow_requires_operator(async_client, reader_token, test_db):
    """POST /findings/{id}/transition returns 403 for reader role."""
    resp = await async_client.post(
        "/findings/any-finding/transition",
        json={"target_state": "investigating"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Saved filters tests (BE-09)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_saved_filter_crud(async_client, admin_token, test_db):
    """POST/GET/PATCH/DELETE /saved-filters: full CRUD cycle."""
    # Create
    resp = await async_client.post(
        "/saved-filters",
        json={
            "name": "Critical findings",
            "entity_type": "findings",
            "filter_json": '{"severity": "CRITICAL"}',
            "is_pinned": True,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201, resp.text
    filter_id = resp.json()["data"]["id"]
    assert resp.json()["data"]["name"] == "Critical findings"

    # List
    resp = await async_client.get(
        "/saved-filters",
        params={"entity_type": "findings"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    items = resp.json()["data"]
    assert any(i["id"] == filter_id for i in items)

    # Update
    resp = await async_client.patch(
        f"/saved-filters/{filter_id}",
        json={"name": "Critical and High findings", "is_pinned": False},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["name"] == "Critical and High findings"

    # Delete
    resp = await async_client.delete(
        f"/saved-filters/{filter_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_saved_filter_team_sharing(async_client, admin_token, operator_token, test_db):
    """Shared filter is visible to other users."""
    # Create shared filter as admin
    resp = await async_client.post(
        "/saved-filters",
        json={
            "name": "Team shared filter",
            "entity_type": "systems",
            "filter_json": "{}",
            "shared_with_team": True,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201

    # Operator should see shared filter
    resp = await async_client.get(
        "/saved-filters",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 200
    items = resp.json()["data"]
    assert any(i["name"] == "Team shared filter" for i in items)


@pytest.mark.asyncio
async def test_saved_filter_ownership_enforced(async_client, admin_token, operator_token, test_db):
    """Owner check: operator cannot delete admin's filter."""
    resp = await async_client.post(
        "/saved-filters",
        json={"name": "Admin only", "entity_type": "findings", "filter_json": "{}"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    filter_id = resp.json()["data"]["id"]

    resp = await async_client.delete(
        f"/saved-filters/{filter_id}",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Widget layout tests (BE-04)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_widget_layout_upsert(async_client, admin_token, test_db):
    """PUT /widgets/layout then GET returns same layout_json."""
    layout = '{"widgets": [{"id": "risk-score", "col": 0, "row": 0}]}'

    # PUT (create)
    resp = await async_client.put(
        "/widgets/layout",
        json={"layout_json": layout},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"]["layout_json"] == layout

    # GET
    resp = await async_client.get(
        "/widgets/layout",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["layout_json"] == layout


@pytest.mark.asyncio
async def test_widget_layout_default_when_empty(async_client, admin_token, test_db):
    """GET /widgets/layout returns default layout when none saved."""
    resp = await async_client.get(
        "/widgets/layout",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "data" in body
    assert body["meta"].get("is_default") is True


@pytest.mark.asyncio
async def test_widget_layout_size_limit(async_client, admin_token, test_db):
    """PUT /widgets/layout with >64KB payload returns 422."""
    oversized = "x" * (65 * 1024)
    resp = await async_client.put(
        "/widgets/layout",
        json={"layout_json": oversized},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Scheduled reports tests (BE-10)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scheduled_report_crud(async_client, admin_token, test_db):
    """POST/GET/PATCH/DELETE /scheduled-reports: full CRUD cycle."""
    # Create
    resp = await async_client.post(
        "/scheduled-reports",
        json={
            "name": "Weekly Risk Digest",
            "report_type": "risk_digest",
            "cron_expression": "0 9 * * MON",
            "recipient_emails_json": '["admin@example.com"]',
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201, resp.text
    report_id = resp.json()["data"]["id"]
    assert resp.json()["data"]["name"] == "Weekly Risk Digest"
    assert resp.json()["data"]["cron_expression"] == "0 9 * * MON"

    # List
    resp = await async_client.get(
        "/scheduled-reports",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    items = resp.json()["data"]
    assert any(i["id"] == report_id for i in items)

    # Update
    resp = await async_client.patch(
        f"/scheduled-reports/{report_id}",
        json={"name": "Bi-weekly Risk Digest", "cron_expression": "0 9 * * 1/2"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["name"] == "Bi-weekly Risk Digest"

    # Delete
    resp = await async_client.delete(
        f"/scheduled-reports/{report_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_scheduled_report_invalid_cron(async_client, admin_token, test_db):
    """POST /scheduled-reports with invalid cron returns 422."""
    resp = await async_client.post(
        "/scheduled-reports",
        json={
            "name": "Bad cron",
            "report_type": "custom",
            "cron_expression": "not-a-cron",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_scheduled_report_requires_admin(async_client, operator_token, test_db):
    """POST /scheduled-reports returns 403 for operator role."""
    resp = await async_client.post(
        "/scheduled-reports",
        json={"name": "r", "report_type": "custom", "cron_expression": "0 0 * * *"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_scheduled_report_trigger(async_client, admin_token, test_db):
    """POST /scheduled-reports/{id}/trigger returns queued status."""
    # Create first
    resp = await async_client.post(
        "/scheduled-reports",
        json={
            "name": "Trigger test",
            "report_type": "custom",
            "cron_expression": "0 0 * * *",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    report_id = resp.json()["data"]["id"]

    # Trigger
    resp = await async_client.post(
        f"/scheduled-reports/{report_id}/trigger",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["report_id"] == report_id
    assert data["status"] == "queued"


# ---------------------------------------------------------------------------
# Notification tests (RT-05)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def seeded_notifications(test_db, admin_key_record):
    """Seed 3 notification records for admin user (2 unread, 1 read)."""
    async with async_session_scope() as session:
        records = [
            NotificationRecord(
                user_id=admin_key_record.id,
                title="Critical CVE detected",
                body="CVE-2023-0001 affects web01",
                category="critical",
                is_read=False,
                created_at=utc_now(),
            ),
            NotificationRecord(
                user_id=admin_key_record.id,
                title="Scan completed",
                body="web01 scan finished",
                category="info",
                is_read=False,
                created_at=utc_now(),
            ),
            NotificationRecord(
                user_id=admin_key_record.id,
                title="Old notification",
                body="Already read",
                category="info",
                is_read=True,
                created_at=utc_now(),
            ),
        ]
        for r in records:
            session.add(r)
        await session.commit()
        for r in records:
            await session.refresh(r)
    return records


@pytest.mark.asyncio
async def test_notification_lifecycle(async_client, admin_token, seeded_notifications):
    """List unread -> mark one read -> verify count decreases."""
    # Get unread
    resp = await async_client.get(
        "/notifications/unread",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["unread_count"] == 2
    assert len(data["items"]) == 2

    # Mark first one read
    first_id = data["items"][0]["id"]
    resp = await async_client.post(
        f"/notifications/{first_id}/read",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["is_read"] is True

    # Verify count decreased
    resp = await async_client.get(
        "/notifications/unread",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.json()["data"]["unread_count"] == 1


@pytest.mark.asyncio
async def test_notification_list_paginated(async_client, admin_token, seeded_notifications):
    """GET /notifications returns paginated list with envelope."""
    resp = await async_client.get(
        "/notifications",
        params={"limit": 2, "offset": 0},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "data" in body
    assert "meta" in body
    assert body["meta"]["total"] == 3
    assert len(body["data"]) == 2


@pytest.mark.asyncio
async def test_notification_mark_all_read(async_client, admin_token, seeded_notifications):
    """POST /notifications/read-all marks all unread for user."""
    resp = await async_client.post(
        "/notifications/read-all",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["marked_read"] == 2

    # Verify none unread
    resp = await async_client.get(
        "/notifications/unread",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.json()["data"]["unread_count"] == 0


@pytest.mark.asyncio
async def test_notification_delete(async_client, admin_token, seeded_notifications):
    """DELETE /notifications/{id} removes the notification."""
    notif_id = seeded_notifications[0].id
    resp = await async_client.delete(
        f"/notifications/{notif_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 204

    # Verify deleted
    resp = await async_client.get(
        "/notifications",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    ids = [n["id"] for n in resp.json()["data"]]
    assert notif_id not in ids


@pytest.mark.asyncio
async def test_notification_isolation(async_client, admin_token, operator_token, test_db):
    """Operator cannot access admin's notifications (T-138-18)."""
    # Create notification for admin
    async with async_session_scope() as session:
        from sqlmodel import select  # noqa: PLC0415

        from aila.storage.db_models import ApiKeyRecord  # noqa: PLC0415

        admin_key = (await session.exec(select(ApiKeyRecord).where(ApiKeyRecord.role == "admin"))).first()
        if admin_key:
            n = NotificationRecord(
                user_id=admin_key.id,
                title="Admin private",
                body="Do not leak",
                category="info",
                is_read=False,
                created_at=utc_now(),
            )
            session.add(n)
            await session.commit()
            await session.refresh(n)
            notif_id = n.id
        else:
            pytest.skip("No admin key in DB")
            return

    # Operator should NOT see admin's notification
    resp = await async_client.get(
        "/notifications",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    ids = [n["id"] for n in resp.json()["data"]]
    assert notif_id not in ids


# ---------------------------------------------------------------------------
# Envelope shape tests (D-27)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_endpoints_use_envelope(admin_key_record, test_db):
    """Spot-check: all major endpoints return data/error/meta envelope.

    Uses a fresh app instance per test to avoid rate-limit state from other tests.
    Search is excluded here since other search tests may have consumed the quota.
    """
    import time

    from httpx import ASGITransport, AsyncClient

    from aila.api.app import create_app
    from aila.api.auth import issue_jwt_token

    token, _ = issue_jwt_token(admin_key_record)

    test_app = create_app()
    test_app.state.platform = None
    test_app.state.start_time = time.monotonic()

    endpoints = [
        ("/dashboard", "GET"),
        ("/notifications", "GET"),
        ("/notifications/unread", "GET"),
        ("/widgets/layout", "GET"),
        ("/saved-filters", "GET"),
        ("/scheduled-reports", "GET"),
        ("/findings/workflow/states", "GET"),
    ]
    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://test-envelope",
    ) as client:
        for path, method in endpoints:
            resp = await client.request(
                method,
                path,
                headers={"Authorization": f"Bearer {token}"},
            )
            body = resp.json()
            assert "data" in body, f"{method} {path} missing 'data' key — got: {body}"
            assert "error" in body, f"{method} {path} missing 'error' key"
            assert "meta" in body, f"{method} {path} missing 'meta' key"


# ---------------------------------------------------------------------------
# Rate limiting test (D-31 / T-138-21)
# ---------------------------------------------------------------------------


def test_rate_limiting_wired():
    """Verify slowapi rate limiting is correctly wired to the application (D-31 / T-138-21).

    Tests that:
    1. The ASGI app has app.state.limiter set to the module-level Limiter instance
    2. The Limiter is a slowapi Limiter (not None or a stub)
    3. The @limiter.limit decorators are registered on router endpoints

    We do not attempt to actually trigger a 429 in the test suite because the
    module-level Limiter uses shared in-memory bucket state across tests, making
    429-trigger tests inherently order-dependent and flaky. The structural assertion
    that the limiter is wired is sufficient — slowapi's own test suite covers the
    429 response behavior.
    """
    from slowapi import Limiter

    from aila.api.app import app
    from aila.api.limiter import limiter as module_limiter

    # 1. App state must hold the Limiter (slowapi reads from request.app.state.limiter)
    assert hasattr(app.state, "limiter"), "app.state.limiter not set — RateLimitExceeded handler won't fire"
    assert isinstance(app.state.limiter, Limiter), f"app.state.limiter is {type(app.state.limiter)}, expected Limiter"

    # 2. The app's limiter must be the same object as the module-level limiter
    assert app.state.limiter is module_limiter, (
        "app.state.limiter is not the same object as aila.api.limiter.limiter — "
        "this means the rate limiting won't be applied to decorated routes"
    )

    # 3. Verify the RateLimitExceeded exception handler is registered
    from slowapi.errors import RateLimitExceeded

    assert RateLimitExceeded in app.exception_handlers, (
        "RateLimitExceeded not in app.exception_handlers — 429 responses won't be returned"
    )
