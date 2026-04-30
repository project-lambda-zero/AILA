"""Comprehensive audit router tests -- FILE-02 deep review.

Covers: comma-OR filter logic on all 4 filterable fields,
pagination edge cases (first/last/beyond-last page),
filter bypass prevention, and run-specific endpoint.

Created by Phase 65 Plan 01 for exhaustive audit router coverage.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlmodel import SQLModel

from aila.storage.db_models import AuditEventRecord


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ─── Local fixture: 5 audit events with diverse field values ──────────────────


@pytest.fixture(scope="function")
def many_audit_events(test_db, seeded_run):
    """Seed 5 AuditEventRecord rows with diverse stage/action/status/user_id.

    Records:
      1. stage=ssh,    action=connect,   status=completed, user_id=system
      2. stage=scan,   action=inventory, status=completed, user_id=system
      3. stage=report, action=persist,   status=completed, user_id=admin-1
      4. stage=ssh,    action=execute,   status=failed,    user_id=system
      5. stage=analysis, action=create,  status=completed, user_id=admin-1
    """
    from aila.storage.database import session_scope

    records = [
        AuditEventRecord(
            run_id=seeded_run.id,
            stage="ssh",
            action="connect",
            status="completed",
            target="web01",
            user_id="system",
            details_json='{"host": "web01"}',
            created_at=_utc_now(),
        ),
        AuditEventRecord(
            run_id=seeded_run.id,
            stage="scan",
            action="inventory",
            status="completed",
            target="web01",
            user_id="system",
            details_json='{"packages": 42}',
            created_at=_utc_now(),
        ),
        AuditEventRecord(
            run_id=seeded_run.id,
            stage="report",
            action="persist",
            status="completed",
            target="fleet",
            user_id="admin-1",
            details_json="{}",
            created_at=_utc_now(),
        ),
        AuditEventRecord(
            run_id=seeded_run.id,
            stage="ssh",
            action="execute",
            status="failed",
            target="web01",
            user_id="system",
            details_json='{"cmd": "ls -al"}',
            created_at=_utc_now(),
        ),
        AuditEventRecord(
            run_id=seeded_run.id,
            stage="analysis",
            action="create",
            status="completed",
            target="web01",
            user_id="admin-1",
            details_json='{"type": "vuln"}',
            created_at=_utc_now(),
        ),
    ]
    with session_scope() as session:
        for r in records:
            session.add(r)
        session.commit()
    return records


# ─── Comma-OR filter correctness ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_filter_stage_single_value(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """stage=ssh returns only ssh-stage events (2 of 5)."""
    resp = await async_client.get(
        "/audit/events",
        params={"stage": "ssh"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert all(item["stage"] == "ssh" for item in data["items"])


@pytest.mark.asyncio
async def test_filter_stage_comma_or(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """stage=ssh,scan returns events from both stages (comma-OR)."""
    resp = await async_client.get(
        "/audit/events",
        params={"stage": "ssh,scan"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3  # 2 ssh + 1 scan
    returned_stages = {item["stage"] for item in data["items"]}
    assert returned_stages == {"ssh", "scan"}


@pytest.mark.asyncio
async def test_filter_action_single_value(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """action=connect returns 1 event (single value on action field)."""
    resp = await async_client.get(
        "/audit/events",
        params={"action": "connect"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["action"] == "connect"


@pytest.mark.asyncio
async def test_filter_action_comma_or(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """action=connect,persist returns 2 events (comma-OR on action)."""
    resp = await async_client.get(
        "/audit/events",
        params={"action": "connect,persist"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    returned_actions = {item["action"] for item in data["items"]}
    assert returned_actions == {"connect", "persist"}


@pytest.mark.asyncio
async def test_filter_status_single_value(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """status=completed returns 4 events (all seeded except the failed one)."""
    resp = await async_client.get(
        "/audit/events",
        params={"status": "completed"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 4
    assert all(item["status"] == "completed" for item in data["items"])


@pytest.mark.asyncio
async def test_filter_status_comma_or(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """status=completed,failed returns all 5 events (comma-OR on status)."""
    resp = await async_client.get(
        "/audit/events",
        params={"status": "completed,failed"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5


@pytest.mark.asyncio
async def test_filter_user_id_single_value(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """user_id=system returns 3 events (only system-owned)."""
    resp = await async_client.get(
        "/audit/events",
        params={"user_id": "system"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3
    assert all(item["user_id"] == "system" for item in data["items"])


@pytest.mark.asyncio
async def test_filter_user_id_no_match(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """user_id=nonexistent returns 0 events (no match)."""
    resp = await async_client.get(
        "/audit/events",
        params={"user_id": "nonexistent"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_filter_cross_field_and(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """stage=ssh AND action=connect (cross-field AND) returns 1 event."""
    resp = await async_client.get(
        "/audit/events",
        params={"stage": "ssh", "action": "connect"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["stage"] == "ssh"
    assert data["items"][0]["action"] == "connect"


# ─── Pagination edge cases ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pagination_first_page(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """page=1, page_size=2 returns 2 items, total=5, pages=3."""
    resp = await async_client.get(
        "/audit/events",
        params={"page": 1, "page_size": 2},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5
    assert len(data["items"]) == 2
    assert data["pages"] == 3
    assert data["page"] == 1
    assert data["page_size"] == 2


@pytest.mark.asyncio
async def test_pagination_last_page_partial(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """page=3, page_size=2 returns 1 item (last page partial), total=5, pages=3."""
    resp = await async_client.get(
        "/audit/events",
        params={"page": 3, "page_size": 2},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5
    assert len(data["items"]) == 1
    assert data["pages"] == 3


@pytest.mark.asyncio
async def test_pagination_beyond_last_page(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """page=4, page_size=2 returns 0 items (beyond last), total=5, pages=3."""
    resp = await async_client.get(
        "/audit/events",
        params={"page": 4, "page_size": 2},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5
    assert len(data["items"]) == 0
    assert data["pages"] == 3


@pytest.mark.asyncio
async def test_pagination_large_page_size(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """page=1, page_size=250 returns all 5 items (page_size larger than dataset)."""
    resp = await async_client.get(
        "/audit/events",
        params={"page": 1, "page_size": 250},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5
    assert len(data["items"]) == 5
    assert data["pages"] == 1


@pytest.mark.asyncio
async def test_pagination_page_size_zero_rejected(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """page_size=0 returns 422 (ge=1 validation)."""
    resp = await async_client.get(
        "/audit/events",
        params={"page_size": 0},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_pagination_page_size_exceeds_max_rejected(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """page_size=251 returns 422 (le=250 validation)."""
    resp = await async_client.get(
        "/audit/events",
        params={"page_size": 251},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


# ─── Filter bypass prevention ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_filter_whitespace_only_returns_all(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """Whitespace-only stage=' ' returns all records (treated as no filter).

    _parse_comma_list(' ') -> [' '.strip()] -> [''] with if v.strip() -> []
    Empty list is falsy, so no filter applied.
    """
    resp = await async_client.get(
        "/audit/events",
        params={"stage": " "},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5  # all records returned


@pytest.mark.asyncio
async def test_filter_empty_commas_returns_all(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """Empty commas stage=',,' returns all records (treated as no filter).

    _parse_comma_list(',,') -> splits into ['', '', ''] -> filtered by v.strip() -> []
    Empty list is falsy, so no filter applied.
    """
    resp = await async_client.get(
        "/audit/events",
        params={"stage": ",,"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5  # all records returned


@pytest.mark.asyncio
async def test_filter_sql_injection_safe(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """SQL injection payload in stage returns 200 with 0 results, not 500.

    Parameterized .in_() prevents SQL injection execution.
    """
    resp = await async_client.get(
        "/audit/events",
        params={"stage": "'; DROP TABLE auditeventrecord;--"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_no_auth_returns_401(
    async_client: AsyncClient, many_audit_events
) -> None:
    """No auth header returns 401."""
    resp = await async_client.get("/audit/events")
    assert resp.status_code == 401


# ─── Run-specific endpoint ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_events_returns_all_for_run(
    async_client: AsyncClient, admin_token: str, many_audit_events, seeded_run
) -> None:
    """GET /audit/events/{run_id} returns all events for that run in ascending order."""
    resp = await async_client.get(
        f"/audit/events/{seeded_run.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5
    assert len(data["items"]) == 5
    # All events belong to the seeded run
    for item in data["items"]:
        assert item["run_id"] == seeded_run.id
    # Verify ascending order by checking created_at is non-decreasing
    timestamps = [item["created_at"] for item in data["items"]]
    assert timestamps == sorted(timestamps)


@pytest.mark.asyncio
async def test_run_events_nonexistent_run_returns_empty(
    async_client: AsyncClient, admin_token: str, many_audit_events
) -> None:
    """GET /audit/events/{nonexistent_run_id} returns empty list (not 404)."""
    resp = await async_client.get(
        "/audit/events/run-does-not-exist-999",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []
