"""Tests for ScheduledScansTool (ENT-06 / plan 27-01, Task 2)."""
from __future__ import annotations

import pytest


async def test_create_returns_count_and_fields(test_db):
    from aila.modules.vulnerability.tools.scheduled_scans import ScheduledScansTool

    tool = ScheduledScansTool()
    result = await tool.forward(action="create", target_name="web01", cron_expression="0 2 * * *")
    assert result["count"] == 1
    scan = result["scans"][0]
    assert scan["target_name"] == "web01"
    assert scan["cron_expression"] == "0 2 * * *"
    assert scan["enabled"] is True
    assert scan["last_run_at"] is None
    assert scan["last_run_result"] is None


async def test_list_returns_all_created_scans(test_db):
    from aila.modules.vulnerability.tools.scheduled_scans import ScheduledScansTool

    tool = ScheduledScansTool()
    await tool.forward(action="create", target_name="web01", cron_expression="0 2 * * *")
    await tool.forward(action="create", target_name="db01", cron_expression="0 3 * * *")
    result = await tool.forward(action="list")
    assert result["count"] == 2
    names = {s["target_name"] for s in result["scans"]}
    assert names == {"web01", "db01"}


async def test_update_changes_cron_expression(test_db):
    from aila.modules.vulnerability.tools.scheduled_scans import ScheduledScansTool

    tool = ScheduledScansTool()
    created = await tool.forward(action="create", target_name="web01", cron_expression="0 2 * * *")
    scan_id = created["scans"][0]["id"]
    result = await tool.forward(action="update", scan_id=scan_id, cron_expression="0 4 * * *")
    assert result["count"] == 1
    assert result["scans"][0]["cron_expression"] == "0 4 * * *"


async def test_delete_removes_scan_by_id(test_db):
    from aila.modules.vulnerability.tools.scheduled_scans import ScheduledScansTool

    tool = ScheduledScansTool()
    created = await tool.forward(action="create", target_name="web01", cron_expression="0 2 * * *")
    scan_id = created["scans"][0]["id"]
    result = await tool.forward(action="delete", scan_id=scan_id)
    assert result["count"] == 1
    assert result["deleted_ids"] == [scan_id]
    listed = await tool.forward(action="list")
    assert listed["count"] == 0


async def test_unknown_action_raises(test_db):
    from aila.modules.vulnerability.tools.scheduled_scans import ScheduledScansTool

    tool = ScheduledScansTool()
    with pytest.raises(ValueError):
        await tool.forward(action="explode")
