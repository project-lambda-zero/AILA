"""Tests for ScheduledScansTool (ENT-06 / plan 27-01, Task 2)."""
from __future__ import annotations

import pytest


def _make_tool(tmp_path):
    from aila.config import Settings
    from aila.modules.vulnerability.tools.scheduled_scans import ScheduledScansTool

    settings = Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    return ScheduledScansTool(settings=settings)


def test_create_returns_count_and_fields(tmp_path):
    tool = _make_tool(tmp_path)
    result = tool.forward(action="create", target_name="web01", cron_expression="0 2 * * *")
    assert result["count"] == 1
    scan = result["scans"][0]
    assert scan["target_name"] == "web01"
    assert scan["cron_expression"] == "0 2 * * *"
    assert scan["enabled"] is True
    assert scan["last_run_at"] is None
    assert scan["last_run_result"] is None


def test_list_returns_all_created_scans(tmp_path):
    tool = _make_tool(tmp_path)
    tool.forward(action="create", target_name="web01", cron_expression="0 2 * * *")
    tool.forward(action="create", target_name="db01", cron_expression="0 3 * * *")
    result = tool.forward(action="list")
    assert result["count"] == 2
    names = {s["target_name"] for s in result["scans"]}
    assert names == {"web01", "db01"}


def test_update_changes_cron_expression(tmp_path):
    tool = _make_tool(tmp_path)
    created = tool.forward(action="create", target_name="web01", cron_expression="0 2 * * *")
    scan_id = created["scans"][0]["id"]
    result = tool.forward(action="update", scan_id=scan_id, cron_expression="0 4 * * *")
    assert result["count"] == 1
    assert result["scans"][0]["cron_expression"] == "0 4 * * *"


def test_delete_removes_scan_by_id(tmp_path):
    tool = _make_tool(tmp_path)
    created = tool.forward(action="create", target_name="web01", cron_expression="0 2 * * *")
    scan_id = created["scans"][0]["id"]
    result = tool.forward(action="delete", scan_id=scan_id)
    assert result["count"] == 1
    assert result["deleted_ids"] == [scan_id]
    listed = tool.forward(action="list")
    assert listed["count"] == 0


def test_unknown_action_raises(tmp_path):
    tool = _make_tool(tmp_path)
    with pytest.raises(ValueError):
        tool.forward(action="explode")
