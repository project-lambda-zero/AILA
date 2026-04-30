"""Tests for schedule due-checking and run_pending / schedule_status logic (SCHED-01, SCHED-02)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest


def _utc(*args) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


def _make_settings(tmp_path):
    from aila.config import Settings
    return Settings(database_url=f"sqlite:///{(tmp_path / 'sched.db').as_posix()}")


def _make_tool(settings):
    from aila.modules.vulnerability.tools.scheduled_scans import ScheduledScansTool
    return ScheduledScansTool(settings=settings)


# --- _is_due unit tests ---

def test_is_due_none_last_run_always_due():
    from aila.modules.vulnerability.tools.scheduled_scans import _is_due
    assert _is_due("0 2 * * *", None, _utc(2026, 4, 2, 3, 0)) is True


def test_is_due_daily_cron_24h_elapsed():
    from aila.modules.vulnerability.tools.scheduled_scans import _is_due
    last = _utc(2026, 4, 1, 3, 0)
    now = _utc(2026, 4, 2, 3, 0)
    assert _is_due("0 2 * * *", last, now) is True


def test_is_due_daily_cron_not_yet_elapsed():
    from aila.modules.vulnerability.tools.scheduled_scans import _is_due
    last = _utc(2026, 4, 2, 2, 0)   # just fired at 02:00
    now = _utc(2026, 4, 2, 2, 30)   # only 30 min later
    assert _is_due("0 2 * * *", last, now) is False


# --- run_pending tests ---

def test_run_pending_skips_disabled(tmp_path, monkeypatch):
    settings = _make_settings(tmp_path)
    tool = _make_tool(settings)
    tool.forward(action="create", target_name="db01", cron_expression="0 2 * * *")
    tool.forward(action="update", scan_id=1, enabled=False)

    from aila.modules.vulnerability.tools import scheduled_scans as mod
    monkeypatch.setattr(mod, "_is_due", lambda *_: True)

    from aila.modules.vulnerability.tools.scheduled_scans import run_pending
    result = run_pending(settings=settings)

    assert result["fired"] == 0
    assert result["skipped"] == 1
    assert result["results"][0]["status"] == "disabled"


def test_run_pending_skips_not_due(tmp_path, monkeypatch):
    settings = _make_settings(tmp_path)
    tool = _make_tool(settings)
    tool.forward(action="create", target_name="web01", cron_expression="0 2 * * *")

    from aila.modules.vulnerability.tools import scheduled_scans as mod
    monkeypatch.setattr(mod, "_is_due", lambda *_: False)

    from aila.modules.vulnerability.tools.scheduled_scans import run_pending
    result = run_pending(settings=settings)

    assert result["fired"] == 0
    assert result["skipped"] == 1
    assert result["results"][0]["status"] == "not_due"


def test_run_pending_fires_due_schedule_and_updates_last_run_at(tmp_path, monkeypatch):
    settings = _make_settings(tmp_path)
    tool = _make_tool(settings)
    tool.forward(action="create", target_name="web01", cron_expression="0 2 * * *")

    from aila.modules.vulnerability.tools import scheduled_scans as mod
    monkeypatch.setattr(mod, "_is_due", lambda *_: True)

    fired_targets = []

    class _FakePlatform:
        def handle(self, query, module_payload, module_options):
            fired_targets.append(module_payload["target_names"])
            return type("R", (), {"model_dump": lambda self, **kw: {}})()

    import aila.platform.runtime as runtime_mod
    monkeypatch.setattr(runtime_mod, "AILAPlatform", _FakePlatform)

    from aila.modules.vulnerability.tools.scheduled_scans import run_pending
    result = run_pending(settings=settings)

    assert result["fired"] == 1
    assert fired_targets == [["web01"]]
    assert result["results"][0]["status"] == "ok"

    # Confirm last_run_at written to DB
    from aila.modules.vulnerability.tools.scheduled_scans import schedule_status
    status = schedule_status(settings=settings)
    assert status["schedules"][0]["last_run_at"] is not None
    assert status["schedules"][0]["last_run_result"] == "ok"


def test_run_pending_records_error_result(tmp_path, monkeypatch):
    settings = _make_settings(tmp_path)
    tool = _make_tool(settings)
    tool.forward(action="create", target_name="fail01", cron_expression="* * * * *")

    from aila.modules.vulnerability.tools import scheduled_scans as mod
    monkeypatch.setattr(mod, "_is_due", lambda *_: True)

    class _BrokenPlatform:
        def handle(self, **kw):
            raise RuntimeError("ssh refused")

    import aila.platform.runtime as runtime_mod
    monkeypatch.setattr(runtime_mod, "AILAPlatform", _BrokenPlatform)

    from aila.modules.vulnerability.tools.scheduled_scans import run_pending
    result = run_pending(settings=settings)

    assert result["fired"] == 1
    assert "error:" in result["results"][0]["status"]


# --- schedule_status tests ---

def test_schedule_status_returns_next_fire_at(tmp_path):
    settings = _make_settings(tmp_path)
    tool = _make_tool(settings)
    tool.forward(action="create", target_name="web01", cron_expression="0 2 * * *")

    from aila.modules.vulnerability.tools.scheduled_scans import schedule_status
    result = schedule_status(settings=settings)

    assert result["count"] == 1
    s = result["schedules"][0]
    assert s["target_name"] == "web01"
    assert s["next_fire_at"] is not None
    assert s["last_run_at"] is None
    assert s["last_run_result"] is None


def test_schedule_status_empty_db(tmp_path):
    settings = _make_settings(tmp_path)
    _make_tool(settings)  # init_db only

    from aila.modules.vulnerability.tools.scheduled_scans import schedule_status
    result = schedule_status(settings=settings)
    assert result["count"] == 0
    assert result["schedules"] == []
