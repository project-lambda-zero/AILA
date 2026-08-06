"""Tests for schedule due-checking and run_pending / schedule_status logic (SCHED-01, SCHED-02).

The ScheduledScansTool + run_pending + schedule_status surfaces are all async and
persist through the async ServiceFactory (which uses the platform's async engine).
Tests seed and drive the flow against the shared aila_test database via the
`test_db` fixture and drop the previous sqlite-based `_make_settings` helper --
that helper produced a Settings object that was never actually consulted by the
async storage service (ServiceFactory ignores the settings kwarg and uses
`async_session_scope()` / `get_settings()` for the URL). Passing sqlite settings
was silently a no-op; the tool always writes to the configured platform DB.
"""
from __future__ import annotations

from datetime import UTC, datetime


def _utc(*args) -> datetime:
    return datetime(*args, tzinfo=UTC)


def _make_tool():
    from aila.modules.vulnerability.tools.scheduled_scans import ScheduledScansTool
    return ScheduledScansTool()


# --- _is_due unit tests (pure function, no DB needed) ---

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

async def test_run_pending_skips_disabled(test_db, monkeypatch):
    tool = _make_tool()
    created = await tool.forward(action="create", target_name="db01", cron_expression="0 2 * * *")
    scan_id = created["scans"][0]["id"]
    await tool.forward(action="update", scan_id=scan_id, enabled=False)

    from aila.modules.vulnerability.tools import scheduled_scans as mod
    monkeypatch.setattr(mod, "_is_due", lambda *_: True)

    from aila.modules.vulnerability.tools.scheduled_scans import run_pending
    result = await run_pending()

    assert result["fired"] == 0
    assert result["skipped"] == 1
    assert result["results"][0]["status"] == "disabled"


async def test_run_pending_skips_not_due(test_db, monkeypatch):
    tool = _make_tool()
    await tool.forward(action="create", target_name="web01", cron_expression="0 2 * * *")

    from aila.modules.vulnerability.tools import scheduled_scans as mod
    monkeypatch.setattr(mod, "_is_due", lambda *_: False)

    from aila.modules.vulnerability.tools.scheduled_scans import run_pending
    result = await run_pending()

    assert result["fired"] == 0
    assert result["skipped"] == 1
    assert result["results"][0]["status"] == "not_due"


async def test_run_pending_fires_due_schedule_and_updates_last_run_at(test_db, monkeypatch):
    tool = _make_tool()
    await tool.forward(action="create", target_name="web01", cron_expression="0 2 * * *")

    from aila.modules.vulnerability.tools import scheduled_scans as mod
    monkeypatch.setattr(mod, "_is_due", lambda *_: True)

    fired_targets: list[list[str]] = []

    class _FakePlatform:
        def handle(self, query, module_payload, module_options):
            fired_targets.append(module_payload["target_names"])
            return type("R", (), {"model_dump": lambda self, **kw: {}})()

    import aila.platform.runtime as runtime_mod
    monkeypatch.setattr(runtime_mod, "AILAPlatform", _FakePlatform)

    from aila.modules.vulnerability.tools.scheduled_scans import run_pending
    result = await run_pending()

    assert result["fired"] == 1
    assert fired_targets == [["web01"]]
    assert result["results"][0]["status"] == "ok"

    # Confirm last_run_at written to DB
    from aila.modules.vulnerability.tools.scheduled_scans import schedule_status
    status = await schedule_status()
    assert status["schedules"][0]["last_run_at"] is not None
    assert status["schedules"][0]["last_run_result"] == "ok"


async def test_run_pending_records_error_result(test_db, monkeypatch):
    tool = _make_tool()
    await tool.forward(action="create", target_name="fail01", cron_expression="* * * * *")

    from aila.modules.vulnerability.tools import scheduled_scans as mod
    monkeypatch.setattr(mod, "_is_due", lambda *_: True)

    from aila.platform.exceptions import AILAError

    class _BrokenPlatform:
        def handle(self, **kw):
            # run_pending only catches AILAError. RuntimeError would bubble out; use
            # AILAError to exercise the intended error-capture branch.
            raise AILAError("ssh refused")

    import aila.platform.runtime as runtime_mod
    monkeypatch.setattr(runtime_mod, "AILAPlatform", _BrokenPlatform)

    from aila.modules.vulnerability.tools.scheduled_scans import run_pending
    result = await run_pending()

    assert result["fired"] == 1
    assert "error:" in result["results"][0]["status"]


# --- schedule_status tests ---

async def test_schedule_status_returns_next_fire_at(test_db):
    tool = _make_tool()
    await tool.forward(action="create", target_name="web01", cron_expression="0 2 * * *")

    from aila.modules.vulnerability.tools.scheduled_scans import schedule_status
    result = await schedule_status()

    assert result["count"] == 1
    s = result["schedules"][0]
    assert s["target_name"] == "web01"
    assert s["next_fire_at"] is not None
    assert s["last_run_at"] is None
    assert s["last_run_result"] is None


async def test_schedule_status_empty_db(test_db):
    from aila.modules.vulnerability.tools.scheduled_scans import schedule_status
    result = await schedule_status()
    assert result["count"] == 0
    assert result["schedules"] == []
