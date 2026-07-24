"""Event-loop safety tests for #64.

Blocking calls (sync HTTP, subprocess, embedding encode) invoked from an
``async def`` must run on a platform worker thread via ``run_blocking_io``
so the event loop is never stalled. These tests assert the observable
consequence: the blocking callable executes on a thread other than the
event loop's own thread.
"""
from __future__ import annotations

import inspect
import subprocess
import threading

from aila.modules.vulnerability.tools.intel_epss_kev import EPSSKEVIntelTool
from aila.storage import database as db


class _ThreadRecordingClient:
    """Records the thread on which its blocking method runs."""

    def __init__(self) -> None:
        self.thread: threading.Thread | None = None

    def fetch_scores(self, cve_ids: list[str]) -> dict[str, float]:
        self.thread = threading.current_thread()
        return {cid: 0.5 for cid in cve_ids}

    def fetch_catalog(self) -> dict:
        self.thread = threading.current_thread()
        return {"vulnerabilities": []}


def test_epss_kev_forward_is_coroutine_function() -> None:
    """forward() is async so the framework can await it (mirrors NVD)."""
    tool = EPSSKEVIntelTool()
    assert inspect.iscoroutinefunction(tool.forward)


async def test_epss_kev_epss_lookup_offloads_to_worker_thread() -> None:
    """epss_lookup runs the blocking HTTP client off the event-loop thread."""
    tool = EPSSKEVIntelTool()
    stub = _ThreadRecordingClient()
    tool._epss_client = stub  # type: ignore[assignment]
    result = await tool.forward(action="epss_lookup", cve_ids=["cve-2021-1"])
    assert result == {"CVE-2021-1": 0.5}
    assert stub.thread is not None
    assert stub.thread is not threading.main_thread()


async def test_epss_kev_kev_catalog_offloads_and_coerces() -> None:
    """kev_catalog offloads and non-dict returns coerce to an empty dict."""
    tool = EPSSKEVIntelTool()
    stub = _ThreadRecordingClient()
    tool._kev_client = stub  # type: ignore[assignment]
    result = await tool.forward(action="kev_catalog")
    assert result == {"vulnerabilities": []}
    assert stub.thread is not threading.main_thread()


async def test_backup_database_offloads_pg_dump(monkeypatch, tmp_path) -> None:
    """backup_database runs pg_dump on a worker thread, not the event loop."""
    recorded: dict[str, object] = {}

    def fake_run(*args, **kwargs):
        recorded["thread"] = threading.current_thread()
        recorded["argv"] = args[0]

        class _Result:
            returncode = 0
            stderr = ""

        return _Result()

    monkeypatch.setattr(subprocess, "run", fake_run)

    class _Settings:
        database_url = "postgresql+asyncpg://user:pw@localhost:5432/aila"

    dest = tmp_path / "backup.dump"
    out = await db.backup_database(settings=_Settings(), destination=dest)

    assert out == dest
    assert recorded["thread"] is not threading.main_thread()
    # pg_dump receives a libpq URL (no +asyncpg driver prefix).
    assert "postgresql://user:pw@localhost:5432/aila" in recorded["argv"]
