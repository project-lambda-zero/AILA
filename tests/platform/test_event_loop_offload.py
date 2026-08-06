"""Event-loop safety tests for #64.

Blocking calls (sync subprocess, embedding encode) invoked from an
``async def`` must run on a platform worker thread via ``run_blocking_io``
so the event loop is never stalled.  For providers whose backend tolerates
asyncio-native I/O (NVD/EPSS/KEV, #64/#55 backend gap) the required
consequence is stronger: the client method itself is a coroutine that
drives ``httpx.AsyncClient`` -- no worker-thread bridge is needed, and no
``time.sleep`` may remain in the retry / rate-limit path.
"""
from __future__ import annotations

import inspect
import subprocess
import threading

from aila.modules.vulnerability.tools.intel_epss_kev import EPSSKEVIntelTool
from aila.storage import database as db


class _AsyncRecordingClient:
    """Records the thread on which its async method runs."""

    def __init__(self) -> None:
        self.thread: threading.Thread | None = None

    async def fetch_scores(self, cve_ids: list[str]) -> dict[str, dict]:
        self.thread = threading.current_thread()
        return {cid: {"epss": 0.5, "percentile": 0.9} for cid in cve_ids}

    async def fetch_catalog(self) -> dict:
        self.thread = threading.current_thread()
        return {"vulnerabilities": []}


def test_epss_kev_forward_is_coroutine_function() -> None:
    """forward() is async so the framework can await it (mirrors NVD)."""
    tool = EPSSKEVIntelTool()
    assert inspect.iscoroutinefunction(tool.forward)


def test_epss_client_methods_are_async() -> None:
    """EPSS provider drives httpx.AsyncClient natively; no thread bridge."""
    from aila.modules.vulnerability.providers.epss import EPSSClient

    assert inspect.iscoroutinefunction(EPSSClient.fetch_scores)


def test_kev_client_methods_are_async() -> None:
    """KEV provider drives httpx.AsyncClient natively; no thread bridge."""
    from aila.modules.vulnerability.providers.kev import KEVClient

    assert inspect.iscoroutinefunction(KEVClient.fetch_catalog)


def test_nvd_client_methods_are_async() -> None:
    """NVD provider drives httpx.AsyncClient natively; retries use asyncio.sleep."""
    from aila.modules.vulnerability.providers.nvd import NVDClient

    assert inspect.iscoroutinefunction(NVDClient.fetch_cve)
    assert inspect.iscoroutinefunction(NVDClient._wait_for_request_slot)


def test_nvd_provider_has_no_blocking_sleep() -> None:
    """NVD provider source contains no ``time.sleep`` on the request path."""
    from aila.modules.vulnerability.providers import nvd as nvd_mod

    src = inspect.getsource(nvd_mod)
    assert "time.sleep" not in src, (
        "NVD provider must not call time.sleep in an async code path (#64)."
    )


def test_epss_provider_has_no_blocking_sleep() -> None:
    """EPSS provider source contains no ``time.sleep``."""
    from aila.modules.vulnerability.providers import epss as epss_mod

    assert "time.sleep" not in inspect.getsource(epss_mod)


def test_kev_provider_has_no_blocking_sleep() -> None:
    """KEV provider source contains no ``time.sleep``."""
    from aila.modules.vulnerability.providers import kev as kev_mod

    assert "time.sleep" not in inspect.getsource(kev_mod)


async def test_epss_kev_epss_lookup_awaits_async_provider() -> None:
    """epss_lookup awaits the AsyncClient-backed provider on the event loop thread."""
    tool = EPSSKEVIntelTool()
    stub = _AsyncRecordingClient()
    tool._epss_client = stub  # type: ignore[assignment]
    result = await tool.forward(action="epss_lookup", cve_ids=["cve-2021-1"])
    assert result == {"CVE-2021-1": {"epss": 0.5, "percentile": 0.9}}
    # The AsyncClient drives non-blocking I/O directly on the loop thread;
    # no worker-thread bridge is required.
    assert stub.thread is threading.main_thread()


async def test_epss_kev_kev_catalog_awaits_and_coerces() -> None:
    """kev_catalog awaits the async provider and coerces non-dict returns."""
    tool = EPSSKEVIntelTool()
    stub = _AsyncRecordingClient()
    tool._kev_client = stub  # type: ignore[assignment]
    result = await tool.forward(action="kev_catalog")
    assert result == {"vulnerabilities": []}
    assert stub.thread is threading.main_thread()


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
