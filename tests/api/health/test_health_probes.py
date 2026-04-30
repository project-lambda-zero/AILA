"""Unit tests for the health probe primitives (Phase 176d).

Covers:
- HTTP probe success, rate_limited, unreachable, timed_out
- SSH TCP-connect probe against a local listening socket
- Discovery metadata parsers (pure functions)
"""
from __future__ import annotations

import asyncio
import socket
import threading

import pytest

from aila.api.schemas.comprehensive_health import (
    SshReachabilityResult,
    SubsystemHealth,
)
from aila.platform.services.health_probes import (
    _probe_single_ssh,
    probe_arch_security,
    probe_nvd,
    probe_omniroute,
)
from aila.platform.tasks.discovery import (
    parse_df_root_disk_gb,
    parse_free_memory_mb,
    parse_ip_route_default,
    parse_nproc,
    parse_os_release,
    parse_uptime_seconds,
)

# Only async tests need the mark; pure-sync parser tests omit it.


# ---------------------------------------------------------------------------
# HTTP probes -- patch httpx.AsyncClient with a minimal async stub
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict:
        if self._payload is None:
            raise ValueError("no json payload")
        return self._payload


class _StubAsyncClient:
    def __init__(self, response: _StubResponse | Exception) -> None:
        self._response = response

    async def __aenter__(self) -> "_StubAsyncClient":
        return self

    async def __aexit__(self, *args) -> None:
        return None

    async def head(self, url: str) -> _StubResponse:
        if isinstance(self._response, Exception):
            raise self._response
        return self._response

    async def get(self, url: str) -> _StubResponse:
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


@pytest.mark.asyncio
async def test_probe_arch_security_healthy_on_200(monkeypatch):
    import aila.platform.services.health_probes as hp

    def _factory(*args, **kwargs):
        return _StubAsyncClient(_StubResponse(200))

    monkeypatch.setattr(hp.httpx, "AsyncClient", _factory)
    result = await probe_arch_security()
    assert isinstance(result, SubsystemHealth)
    assert result.status == "healthy"


@pytest.mark.asyncio
async def test_probe_arch_security_rate_limited_on_429(monkeypatch):
    import aila.platform.services.health_probes as hp

    def _factory(*args, **kwargs):
        return _StubAsyncClient(_StubResponse(429))

    monkeypatch.setattr(hp.httpx, "AsyncClient", _factory)
    result = await probe_arch_security()
    assert result.status == "rate_limited"


@pytest.mark.asyncio
async def test_probe_arch_security_timeout(monkeypatch):
    import aila.platform.services.health_probes as hp

    def _factory(*args, **kwargs):
        return _StubAsyncClient(hp.httpx.TimeoutException("slow"))

    monkeypatch.setattr(hp.httpx, "AsyncClient", _factory)
    result = await probe_arch_security()
    assert result.status == "timed_out"


@pytest.mark.asyncio
async def test_probe_nvd_healthy_on_200(monkeypatch):
    import aila.platform.services.health_probes as hp

    def _factory(*args, **kwargs):
        return _StubAsyncClient(_StubResponse(200, payload={"totalResults": 1}))

    monkeypatch.setattr(hp.httpx, "AsyncClient", _factory)
    result = await probe_nvd()
    assert result.status == "healthy"


@pytest.mark.asyncio
async def test_probe_nvd_unreachable(monkeypatch):
    import aila.platform.services.health_probes as hp

    def _factory(*args, **kwargs):
        return _StubAsyncClient(hp.httpx.ConnectError("dns failure"))

    monkeypatch.setattr(hp.httpx, "AsyncClient", _factory)
    result = await probe_nvd()
    assert result.status == "unreachable"


@pytest.mark.asyncio
async def test_probe_omniroute_degraded_when_empty_models(monkeypatch):
    import aila.platform.services.health_probes as hp

    def _factory(*args, **kwargs):
        return _StubAsyncClient(_StubResponse(200, payload={"data": []}))

    monkeypatch.setattr(hp.httpx, "AsyncClient", _factory)
    result = await probe_omniroute()
    assert result.status == "degraded"


@pytest.mark.asyncio
async def test_probe_omniroute_healthy_with_models(monkeypatch):
    import aila.platform.services.health_probes as hp

    def _factory(*args, **kwargs):
        return _StubAsyncClient(_StubResponse(200, payload={"data": [{"id": "x"}]}))

    monkeypatch.setattr(hp.httpx, "AsyncClient", _factory)
    result = await probe_omniroute()
    assert result.status == "healthy"
    assert (result.details or {}).get("model_count") == 1


# ---------------------------------------------------------------------------
# SSH TCP-connect probe against an ephemeral listening socket
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_probe_single_ssh_reachable_local_listener():
    """Spin up a local listener and verify the probe reports reachable."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    def _accept_loop():
        try:
            conn, _ = sock.accept()
            conn.close()
        except OSError:
            pass

    thread = threading.Thread(target=_accept_loop, daemon=True)
    thread.start()
    try:
        result = await _probe_single_ssh(
            {"id": 1, "name": "local", "host": "127.0.0.1", "port": port}
        )
    finally:
        sock.close()

    assert isinstance(result, SshReachabilityResult)
    assert result.status == "reachable"
    assert result.port == port


@pytest.mark.asyncio
async def test_probe_single_ssh_unreachable_port():
    """Connecting to an almost-certainly-closed port returns unreachable or timed_out."""
    result = await _probe_single_ssh(
        {"id": 1, "name": "nobody", "host": "127.0.0.1", "port": 1}
    )
    assert isinstance(result, SshReachabilityResult)
    assert result.status in ("unreachable", "timed_out", "error")


# ---------------------------------------------------------------------------
# Metadata parsers
# ---------------------------------------------------------------------------


def test_parse_ip_route_default_extracts_gateway_and_interface():
    output = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600"
    gw, iface = parse_ip_route_default(output)
    assert gw == "192.168.1.1"
    assert iface == "wlan0"


def test_parse_ip_route_default_returns_none_when_missing():
    gw, iface = parse_ip_route_default("")
    assert gw is None
    assert iface is None


def test_parse_os_release_extracts_id_and_pretty():
    output = 'NAME="Arch Linux"\nID=arch\nPRETTY_NAME="Arch Linux"\n'
    os_id, pretty = parse_os_release(output)
    assert os_id == "arch"
    assert pretty == "Arch Linux"


def test_parse_nproc():
    assert parse_nproc("8\n") == 8
    assert parse_nproc("") is None
    assert parse_nproc("abc") is None


def test_parse_free_memory_mb():
    output = (
        "              total        used        free      shared  buff/cache   available\n"
        "Mem:          15947        5012        1231         678       9704        9812\n"
        "Swap:             0           0           0\n"
    )
    assert parse_free_memory_mb(output) == 15947


def test_parse_df_root_disk_gb():
    output = (
        "Filesystem     1G-blocks  Used Available Use% Mounted on\n"
        "/dev/sda1           500G  123G      377G  25% /\n"
    )
    assert parse_df_root_disk_gb(output) == 500


def test_parse_uptime_seconds():
    assert parse_uptime_seconds("12345.67 6543.21\n") == 12345
    assert parse_uptime_seconds("") is None
    assert parse_uptime_seconds("notanumber") is None
