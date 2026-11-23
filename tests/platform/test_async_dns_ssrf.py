"""Async SSRF validation resolves hostnames off the event loop and keeps the shared policy."""

from __future__ import annotations

import socket

import pytest

from aila.platform.services import ssrf
from aila.platform.services.ssrf import SSRFBlockedError, check_url_async


def _forbid_sync_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def _getaddrinfo(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("async SSRF path must not call socket.getaddrinfo")

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", _getaddrinfo)


async def test_async_check_awaits_resolver_and_allows_public_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_sync_dns(monkeypatch)
    calls: list[str] = []

    async def _resolve(hostname: str) -> list[str]:
        calls.append(hostname)
        return ["93.184.216.34"]

    monkeypatch.setattr(ssrf, "resolve_system_addresses", _resolve)

    await check_url_async("https://public.example.test/path")

    assert calls == ["public.example.test"]


async def test_async_check_blocks_private_resolved_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_sync_dns(monkeypatch)

    async def _resolve(_hostname: str) -> list[str]:
        return ["10.0.0.5"]

    monkeypatch.setattr(ssrf, "resolve_system_addresses", _resolve)

    with pytest.raises(SSRFBlockedError):
        await check_url_async("https://internal.example.test/")


async def test_async_check_maps_dns_failure_to_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_sync_dns(monkeypatch)

    async def _resolve(_hostname: str) -> list[str]:
        raise socket.gaierror("name not known")

    monkeypatch.setattr(ssrf, "resolve_system_addresses", _resolve)

    with pytest.raises(SSRFBlockedError, match="DNS lookup failed"):
        await check_url_async("https://missing.example.test/")


async def test_async_check_literal_ip_skips_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_sync_dns(monkeypatch)

    async def _resolve(_hostname: str) -> list[str]:
        raise AssertionError("literal IPs must not be resolved")

    monkeypatch.setattr(ssrf, "resolve_system_addresses", _resolve)

    with pytest.raises(SSRFBlockedError):
        await check_url_async("http://10.0.0.5/")
