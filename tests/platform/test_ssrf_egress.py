"""#42 -- build_http_client / health-probe egress re-validates every redirect
hop against the SSRF policy, not just the initial URL.

Hermetic: MockTransport intercepts sockets, and every host used is a numeric
literal so check_url never performs real DNS. 169.254.169.254 (cloud IMDS)
and 10.0.0.5 (RFC1918) are blocked; 203.0.113.x / 198.51.100.x (TEST-NET,
not in the blocklist) stand in for public hosts.
"""
from __future__ import annotations

import httpx
import pytest

from aila.platform.services.http import build_http_client
from aila.platform.services.ssrf import (
    SSRFBlockedError,
    SSRFValidatingAsyncTransport,
    SSRFValidatingTransport,
)


class _Settings:
    request_timeout_seconds = 5.0
    user_agent = "aila-test"


def _sync_client(handler) -> httpx.Client:
    return httpx.Client(
        transport=SSRFValidatingTransport(httpx.MockTransport(handler)),
        follow_redirects=True,
    )


def test_redirect_into_imds_is_blocked() -> None:
    """A 302 from a public host into cloud IMDS must raise before the IMDS
    socket opens -- the IMDS handler branch must never be reached."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "203.0.113.10":
            return httpx.Response(
                302, headers={"location": "http://169.254.169.254/latest/meta-data/"},
            )
        return httpx.Response(200, text="LEAKED-IMDS-BODY")

    with _sync_client(handler) as client, pytest.raises(SSRFBlockedError):
        client.get("http://203.0.113.10/start")


def test_redirect_to_public_host_is_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "http://198.51.100.7/final"})
        return httpx.Response(200, text="ok")

    with _sync_client(handler) as client:
        resp = client.get("http://203.0.113.10/start")
    assert resp.status_code == 200
    assert resp.text == "ok"


def test_initial_private_url_is_blocked() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="LEAKED")

    with _sync_client(handler) as client, pytest.raises(SSRFBlockedError):
        client.get("http://10.0.0.5/internal")


def test_disallowed_scheme_redirect_is_blocked() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "file:///etc/passwd"})
        return httpx.Response(200, text="ok")

    with _sync_client(handler) as client, pytest.raises(SSRFBlockedError):
        client.get("http://203.0.113.10/start")


def test_build_http_client_enforces_policy_end_to_end() -> None:
    """The client build_http_client returns blocks a private target before any
    socket opens (no real network needed)."""
    with build_http_client(_Settings()) as client, pytest.raises(SSRFBlockedError):
        client.get("http://169.254.169.254/latest/meta-data/")


async def test_async_transport_blocks_private_redirect() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "203.0.113.10":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/x"})
        return httpx.Response(200, text="LEAKED-IMDS-BODY")

    transport = SSRFValidatingAsyncTransport(httpx.MockTransport(handler))
    async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
        with pytest.raises(SSRFBlockedError):
            await client.get("http://203.0.113.10/start")
