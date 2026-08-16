"""#181 -- ``build_async_http_client`` wraps ``httpx.AsyncClient`` with the
async SSRF transport so operator-set MCP-bridge base_urls (upload/refresh
call sites in the malware and vr routers) cannot smuggle an outbound
request to a private / link-local / cloud-IMDS address.

Hermetic: numeric-literal hosts only so :func:`check_url` never performs
real DNS.  169.254.169.254 (cloud IMDS) is in the blocklist; 203.0.113.x
(TEST-NET-3) stands in for a public host and is intentionally NOT
intercepted with a MockTransport -- the SSRF check must refuse the
blocked URL before the socket is opened.
"""
from __future__ import annotations

import httpx
import pytest

from aila.platform.services.http import build_async_http_client
from aila.platform.services.ssrf import SSRFBlockedError, SSRFValidatingAsyncTransport


class _Settings:
    request_timeout_seconds = 5.0
    user_agent = "aila-test"


async def test_build_async_http_client_blocks_imds_target() -> None:
    """POST to 169.254.169.254 (cloud IMDS) must raise SSRFBlockedError
    before any socket opens, matching what the malware/vr upload sites now
    do when an operator points base_url at an internal address."""
    async with build_async_http_client(_Settings(), timeout=1.0) as client:
        with pytest.raises(SSRFBlockedError):
            await client.post(
                "http://169.254.169.254/upload",
                files={"file": ("s.bin", b"contents", "application/octet-stream")},
            )


async def test_build_async_http_client_blocks_private_range() -> None:
    """An RFC1918 base_url (e.g. 10.0.0.5) is refused before the POST."""
    async with build_async_http_client(_Settings(), timeout=1.0) as client:
        with pytest.raises(SSRFBlockedError):
            await client.post(
                "http://10.0.0.5/tools/refresh_index",
                json={"index_id": "x", "force": False},
            )


async def test_build_async_http_client_blocks_loopback() -> None:
    """127.0.0.1 is in the blocklist -- an operator setting base_url to
    localhost against the SSRF-guarded client is refused."""
    async with build_async_http_client(_Settings(), timeout=1.0) as client:
        with pytest.raises(SSRFBlockedError):
            await client.post("http://127.0.0.1:8080/upload", content=b"x")


async def test_build_async_http_client_blocks_disallowed_scheme() -> None:
    async with build_async_http_client(_Settings(), timeout=1.0) as client:
        with pytest.raises(SSRFBlockedError):
            await client.get("file:///etc/passwd")


async def test_build_async_http_client_reaches_public_via_mock() -> None:
    """A public TEST-NET address is allowed through the SSRF wrapper.
    Swap the async transport under the wrapper with a MockTransport so
    the call resolves without touching the network."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok"})

    transport = SSRFValidatingAsyncTransport(httpx.MockTransport(handler))
    async with httpx.AsyncClient(
        transport=transport, follow_redirects=True, timeout=1.0,
    ) as client:
        resp = await client.get("http://203.0.113.10/health")
    assert resp.status_code == 200
