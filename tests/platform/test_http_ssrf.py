"""#42 SSRF hardening for the agent-facing http_fetch tool.

The tool now enforces a scheme + port allow-list and a blocked-network list on
the initial URL AND on every redirect hop (redirects are followed manually so a
``301 Location: http://169.254.169.254/...`` to cloud IMDS, or a redirect to a
non-web scheme/port, is refused before its socket opens).
"""
from __future__ import annotations

import types

import httpx
import pytest

from aila.platform.tools.http import (
    HTTPFetchTool,
    SSRFBlockedError,
    _check_url,
)


def _settings() -> object:
    return types.SimpleNamespace(request_timeout_seconds=5.0, user_agent="test-agent")


# --- _check_url unit tests ------------------------------------------------

def test_check_url_allows_public_ip() -> None:
    _check_url("http://1.1.1.1/")  # must not raise


def test_check_url_blocks_imds() -> None:
    with pytest.raises(SSRFBlockedError):
        _check_url("http://169.254.169.254/latest/meta-data/")


def test_check_url_blocks_private_ip() -> None:
    with pytest.raises(SSRFBlockedError):
        _check_url("http://10.0.0.5/")


def test_check_url_blocks_loopback() -> None:
    with pytest.raises(SSRFBlockedError):
        _check_url("http://127.0.0.1/")


def test_check_url_blocks_ipv4_mapped_loopback() -> None:
    with pytest.raises(SSRFBlockedError):
        _check_url("http://[::ffff:127.0.0.1]/")


def test_check_url_blocks_disallowed_scheme() -> None:
    with pytest.raises(SSRFBlockedError):
        _check_url("file:///etc/passwd")


def test_check_url_blocks_disallowed_port() -> None:
    with pytest.raises(SSRFBlockedError):
        _check_url("http://1.1.1.1:22/")


# --- redirect-loop integration tests (MockTransport, no network) ----------

def _install_mock(monkeypatch, handler) -> None:
    def _fake_build(settings, **kwargs):  # noqa: ANN001, ANN003
        return httpx.Client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr("aila.platform.tools.http.build_http_client", _fake_build)


def test_fetch_happy_path_returns_response(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    _install_mock(monkeypatch, handler)
    tool = HTTPFetchTool(_settings())
    result = tool.forward("GET", "http://1.1.1.1/")
    assert result["status_code"] == 200
    assert result["text"] == "ok"


def test_fetch_blocks_redirect_to_imds(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # First (and only) hop: redirect toward cloud IMDS.
        return httpx.Response(
            301, headers={"location": "http://169.254.169.254/latest/meta-data/"}
        )

    _install_mock(monkeypatch, handler)
    tool = HTTPFetchTool(_settings())
    with pytest.raises(SSRFBlockedError):
        tool.forward("GET", "http://1.1.1.1/")


def test_fetch_blocks_redirect_to_file_scheme(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "file:///etc/passwd"})

    _install_mock(monkeypatch, handler)
    tool = HTTPFetchTool(_settings())
    with pytest.raises(SSRFBlockedError):
        tool.forward("GET", "http://1.1.1.1/")


def test_fetch_blocks_direct_imds_before_request(monkeypatch) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, text="should-not-reach")

    _install_mock(monkeypatch, handler)
    tool = HTTPFetchTool(_settings())
    with pytest.raises(SSRFBlockedError):
        tool.forward("GET", "http://169.254.169.254/")
    assert calls == []  # blocked before any socket was opened


def test_fetch_refuses_redirect_loop(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # Always redirect to another allowed public host -> exceeds hop limit.
        return httpx.Response(301, headers={"location": "http://1.0.0.1/"})

    _install_mock(monkeypatch, handler)
    tool = HTTPFetchTool(_settings())
    with pytest.raises(SSRFBlockedError):
        tool.forward("GET", "http://1.1.1.1/")
