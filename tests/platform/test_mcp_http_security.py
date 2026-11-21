from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest

from aila.platform.mcp.mcp_session import McpHttpError, McpHttpSession


class _Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


def _secure_session(response: httpx.Response) -> McpHttpSession:
    session = McpHttpSession(
        "https://secret-token@scopesentry.example.test", validate_egress=True,
        client_factory=httpx.AsyncClient,
    )
    async def transport(_request: httpx.Request) -> httpx.Response:
        return response
    session._http = httpx.AsyncClient(transport=httpx.MockTransport(transport))
    return session


@pytest.mark.asyncio
async def test_secure_mcp_stream_enforces_cap_without_content_length() -> None:
    session = _secure_session(httpx.Response(
        200, headers={"Content-Type": "application/json"},
        stream=_Chunks([b"x" * 1024 * 1024, b"x" * 1024 * 1024, b"overflow"]),
    ))
    try:
        with pytest.raises(McpHttpError, match="exceeds 2 MiB"):
            await session._post_rpc("tools/list", {}, timeout=1.0)
    finally:
        await session.aclose()


@pytest.mark.asyncio
async def test_secure_mcp_http_error_reflects_neither_url_nor_upstream_body() -> None:
    session = _secure_session(httpx.Response(500, content=b"secret-upstream-body"))
    try:
        with pytest.raises(McpHttpError) as captured:
            await session._post_rpc("tools/list", {}, timeout=1.0)
        message = str(captured.value)
        assert "secret-upstream-body" not in message
        assert "secret-token" not in message
        assert message == "HTTP 500 from secure MCP endpoint"
    finally:
        await session.aclose()


@pytest.mark.asyncio
async def test_secure_mcp_json_rpc_error_does_not_reflect_upstream_message() -> None:
    session = _secure_session(httpx.Response(
        200, json={"jsonrpc": "2.0", "error": {"code": -32000, "message": "secret-upstream-message"}},
    ))
    try:
        with pytest.raises(McpHttpError) as captured:
            await session._post_rpc("tools/list", {}, timeout=1.0)
        assert str(captured.value) == "JSON-RPC -32000"
    finally:
        await session.aclose()
