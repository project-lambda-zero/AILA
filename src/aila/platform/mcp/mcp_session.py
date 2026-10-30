"""Native MCP protocol sessions -- streamable-HTTP and stdio transports.

:class:`McpClient` historically spoke only the bespoke bridge HTTP
contract (``GET /tools`` + ``POST /tools/<action>``) implemented by the
in-repo audit-mcp / ida-headless servers. External MCP servers speak the
Model Context Protocol itself: JSON-RPC 2.0 ``initialize`` /
``tools/list`` / ``tools/call`` over a streamable-HTTP endpoint (``POST
{base}/mcp``, responses as ``application/json`` or ``text/event-stream``
frames) or over stdio (newline-delimited JSON-RPC on the child's stdout).

This module implements both wire transports behind one small surface:

* :class:`McpHttpSession` -- one MCP session against one streamable-HTTP
  server. Performs the ``initialize`` handshake lazily on first use,
  retains the ``Mcp-Session-Id`` the server returns, replays it on every
  subsequent request, and sends ``notifications/initialized`` once after
  the handshake, per the MCP transport spec. REA (morluto/rea) documents
  exactly this behaviour, including the session-replacement rule: a new
  ``initialize`` evicts the previous session, so ONE session object maps
  to ONE logical client and concurrent callers must serialize on
  :meth:`request` (the REA HTTP runtime serves one client at a time and
  admits at most eight concurrent dispatches).
* :class:`McpStdioSession` -- spawns ``command`` as a subprocess and
  exchanges newline-delimited JSON-RPC messages on stdin/stdout per the
  MCP stdio transport. One reader task owns stdout and demuxes responses
  by JSON-RPC id; notifications (messages without an id) are dropped
  after optional progress logging. The child is terminated on
  :meth:`aclose`.

Both transports return raw JSON-RPC result payloads; the caller
(:class:`aila.platform.mcp.client.McpClient`) maps them onto the legacy
bridge envelope so every downstream consumer keeps one shape.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import Sequence
from typing import Any

import httpx

__all__ = [
    "MCP_PROTOCOL_VERSION",
    "McpHttpError",
    "McpHttpSession",
    "McpSession",
    "McpStdioError",
    "McpStdioSession",
]

_log = logging.getLogger(__name__)

# MCP protocol revision negotiated at initialize. The streamable-HTTP
# transport spec versions the protocol independently of the SDK; the
# 2025-06-18 revision is the current LTS negotiation token. Servers on
# an older revision answer with their own version and the session
# continues on the server's token (captured at handshake).
MCP_PROTOCOL_VERSION = "2025-06-18"

_MCP_ENDPOINT_PATH = "/mcp"
_SSE_DATA_PREFIX = "data:"


class McpHttpError(RuntimeError):
    """The streamable-HTTP MCP endpoint returned an unusable response."""


class McpStdioError(RuntimeError):
    """The stdio MCP child failed to handshake, respond, or stay up."""


class McpSession:
    """Transport-agnostic MCP session surface."""

    async def list_tools(self, *, timeout: float) -> list[dict[str, Any]]:
        """Return the server's ``tools/list`` entries."""
        result = await self.request(
            "tools/list", {}, timeout=timeout,
        )
        tools = result.get("tools") if isinstance(result, dict) else None
        return [t for t in tools if isinstance(t, dict)] if isinstance(tools, list) else []

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        timeout: float,
    ) -> dict[str, Any]:
        """Invoke ``tools/call`` and return the raw JSON-RPC result."""
        result = await self.request(
            "tools/call", {"name": name, "arguments": arguments}, timeout=timeout,
        )
        return result if isinstance(result, dict) else {"result": result}

    async def request(
        self, _method: str, _params: dict[str, Any], *, timeout: float,
    ) -> Any:
        """Send one JSON-RPC request and return the decoded result."""
        raise NotImplementedError

    async def aclose(self) -> None:
        """Release transport resources (HTTP client / child process)."""

    def _next_id(self) -> str:
        return uuid.uuid4().hex[:12]


class McpHttpSession(McpSession):
    """One MCP session over the streamable-HTTP transport.

    ``base_url`` is the SERVER ROOT (``http://127.0.0.1:18823``); the
    ``/mcp`` endpoint path is appended here. The session performs the
    ``initialize`` handshake on first use, retains the negotiated
    protocol version and the ``Mcp-Session-Id`` response header, replays
    the session id on later requests, and emits the one-time
    ``notifications/initialized`` notification after the handshake.
    Requests are serialized through an :class:`asyncio.Lock` because the
    stateful servers behind this transport (REA) serve one client per
    session and a second in-flight ``initialize`` would evict ours.
    """

    def __init__(
        self,
        base_url: str,
        *,
        client_name: str = "aila",
        client_version: str = "1.0",
        headers: dict[str, str] | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._client_name = client_name
        self._client_version = client_version
        self._extra_headers = dict(headers or {})
        self._http: httpx.AsyncClient | None = None
        self._session_id: str | None = None
        self._protocol_version = MCP_PROTOCOL_VERSION
        self._initialized = False
        self._lock = asyncio.Lock()

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient()
        return self._http

    async def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        result, headers = await self._post_rpc(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": self._client_name,
                    "version": self._client_version,
                },
            },
            timeout=30.0,
        )
        session_id = headers.get("mcp-session-id")
        if session_id:
            self._session_id = session_id
        if isinstance(result, dict):
            negotiated = result.get("protocolVersion")
            if isinstance(negotiated, str) and negotiated:
                self._protocol_version = negotiated
        # The MCP streamable-HTTP transport REQUIRES the initialized
        # notification after a successful handshake; servers (REA
        # included) acknowledge it with 202. It carries no JSON-RPC id.
        await self._post_notification("notifications/initialized", {})
        self._initialized = True

    async def _post_notification(
        self, method: str, params: dict[str, Any],
    ) -> None:
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        headers = self._request_headers()
        client = await self._client()
        try:
            await client.post(
                self._endpoint(),
                json=message,
                headers=headers,
                timeout=30.0,
            )
        except httpx.HTTPError as exc:
            _log.debug(
                "mcp_http: %s notification not acknowledged: %s", method, exc,
            )

    def _endpoint(self) -> str:
        return f"{self._base}{_MCP_ENDPOINT_PATH}"

    def _request_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self._extra_headers,
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    async def _post_rpc(
        self, method: str, params: dict[str, Any], *, timeout: float,
    ) -> tuple[Any, httpx.Headers]:
        """POST one JSON-RPC request; return (result, response headers).

        Parses either a direct ``application/json`` JSON-RPC body or an
        SSE stream whose ``data:`` frames carry JSON-RPC messages; the
        first message bearing our request id wins.
        """
        request_id = self._next_id()
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        client = await self._client()
        resp = await client.post(
            self._endpoint(),
            json=message,
            headers=self._request_headers(),
            timeout=timeout,
        )
        content_type = resp.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            payload = self._decode_sse(resp, request_id)
        else:
            try:
                payload = resp.json()
            except ValueError as exc:
                raise McpHttpError(
                    f"non-JSON response from {self._endpoint()}: "
                    f"{resp.text[:200]}"
                ) from exc
        if resp.status_code >= 400:
            raise McpHttpError(
                f"HTTP {resp.status_code} from {self._endpoint()}: "
                f"{resp.text[:200]}"
            )
        if not isinstance(payload, dict):
            raise McpHttpError(
                f"unexpected JSON-RPC payload from {self._endpoint()}: "
                f"{str(payload)[:200]}"
            )
        error = payload.get("error")
        if isinstance(error, dict):
            raise McpHttpError(
                f"JSON-RPC {error.get('code')}: {error.get('message')}"
            )
        return payload.get("result"), resp.headers

    def _decode_sse(
        self, resp: httpx.Response, request_id: str,
    ) -> dict[str, Any] | None:
        """Scan SSE frames for the JSON-RPC message matching ``request_id``."""
        matched: dict[str, Any] | None = None
        for line in resp.text.splitlines():
            if not line.startswith(_SSE_DATA_PREFIX):
                continue
            data = line[len(_SSE_DATA_PREFIX):].strip()
            if not data:
                continue
            try:
                message = json.loads(data)
            except ValueError:
                continue
            if isinstance(message, dict) and str(message.get("id")) == request_id:
                matched = message
                break
        return matched

    async def request(
        self, method: str, params: dict[str, Any], *, timeout: float,
    ) -> Any:
        async with self._lock:
            await self._ensure_initialized()
            result, headers = await self._post_rpc(
                method, params, timeout=timeout,
            )
            session_id = headers.get("mcp-session-id")
            if session_id:
                self._session_id = session_id
            return result

    async def aclose(self) -> None:
        if self._http is not None and not self._http.is_closed:
            await self._http.aclose()
        self._http = None
        self._initialized = False


class McpStdioSession(McpSession):
    """One MCP session over the stdio transport.

    Spawns ``command`` (argv list, e.g. ``("npx", "rea-agents", "mcp")``)
    and exchanges newline-delimited JSON-RPC messages: requests are
    written to the child's stdin as single JSON lines; the reader task
    consumes stdout lines and completes the pending request future whose
    id matches. Notifications (no id) are logged at debug when they
    carry a ``method``. The child is terminated on :meth:`aclose`.
    """

    def __init__(self, command: Sequence[str]) -> None:
        if not command:
            raise McpStdioError("stdio MCP session requires a command")
        self._command = tuple(command)
        self._proc: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._write_lock = asyncio.Lock()
        self._started = False

    async def _ensure_started(self) -> None:
        if self._started:
            return
        self._proc = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self._reader_task = asyncio.create_task(self._read_loop())
        self._started = True
        await self.request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "aila", "version": "1.0"},
            },
            timeout=30.0,
        )
        await self._send_notification("notifications/initialized", {})

    async def _read_loop(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        while True:
            line = await self._proc.stdout.readline()
            if not line:
                break
            try:
                message = json.loads(line.decode("utf-8", errors="replace"))
            except ValueError:
                continue
            if not isinstance(message, dict):
                continue
            msg_id = message.get("id")
            if msg_id is None:
                method = message.get("method")
                if isinstance(method, str):
                    _log.debug("mcp_stdio: notification %s", method)
                continue
            future = self._pending.pop(str(msg_id), None)
            if future is not None and not future.done():
                future.set_result(message)

    async def _send_notification(
        self, method: str, params: dict[str, Any],
    ) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        async with self._write_lock:
            self._proc.stdin.write(
                (json.dumps(message) + "\n").encode("utf-8"),
            )
            await self._proc.stdin.drain()

    async def request(
        self, method: str, params: dict[str, Any], *, timeout: float,
    ) -> Any:
        if not self._started:
            await self._ensure_started()
        assert self._proc is not None and self._proc.stdin is not None
        request_id = self._next_id()
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        try:
            async with self._write_lock:
                self._proc.stdin.write(
                    (json.dumps(message) + "\n").encode("utf-8"),
                )
                await self._proc.stdin.drain()
            response = await asyncio.wait_for(future, timeout=timeout)
        except TimeoutError as exc:
            raise McpStdioError(
                f"timeout ({timeout}s) awaiting {method} from {self._command[0]}",
            ) from exc
        finally:
            self._pending.pop(request_id, None)
        error = response.get("error")
        if isinstance(error, dict):
            raise McpStdioError(
                f"JSON-RPC {error.get('code')}: {error.get('message')}"
            )
        return response.get("result")

    async def aclose(self) -> None:
        for future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()
        if self._reader_task is not None:
            self._reader_task.cancel()
            self._reader_task = None
        if self._proc is not None:
            if self._proc.stdin is not None:
                self._proc.stdin.close()
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            except (TimeoutError, ProcessLookupError):
                self._proc.kill()
            self._proc = None
        self._started = False
