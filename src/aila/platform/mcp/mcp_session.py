"""Native MCP protocol sessions -- streamable-HTTP and stdio transports.

:class:`McpClient` historically spoke only the bespoke bridge HTTP
contract (``GET /tools`` + ``POST /tools/<action>``) implemented by the
in-repo audit-mcp server. External MCP servers speak the
Model Context Protocol itself: JSON-RPC 2.0 ``initialize`` /
``tools/list`` / ``tools/call`` over a streamable-HTTP endpoint (``POST
{base}/mcp``, responses as ``application/json`` or ``text/event-stream``
frames) or over stdio (newline-delimited JSON-RPC on the child's stdout).

This module implements both wire transports behind one small surface:

* :class:`McpHttpSession` -- one MCP session against one streamable-HTTP
  server. Performs the ``initialize`` handshake lazily on first use,
  retains the ``Mcp-Session-Id`` the server returns, replays it on every
  subsequent request, and sends ``notifications/initialized`` once after
  the handshake, per the MCP transport spec. A stateful server MAY
  replace our session when another client initializes (REA does exactly
  that: the newest ``initialize`` wins); a request refused with HTTP
  404/400 while we hold a session id re-handshakes once and retries.
* :class:`McpStdioSession` -- spawns ``command`` as a subprocess and
  exchanges newline-delimited JSON-RPC messages on stdin/stdout per the
  MCP stdio transport. One reader task owns stdout and demuxes responses
  by JSON-RPC id. The stdout line limit is raised to 16 MiB because MCP
  servers deliver a whole result as one JSON line (REA budgets results
  up to its 10 MiB stdio receive buffer; asyncio's 64 KiB default would
  raise on the first large dossier). When the child exits, every pending
  request fails immediately and the next request respawns the child.
  The child's stderr is inherited so server logs land in the host
  process log.

Sessions are SHARED per event loop through :func:`shared_session`: a
stdio server costs one child process (REA + a Ghidra JVM), and a
stateful HTTP server serves one client at a time, so every bridge in a
process that targets the same endpoint MUST reuse one session rather
than spawning / handshaking its own. Each session also carries a
``state`` dict and an ``affinity`` condition for server-specific middleware
that must make several requests atomically (REA: ensure the active
target, then analyze it).

Both transports return raw JSON-RPC result payloads; the caller
(:class:`aila.platform.mcp.client.McpClient`) maps them onto the legacy
bridge envelope so every downstream consumer keeps one shape.
"""
from __future__ import annotations

import abc
import asyncio
import json
import logging
import uuid
import weakref
from collections.abc import Callable, Sequence
from typing import Any

import httpx

__all__ = [
    "MCP_PROTOCOL_VERSION",
    "McpHttpError",
    "McpHttpSession",
    "McpSession",
    "McpStdioError",
    "McpStdioSession",
    "close_shared_sessions",
    "shared_session",
]

_log = logging.getLogger(__name__)

# MCP protocol revision negotiated at initialize. Servers on an older
# revision answer with their own version and the session continues on
# the server's token (captured at handshake).
MCP_PROTOCOL_VERSION = "2025-06-18"

_MCP_ENDPOINT_PATH = "/mcp"
_SSE_DATA_PREFIX = "data:"
# One JSON-RPC message per stdout line; MCP results can be megabytes.
_STDIO_LINE_LIMIT = 16 * 1024 * 1024
_SESSION_REFUSED_STATUSES = frozenset({400, 404})


class McpHttpError(RuntimeError):
    """The streamable-HTTP MCP endpoint returned an unusable response."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class McpStdioError(RuntimeError):
    """The stdio MCP child failed to handshake, respond, or stay up."""


class McpSession(abc.ABC):
    """Transport-agnostic MCP session surface.

    ``state`` and ``affinity`` belong to the server-specific middleware
    (e.g. REA's active-target tracking under a reader/writer protocol on
    the ``affinity`` condition); the transport resets ``state`` whenever
    the server-side session is lost, because any server-side session
    state (an opened target) is gone with it.
    """

    def __init__(self) -> None:
        self.state: dict[str, Any] = {}
        self.affinity = asyncio.Condition()

    async def list_tools(self, *, timeout: float) -> list[dict[str, Any]]:
        """Return the server's ``tools/list`` entries."""
        result = await self.request("tools/list", {}, timeout=timeout)
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

    @abc.abstractmethod
    async def request(
        self, method: str, params: dict[str, Any], *, timeout: float,
    ) -> Any:
        """Send one JSON-RPC request and return the decoded result."""

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Release transport resources (HTTP client / child process)."""

    def _next_id(self) -> str:
        return uuid.uuid4().hex[:12]

    @staticmethod
    def _initialize_params(client_name: str, client_version: str) -> dict[str, Any]:
        return {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": client_name, "version": client_version},
        }


class McpHttpSession(McpSession):
    """One MCP session over the streamable-HTTP transport.

    ``base_url`` is the SERVER ROOT (``http://127.0.0.1:18824``); the
    ``/mcp`` endpoint path is appended here. Requests are serialized
    through an :class:`asyncio.Lock` because the stateful servers behind
    this transport serve one client per session.
    """

    def __init__(
        self,
        base_url: str,
        *,
        client_name: str = "aila",
        client_version: str = "1.0",
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__()
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

    def _reset_session(self) -> None:
        self._initialized = False
        self._session_id = None
        self.state.clear()

    async def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        result, headers = await self._post_rpc(
            "initialize",
            self._initialize_params(self._client_name, self._client_version),
            timeout=30.0,
        )
        session_id = headers.get("mcp-session-id")
        if session_id:
            self._session_id = session_id
        if isinstance(result, dict):
            negotiated = result.get("protocolVersion")
            if isinstance(negotiated, str) and negotiated:
                self._protocol_version = negotiated
        # The streamable-HTTP transport REQUIRES the initialized
        # notification after a successful handshake; servers acknowledge
        # it with 202. It carries no JSON-RPC id.
        await self._post_notification("notifications/initialized", {})
        self._initialized = True

    async def _post_notification(
        self, method: str, params: dict[str, Any],
    ) -> None:
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        client = await self._client()
        try:
            await client.post(
                self._endpoint(),
                json=message,
                headers=self._request_headers(),
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
            headers["MCP-Protocol-Version"] = self._protocol_version
        return headers

    async def _post_rpc(
        self, method: str, params: dict[str, Any], *, timeout: float,
    ) -> tuple[Any, httpx.Headers]:
        """POST one JSON-RPC request; return (result, response headers).

        Parses either a direct ``application/json`` JSON-RPC body or an
        SSE stream whose ``data:`` frames carry JSON-RPC messages; the
        message bearing our request id wins.
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
        if resp.status_code >= 400:
            raise McpHttpError(
                f"HTTP {resp.status_code} from {self._endpoint()}: "
                f"{resp.text[:200]}",
                status_code=resp.status_code,
            )
        content_type = resp.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            payload: Any = self._decode_sse(resp.text, request_id)
        else:
            try:
                payload = resp.json()
            except ValueError as exc:
                raise McpHttpError(
                    f"non-JSON response from {self._endpoint()}: "
                    f"{resp.text[:200]}",
                    status_code=resp.status_code,
                ) from exc
        if not isinstance(payload, dict):
            raise McpHttpError(
                f"no JSON-RPC response for {method} from {self._endpoint()}",
                status_code=resp.status_code,
            )
        error = payload.get("error")
        if isinstance(error, dict):
            raise McpHttpError(
                f"JSON-RPC {error.get('code')}: {error.get('message')}",
                status_code=resp.status_code,
            )
        return payload.get("result"), resp.headers

    @staticmethod
    def _decode_sse(text: str, request_id: str) -> dict[str, Any] | None:
        """Scan SSE frames for the JSON-RPC message matching ``request_id``."""
        for line in text.splitlines():
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
                return message
        return None

    async def request(
        self, method: str, params: dict[str, Any], *, timeout: float,
    ) -> Any:
        async with self._lock:
            await self._ensure_initialized()
            try:
                result, headers = await self._post_rpc(
                    method, params, timeout=timeout,
                )
            except McpHttpError as exc:
                if exc.status_code not in _SESSION_REFUSED_STATUSES or not self._session_id:
                    raise
                # Another client replaced our session (or the server
                # restarted): re-handshake once and retry. Server-side
                # session state (an opened target) is gone with it.
                _log.info(
                    "mcp_http %s: session refused (HTTP %s) -- re-initializing",
                    self._base, exc.status_code,
                )
                self._reset_session()
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
        self._reset_session()


class McpStdioSession(McpSession):
    """One MCP session over the stdio transport.

    Spawns ``command`` (argv, e.g. ``("rea", "mcp")``) with ``env`` (the
    parent environment when ``None``) and exchanges newline-delimited
    JSON-RPC messages: requests are written to the child's stdin as
    single JSON lines; the reader task consumes stdout lines and
    completes the pending request whose id matches. Notifications (no
    id) are logged at debug. The child is terminated on :meth:`aclose`;
    a child that exits on its own fails every pending request and is
    respawned (with a fresh handshake) by the next request.
    """

    def __init__(
        self,
        command: Sequence[str],
        *,
        env: dict[str, str] | None = None,
        client_name: str = "aila",
        client_version: str = "1.0",
    ) -> None:
        super().__init__()
        if not command:
            raise McpStdioError("stdio MCP session requires a command")
        self._command = tuple(command)
        self._env = env
        self._client_name = client_name
        self._client_version = client_version
        self._proc: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._write_lock = asyncio.Lock()
        self._start_lock = asyncio.Lock()
        self._ready = False

    async def _ensure_started(self) -> None:
        if self._ready:
            return
        async with self._start_lock:
            if self._ready:
                return
            try:
                self._proc = await asyncio.create_subprocess_exec(
                    *self._command,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=None,
                    env=self._env,
                    limit=_STDIO_LINE_LIMIT,
                )
            except OSError as exc:
                raise McpStdioError(
                    f"cannot spawn MCP server {self._command[0]!r}: {exc}",
                ) from exc
            self._reader_task = asyncio.create_task(self._read_loop(self._proc))
            await self._send_request(
                "initialize",
                self._initialize_params(self._client_name, self._client_version),
                timeout=60.0,
            )
            await self._send_notification("notifications/initialized", {})
            self._ready = True

    async def _read_loop(self, proc: asyncio.subprocess.Process) -> None:
        if proc.stdout is None:
            raise McpStdioError(f"MCP server {self._command[0]!r} has no stdout pipe")
        try:
            while True:
                try:
                    line = await proc.stdout.readline()
                except (ValueError, asyncio.LimitOverrunError) as exc:
                    _log.warning(
                        "mcp_stdio %s: oversized stdout line dropped: %s",
                        self._command[0], exc,
                    )
                    continue
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
        finally:
            self._on_child_exit(proc)

    def _on_child_exit(self, proc: asyncio.subprocess.Process) -> None:
        """Fail pending requests and mark the session for respawn."""
        if self._proc is not proc:
            return
        self._ready = False
        self._proc = None
        self.state.clear()
        error = McpStdioError(
            f"MCP server {self._command[0]!r} exited "
            f"(returncode={proc.returncode})",
        )
        for future in self._pending.values():
            if not future.done():
                future.set_exception(error)
        self._pending.clear()

    async def _write_line(self, message: dict[str, Any]) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise McpStdioError(f"MCP server {self._command[0]!r} is not running")
        async with self._write_lock:
            try:
                proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError) as exc:
                raise McpStdioError(
                    f"MCP server {self._command[0]!r} closed stdin: {exc}",
                ) from exc

    async def _send_notification(
        self, method: str, params: dict[str, Any],
    ) -> None:
        await self._write_line({"jsonrpc": "2.0", "method": method, "params": params})

    async def _send_request(
        self, method: str, params: dict[str, Any], *, timeout: float,
    ) -> Any:
        request_id = self._next_id()
        future: asyncio.Future[dict[str, Any]] = (
            asyncio.get_running_loop().create_future()
        )
        self._pending[request_id] = future
        try:
            await self._write_line({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            })
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
                f"JSON-RPC {error.get('code')}: {error.get('message')}",
            )
        return response.get("result")

    async def request(
        self, method: str, params: dict[str, Any], *, timeout: float,
    ) -> Any:
        await self._ensure_started()
        return await self._send_request(method, params, timeout=timeout)

    async def aclose(self) -> None:
        proc = self._proc
        self._ready = False
        self._proc = None
        for future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()
        self.state.clear()
        if self._reader_task is not None:
            self._reader_task.cancel()
            self._reader_task = None
        if proc is None:
            return
        if proc.stdin is not None:
            # MCP servers (REA included) shut down cleanly on stdin EOF.
            proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(), timeout=10.0)
        except TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                _log.debug("mcp_stdio %s: child already exited before kill", self._command[0])
            else:
                await proc.wait()


# Process-wide session registry, partitioned per event loop: asyncio
# primitives (locks, futures, subprocess transports) are loop-bound, so a
# session created on one loop must never serve another (pytest and the
# ARQ worker each run their own loops).
_SHARED: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop, dict[tuple[str, ...], McpSession]
] = weakref.WeakKeyDictionary()


def shared_session(
    key: tuple[str, ...], factory: Callable[[], McpSession],
) -> McpSession:
    """Return the loop-local session for ``key``, creating it once.

    ``key`` identifies the endpoint: ``("mcp-http", url)`` or
    ``("stdio", *command)``. Every bridge in the process that targets
    the same endpoint shares one session (one stdio child, one HTTP
    session id).
    """
    loop = asyncio.get_running_loop()
    sessions = _SHARED.setdefault(loop, {})
    session = sessions.get(key)
    if session is None:
        session = factory()
        sessions[key] = session
    return session


async def close_shared_sessions() -> None:
    """Close every session registered on the running loop (shutdown hook)."""
    loop = asyncio.get_running_loop()
    sessions = _SHARED.pop(loop, {})
    for session in sessions.values():
        await session.aclose()
