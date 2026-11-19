from __future__ import annotations

import asyncio
import base64
import builtins
import codecs
import hashlib
import io
import logging
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

import paramiko

from ...storage.database import async_session_scope
from ...storage.secrets import SecretStore
from ..config import PlatformSettings
from ..contracts.platform import RegisteredSystem, SSHIntegrationInput
from ..exceptions import AILATimeoutError, AuthenticationError, UpstreamError, ValidationError
from .log_redact import redact_command_line

_log = logging.getLogger(__name__)

_READ_CHUNK_BYTES = 32_768
_CANCEL_POLL_S = 0.1
_KILL_TIMEOUT_S = 10.0

StreamCallback = Callable[[str], Awaitable[None]]
CancelCheck = Callable[[], Awaitable[bool]]


class CommandCancelledError(RuntimeError):
    """The remote command was cancelled before it produced an exit status."""


def _apply_host_key_policy(
    client: paramiko.SSHClient, payload: SSHIntegrationInput
) -> None:
    """Install a reject-unknown-host-key policy on ``client`` (#42).

    Every SSH surface (pool + direct connect + upload + download)
    routes host-key trust through this helper so the reject-by-default
    rule cannot be reintroduced by drift on any single path.

    An explicitly configured ``known_hosts_path`` is layered on top of
    the system-default known_hosts via ``load_host_keys`` (called by
    the surrounding caller) so an operator-declared trust file still
    admits its hosts. When no ``known_hosts_path`` is configured the
    client no longer silently AutoAdds the server's key on first
    connect -- that is a MITM window on the first handshake against a
    freshly registered host. Hosts the operator has previously
    accepted into ``~/.ssh/known_hosts`` continue to connect because
    every caller runs ``load_system_host_keys()`` before invoking
    this helper; unknown hosts fail closed with a
    ``paramiko.SSHException`` that surfaces as an ``UpstreamError``.

    The ``payload`` parameter is intentionally accepted (even though it
    is not read today) so any future policy variation -- e.g. a
    strict-mode setting that also refuses TOFU on operator-supplied
    known_hosts -- has a single seam to change without touching five
    call sites again.
    """
    del payload  # currently uniform; kept for future policy variation.
    client.set_missing_host_key_policy(paramiko.RejectPolicy())


def _reject_unsafe_path(path: object, *, kind: str) -> None:
    """Reject empty or ``..``-traversal SFTP paths before any network call.

    Guards both remote and local endpoints on the SFTP surface. A ``..``
    segment can escape the intended target directory on either end -- the
    server side on upload, the local file system on download -- so the SFTP
    entry points refuse to open a connection for paths that contain one.
    Splits on POSIX and Windows separators so the check cannot be sidestepped
    by choosing the other style.

    Args:
        path: The user-supplied path string to validate.
        kind: A short label (``"remote"`` or ``"local"``) used in the error
            message so the caller can tell which side of the transfer was
            rejected.

    Raises:
        ValueError: If ``path`` is not a non-empty string, or contains a
            ``..`` path segment.
    """
    if not isinstance(path, str) or not path.strip():
        raise ValueError(f"SFTP {kind} path must be a non-empty string.")
    # Normalize Windows separators so ``..\\foo`` collapses into the same
    # segment view as ``../foo`` before the traversal check runs.
    segments = path.replace("\\", "/").split("/")
    if any(segment == ".." for segment in segments):
        raise ValueError(
            f"SFTP {kind} path {path!r} contains a '..' traversal segment."
        )


class _ChannelCloser:
    """Close an exec channel on behalf of a cancelled awaiting coroutine.

    Cancelling the coroutine that awaits ``asyncio.to_thread`` cannot stop
    the worker thread: it stays parked in a blocking paramiko read until the
    remote command ends. The coroutine side calls :meth:`close`, which closes
    the channel so those reads return and the thread unwinds. The worker side
    calls :meth:`register` as soon as the channel exists; a close requested
    before registration is applied on registration, so the order of the two
    calls does not matter.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._channel: paramiko.Channel | None = None
        self.closed = False

    def register(self, channel: paramiko.Channel) -> None:
        """Track ``channel``; close it at once if a close was already requested."""
        with self._lock:
            self._channel = channel
            if self.closed:
                self._close_channel(channel)

    def close(self) -> None:
        """Request closure and close the registered channel, if any."""
        with self._lock:
            self.closed = True
            if self._channel is not None:
                self._close_channel(self._channel)

    @staticmethod
    def _close_channel(channel: paramiko.Channel) -> None:
        try:
            channel.close()
        except (paramiko.SSHException, OSError, EOFError):
            pass


@dataclass(slots=True)
class _ReadOutcome:
    """Full text and failure captured by one stream reader thread."""

    text: str = ""
    error: BaseException | None = None


class _StreamSink:
    """Decode one remote stream incrementally and hand text to an awaited callback.

    Each chunk is delivered with ``run_coroutine_threadsafe(...).result()``, so
    the reader thread blocks until the callback finishes; a slow consumer
    therefore backpressures the remote process instead of buffering unbounded
    output. When ``redact_lines`` is set, text is buffered to line boundaries
    and each complete line is passed through :func:`redact_command_line` before
    it is streamed.
    """

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        callback: StreamCallback | None,
        *,
        redact_lines: bool,
    ) -> None:
        self._loop = loop
        self._callback = callback
        self._redact_lines = redact_lines
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="ignore")
        self._parts: list[str] = []
        self._line_buf = ""

    def feed(self, data: bytes) -> None:
        text = self._decoder.decode(data)
        self._parts.append(text)
        self._forward(text)

    def finish(self) -> str:
        tail = self._decoder.decode(b"", final=True)
        if tail:
            self._parts.append(tail)
            self._forward(tail)
        if self._redact_lines and self._line_buf:
            self._emit(redact_command_line(self._line_buf))
            self._line_buf = ""
        return "".join(self._parts)

    def _forward(self, text: str) -> None:
        if self._callback is None or not text:
            return
        if not self._redact_lines:
            self._emit(text)
            return
        self._line_buf += text
        *complete, self._line_buf = self._line_buf.split("\n")
        if complete:
            self._emit("".join(redact_command_line(line) + "\n" for line in complete))

    def _emit(self, text: str) -> None:
        if self._callback is None or not text:
            return
        asyncio.run_coroutine_threadsafe(self._callback(text), self._loop).result()


def _drain(
    read: Callable[[int], bytes],
    sink: _StreamSink,
    outcome: _ReadOutcome,
    closer: _ChannelCloser,
) -> None:
    """Read one channel stream to EOF on a worker thread.

    Any failure, including one raised by a streaming callback, is stored on
    ``outcome`` and the channel is closed so the sibling reader and the exit
    poll unblock. The caller thread re-raises it after both readers join.
    """
    try:
        while data := read(_READ_CHUNK_BYTES):
            sink.feed(data)
        outcome.text = sink.finish()
    except BaseException as exc:  # noqa: BLE001 -- re-raised on the caller thread
        outcome.error = exc
        closer.close()


def _kill_remote(client: paramiko.SSHClient, command: str) -> None:
    """Run a cleanup command on a fresh exec channel; failures are logged only."""
    try:
        _, stdout, _ = client.exec_command(command)
        stdout.channel.settimeout(_KILL_TIMEOUT_S)
        stdout.channel.recv_exit_status()
    except (paramiko.SSHException, OSError, EOFError) as exc:
        _log.warning("remote cancel command failed: %s", exc)


async def _watch_for_cancel(cancel_requested: CancelCheck, closer: _ChannelCloser) -> None:
    while not await cancel_requested():
        await asyncio.sleep(_CANCEL_POLL_S)
    closer.close()


def _on_watcher_done(task: asyncio.Task[None], closer: _ChannelCloser) -> None:
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        # Fail closed: a broken cancel probe must not leave the remote run unbounded.
        _log.error("cancel_requested failed; closing SSH channel", exc_info=exc)
        closer.close()


class SSHConnectionPool:
    """Reusable SSH connections keyed by (host, port, username) for one scan's lifetime."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pool: dict[tuple[str, int, str], paramiko.SSHClient] = {}

    def get_or_connect(self, payload: SSHIntegrationInput, connect_kwargs: dict) -> paramiko.SSHClient:
        """Return a live SSH client for the target host, creating one if needed."""
        key = (payload.host, payload.port, payload.username)
        with self._lock:
            client = self._pool.get(key)
            if client is not None:
                transport = client.get_transport()
                if transport is not None and transport.is_active():
                    return client
            new_client = paramiko.SSHClient()
            new_client.load_system_host_keys()
            if payload.known_hosts_path:
                known_hosts_path = Path(payload.known_hosts_path).resolve()
                if known_hosts_path.exists():
                    new_client.load_host_keys(str(known_hosts_path))
            _apply_host_key_policy(new_client, payload)
            new_client.connect(**connect_kwargs)
            self._pool[key] = new_client
            return new_client

    def close_all(self) -> None:
        """Close and remove all pooled SSH connections."""
        with self._lock:
            for client in self._pool.values():
                try:
                    client.close()
                except (paramiko.ssh_exception.SSHException, OSError):
                    pass
            self._pool.clear()


class SSHService:
    """Platform SSH execution service with optional connection pooling."""

    def __init__(self, settings: PlatformSettings, secret_store: SecretStore | None = None):
        self.settings = settings
        self.secret_store = secret_store or SecretStore(self.settings)

    async def run_command(
        self,
        integration: dict | SSHIntegrationInput | RegisteredSystem,
        command: str,
        timeout_seconds: float | None = None,
        pool: SSHConnectionPool | None = None,
        connect_timeout: float = 15.0,
    ) -> str:
        """Execute command over SSH and return decoded stdout.

        Resolves credentials asynchronously, then runs blocking paramiko I/O
        in a thread via asyncio.to_thread to avoid blocking the event loop.

        Cancellation: if the awaiting task is cancelled (including via
        ``asyncio.wait_for``), the command's SSH channel is closed so the
        worker thread exits promptly instead of staying parked on the remote
        command. The remote side sees the channel close (stdin EOF, and
        further writes get a broken pipe). A pooled connection stays in the
        pool; a one-shot connection is closed by the existing ``finally``.

        Args:
            connect_timeout: TCP + auth timeout in seconds for paramiko.connect().
                             Set lower (e.g. 3.0) for health probes so they fail
                             fast when a host is unreachable.
        """
        if isinstance(integration, dict):
            payload = self._to_ssh_integration(RegisteredSystem.model_validate(integration))
        elif isinstance(integration, RegisteredSystem):
            payload = self._to_ssh_integration(integration)
        else:
            payload = integration

        password = await self._resolve_password(payload)
        connect_kwargs = await self._build_connect_kwargs(
            payload, password, connect_timeout,
        )

        # `timeout_seconds` is an IDLE timeout (enforced inside
        # _run_command_blocking via channel.settimeout + exit-status polling),
        # not a wall-time deadline. Legitimate long-running commands
        # (dissect on 100GB disk, volatility on 32GB dump) may take tens of
        # minutes but still produce a steady trickle of output, so a
        # wall-clock wait_for here would kill them. We trust paramiko's
        # per-recv timer + the exit-ready poll to catch true hangs.
        closer = _ChannelCloser()
        try:
            return await asyncio.to_thread(
                self._run_command_blocking, payload, command, timeout_seconds, pool, connect_kwargs, closer,
            )
        except asyncio.CancelledError:
            closer.close()
            raise

    def _run_command_blocking(
        self,
        payload: SSHIntegrationInput,
        command: str,
        timeout_seconds: float | None,
        pool: SSHConnectionPool | None,
        connect_kwargs: dict,
        closer: _ChannelCloser,
    ) -> str:
        """Blocking SSH execution -- runs inside asyncio.to_thread."""
        if pool is not None:
            client = pool.get_or_connect(payload, connect_kwargs)
            SSHService._verify_fingerprint(client, payload)
            return SSHService._exec_command(client, command, timeout_seconds, payload, closer)

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if payload.known_hosts_path:
            known_hosts_path = Path(payload.known_hosts_path).resolve()
            if not known_hosts_path.exists():
                raise ValidationError(f"Known hosts file {known_hosts_path} does not exist.")
            client.load_host_keys(str(known_hosts_path))
        # #42: reject unknown host keys on every SSH surface. The helper
        # centralizes the policy so a fifth site can't silently drift
        # back to AutoAddPolicy.
        _apply_host_key_policy(client, payload)
        try:
            client.connect(**connect_kwargs)
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(60)
            SSHService._verify_fingerprint(client, payload)
            return SSHService._exec_command(client, command, timeout_seconds, payload, closer)
        except paramiko.AuthenticationException as exc:
            raise AuthenticationError(
                f"SSH authentication failed for {payload.name} ({payload.username}@{payload.host}:{payload.port}). "
                "Verify the username and the configured stored password or private key."
            ) from exc
        except paramiko.BadHostKeyException as exc:
            raise UpstreamError(
                f"SSH host key verification failed for {payload.name} ({payload.host}). "
                "The server host key did not match the trusted known_hosts entry."
            ) from exc
        except paramiko.SSHException as exc:
            message = str(exc)
            if "not found in known_hosts" in message.lower():
                raise UpstreamError(
                    f"SSH host key verification failed for {payload.name} ({payload.host}). "
                    "Add the host key to a trusted known_hosts file or configure known_hosts_path."
                ) from exc
            raise UpstreamError(f"SSH transport error for {payload.name} ({payload.host}): {message}") from exc
        finally:
            client.close()

    async def run_command_full(
        self,
        integration: dict | SSHIntegrationInput | RegisteredSystem,
        command: str,
        timeout_seconds: float | None = None,
        pool: SSHConnectionPool | None = None,
        connect_timeout: float = 15.0,
    ) -> tuple[str, str, int]:
        """Execute command over SSH and return (stdout, stderr, exit_code).

        Unlike :meth:`run_command`, a non-zero exit code is NOT converted to
        an ``UpstreamError``. Callers receive the full triple and inspect the
        exit code themselves -- this is the surfacing hook that lets
        script-executor tools honour a remote ``sys.exit(3)`` instead of
        reporting a silent ``exit_code=0``.

        What still raises: connection-level failures that mean the command
        never ran -- authentication rejection (:class:`AuthenticationError`),
        host-key verification failures, transport errors
        (:class:`UpstreamError`), and idle timeouts
        (:class:`aila.platform.exceptions.AILATimeoutError`). Those propagate
        because they are not "the script exited nonzero", they are "the
        script never ran".

        Cancellation: if the awaiting task is cancelled (including via
        ``asyncio.wait_for``), the command's SSH channel is closed so the
        worker thread exits promptly instead of staying parked on the remote
        command. The remote side sees the channel close (stdin EOF, and
        further writes get a broken pipe). A pooled connection stays in the
        pool; a one-shot connection is closed by the existing ``finally``.

        The returned ``stderr`` is passed through
        :func:`redact_command_line` before being handed back so inline
        credentials that a remote tool may print never surface in the
        caller's payload -- this preserves the C6 secret-redaction
        boundary that :meth:`_exec_command` applies inline in its
        error message.
        """
        return await self._run_full(
            integration,
            command,
            timeout_seconds=timeout_seconds,
            pool=pool,
            connect_timeout=connect_timeout,
            on_stdout=None,
            on_stderr=None,
            cancel_requested=None,
            cancel_command=None,
        )

    async def run_command_streaming(
        self,
        integration: dict | SSHIntegrationInput | RegisteredSystem,
        command: str,
        *,
        timeout_seconds: float | None,
        on_stdout: StreamCallback | None = None,
        on_stderr: StreamCallback | None = None,
        cancel_requested: CancelCheck | None = None,
        cancel_command: str | None = None,
        pool: SSHConnectionPool | None = None,
        connect_timeout: float = 15.0,
    ) -> tuple[str, str, int]:
        """Execute ``command`` like :meth:`run_command_full`, streaming output live.

        ``on_stdout`` receives raw decoded stdout chunks; ``on_stderr`` receives
        stderr split on line boundaries and redacted with
        :func:`redact_command_line`. Each callback is awaited before the next
        read, so a slow consumer applies backpressure to the remote process.

        ``cancel_requested`` is polled (zero-argument, returns bool). When it
        returns True the channel is closed and, if ``cancel_command`` is given,
        that command is run on a fresh exec channel to kill the remote process
        group. The result is then :class:`CommandCancelledError`.

        Returned stdout/stderr are the complete texts, as with
        :meth:`run_command_full`.
        """
        return await self._run_full(
            integration,
            command,
            timeout_seconds=timeout_seconds,
            pool=pool,
            connect_timeout=connect_timeout,
            on_stdout=on_stdout,
            on_stderr=on_stderr,
            cancel_requested=cancel_requested,
            cancel_command=cancel_command,
        )

    async def _run_full(
        self,
        integration: dict | SSHIntegrationInput | RegisteredSystem,
        command: str,
        *,
        timeout_seconds: float | None,
        pool: SSHConnectionPool | None,
        connect_timeout: float,
        on_stdout: StreamCallback | None,
        on_stderr: StreamCallback | None,
        cancel_requested: CancelCheck | None,
        cancel_command: str | None,
    ) -> tuple[str, str, int]:
        if isinstance(integration, dict):
            payload = self._to_ssh_integration(RegisteredSystem.model_validate(integration))
        elif isinstance(integration, RegisteredSystem):
            payload = self._to_ssh_integration(integration)
        else:
            payload = integration

        password = await self._resolve_password(payload)
        connect_kwargs = await self._build_connect_kwargs(
            payload, password, connect_timeout,
        )

        # `timeout_seconds` remains an IDLE timeout enforced inside
        # _run_command_full_blocking via channel.settimeout + exit-status
        # polling, mirroring run_command exactly. No wall-clock wrapper.
        loop = asyncio.get_running_loop()
        closer = _ChannelCloser()
        sinks = (
            _StreamSink(loop, on_stdout, redact_lines=False),
            _StreamSink(loop, on_stderr, redact_lines=True),
        )
        watcher: asyncio.Task[None] | None = None
        if cancel_requested is not None:
            watcher = asyncio.create_task(_watch_for_cancel(cancel_requested, closer))
            watcher.add_done_callback(lambda task: _on_watcher_done(task, closer))
        try:
            return await asyncio.to_thread(
                self._run_command_full_blocking,
                payload,
                command,
                timeout_seconds,
                pool,
                connect_kwargs,
                closer,
                sinks,
                cancel_command,
            )
        except asyncio.CancelledError:
            closer.close()
            raise
        finally:
            if watcher is not None:
                watcher.cancel()

    def _run_command_full_blocking(
        self,
        payload: SSHIntegrationInput,
        command: str,
        timeout_seconds: float | None,
        pool: SSHConnectionPool | None,
        connect_kwargs: dict,
        closer: _ChannelCloser,
        sinks: tuple[_StreamSink, _StreamSink],
        cancel_command: str | None,
    ) -> tuple[str, str, int]:
        """Blocking SSH execution returning the full triple.

        Mirrors :meth:`_run_command_blocking` but calls
        :meth:`_exec_command_pump`, which does not raise on non-zero
        exit. Runs inside :func:`asyncio.to_thread`.
        """
        if pool is not None:
            client = pool.get_or_connect(payload, connect_kwargs)
            SSHService._verify_fingerprint(client, payload)
            return SSHService._exec_command_pump(
                client, command, timeout_seconds, payload, closer, sinks, cancel_command,
            )

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if payload.known_hosts_path:
            known_hosts_path = Path(payload.known_hosts_path).resolve()
            if not known_hosts_path.exists():
                raise ValidationError(f"Known hosts file {known_hosts_path} does not exist.")
            client.load_host_keys(str(known_hosts_path))
        # #42: identical reject-by-default plumbing to
        # _run_command_blocking so the full-triple variant cannot
        # silently accept a first-connect key.
        _apply_host_key_policy(client, payload)
        try:
            client.connect(**connect_kwargs)
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(60)
            SSHService._verify_fingerprint(client, payload)
            return SSHService._exec_command_pump(
                client, command, timeout_seconds, payload, closer, sinks, cancel_command,
            )
        except paramiko.AuthenticationException as exc:
            raise AuthenticationError(
                f"SSH authentication failed for {payload.name} ({payload.username}@{payload.host}:{payload.port}). "
                "Verify the username and the configured stored password or private key."
            ) from exc
        except paramiko.BadHostKeyException as exc:
            raise UpstreamError(
                f"SSH host key verification failed for {payload.name} ({payload.host}). "
                "The server host key did not match the trusted known_hosts entry."
            ) from exc
        except paramiko.SSHException as exc:
            message = str(exc)
            if "not found in known_hosts" in message.lower():
                raise UpstreamError(
                    f"SSH host key verification failed for {payload.name} ({payload.host}). "
                    "Add the host key to a trusted known_hosts file or configure known_hosts_path."
                ) from exc
            raise UpstreamError(f"SSH transport error for {payload.name} ({payload.host}): {message}") from exc
        finally:
            client.close()

    @staticmethod
    def _exec_command_pump(
        client: paramiko.SSHClient,
        command: str,
        timeout_seconds: float | None,
        payload: SSHIntegrationInput,
        closer: _ChannelCloser,
        sinks: tuple[_StreamSink, _StreamSink],
        cancel_command: str | None,
    ) -> tuple[str, str, int]:
        """Run ``command`` and return (stdout, stderr, exit_code), pumping both streams.

        stdout and stderr are drained concurrently on two daemon threads so a
        full window on one stream cannot stall the other. Each chunk is handed
        to its sink, which awaits the streaming callback. Non-zero remote exit
        codes are surfaced through the tuple instead of being converted to
        :class:`UpstreamError`. Authentication, host-key, and transport-level
        failures still raise. Stderr is passed through
        :func:`redact_command_line` before being returned so inline secrets
        remain masked at the C6 boundary.

        If the command started and did not complete (cancel, timeout, callback
        failure), the channel is closed and ``cancel_command`` is run on a fresh
        exec channel to stop the remote process group.
        """
        started = False
        completed = False
        try:
            _, stdout, _ = client.exec_command(command)
            chan = stdout.channel
            started = True
            closer.register(chan)
            # IDLE timeout: paramiko resets the timer on every recv() so a
            # slow-but-steady stream (dissect on a huge disk) never trips it.
            # A genuine hang (zero bytes for N seconds) raises
            # builtins.TimeoutError which we translate into the platform
            # AILATimeoutError. Identical semantics to _exec_command.
            if timeout_seconds is not None:
                chan.settimeout(timeout_seconds)
            try:
                stdout_outcome = _ReadOutcome()
                stderr_outcome = _ReadOutcome()
                readers = (
                    threading.Thread(
                        target=_drain,
                        args=(chan.recv, sinks[0], stdout_outcome, closer),
                        daemon=True,
                    ),
                    threading.Thread(
                        target=_drain,
                        args=(chan.recv_stderr, sinks[1], stderr_outcome, closer),
                        daemon=True,
                    ),
                )
                for reader in readers:
                    reader.start()
                for reader in readers:
                    reader.join()
                for outcome in (stdout_outcome, stderr_outcome):
                    if outcome.error is not None:
                        raise outcome.error
                # Streams have closed. Poll for exit status with a tight
                # 30s grace so a detached child that closed stdout without
                # exiting cannot hang the caller indefinitely.
                grace_deadline = time.monotonic() + 30.0
                while not chan.exit_status_ready():
                    if closer.closed:
                        raise CommandCancelledError(
                            f"SSH command for {payload.name} ({payload.host}) was cancelled; "
                            "its channel was closed before an exit status arrived."
                        )
                    if time.monotonic() > grace_deadline:
                        raise AILATimeoutError(
                            f"SSH command for {payload.name} ({payload.host}) closed "
                            f"its streams but did not emit an exit status within 30s "
                            f"(command likely detached a child). Command: {redact_command_line(command)[:200]}"
                        )
                    time.sleep(0.1)
                exit_code = chan.recv_exit_status()
            except builtins.TimeoutError as exc:
                raise AILATimeoutError(
                    f"SSH command for {payload.name} ({payload.host}) idle "
                    f">{timeout_seconds}s with no output. Command: {redact_command_line(command)[:200]}"
                ) from exc
            completed = True
            return stdout_outcome.text, redact_command_line(stderr_outcome.text), exit_code
        except paramiko.AuthenticationException as exc:
            raise AuthenticationError(
                f"SSH authentication failed for {payload.name} ({payload.username}@{payload.host}:{payload.port}). "
                "Verify the username and the configured stored password or private key."
            ) from exc
        except paramiko.BadHostKeyException as exc:
            raise UpstreamError(
                f"SSH host key verification failed for {payload.name} ({payload.host}). "
                "The server host key did not match the trusted known_hosts entry."
            ) from exc
        except paramiko.SSHException as exc:
            message = str(exc)
            if "not found in known_hosts" in message.lower():
                raise UpstreamError(
                    f"SSH host key verification failed for {payload.name} ({payload.host}). "
                    "Add the host key to a trusted known_hosts file or configure known_hosts_path."
                ) from exc
            raise UpstreamError(f"SSH transport error for {payload.name} ({payload.host}): {message}") from exc
        finally:
            if started and not completed:
                if not closer.closed:
                    closer.close()
                if cancel_command is not None:
                    _kill_remote(client, cancel_command)

    @staticmethod
    def _exec_command(
        client: paramiko.SSHClient,
        command: str,
        timeout_seconds: float | None,
        payload: SSHIntegrationInput,
        closer: _ChannelCloser,
    ) -> str:
        try:
            _, stdout, stderr = client.exec_command(command)
            closer.register(stdout.channel)
            # `timeout_seconds` is an IDLE timeout applied to each recv() --
            # paramiko resets the timer every time data arrives, so a slow but
            # steady stream (dissect on a huge disk) never trips it. A genuine
            # hang (zero bytes for N seconds) raises builtins.TimeoutError.
            if timeout_seconds is not None:
                stdout.channel.settimeout(timeout_seconds)
            try:
                # Read first, exit-status second. Reversing this order (as the
                # original code did) can deadlock if the remote fills its stdout
                # buffer and waits for a reader before exiting.
                output = stdout.read().decode("utf-8", errors="ignore")
                error_output = stderr.read().decode("utf-8", errors="ignore")
                # Streams have closed -- the remote is either already exited or
                # imminent. Poll for exit status with a tight grace (30s) so we
                # don't hang forever on a detached child that closed stdout but
                # didn't actually exit.
                import time as _time
                grace_deadline = _time.monotonic() + 30.0
                while not stdout.channel.exit_status_ready():
                    if closer.closed:
                        raise UpstreamError(
                            f"SSH command for {payload.name} ({payload.host}) was cancelled; "
                            "its channel was closed before an exit status arrived."
                        )
                    if _time.monotonic() > grace_deadline:
                        raise AILATimeoutError(
                            f"SSH command for {payload.name} ({payload.host}) closed "
                            f"its streams but did not emit an exit status within 30s "
                            f"(command likely detached a child). Command: {redact_command_line(command)[:200]}"
                        )
                    _time.sleep(0.1)
                exit_code = stdout.channel.recv_exit_status()
            except builtins.TimeoutError as exc:
                raise AILATimeoutError(
                    f"SSH command for {payload.name} ({payload.host}) idle "
                    f">{timeout_seconds}s with no output. Command: {redact_command_line(command)[:200]}"
                ) from exc
            if exit_code != 0:
                redacted_stderr = redact_command_line(error_output)
                raise UpstreamError(
                    f"SSH command failed for {payload.name} ({payload.host}) with exit code {exit_code}: {redacted_stderr}"
                )
            return output
        except paramiko.AuthenticationException as exc:
            raise AuthenticationError(
                f"SSH authentication failed for {payload.name} ({payload.username}@{payload.host}:{payload.port}). "
                "Verify the username and the configured stored password or private key."
            ) from exc
        except paramiko.BadHostKeyException as exc:
            raise UpstreamError(
                f"SSH host key verification failed for {payload.name} ({payload.host}). "
                "The server host key did not match the trusted known_hosts entry."
            ) from exc
        except paramiko.SSHException as exc:
            message = str(exc)
            if "not found in known_hosts" in message.lower():
                raise UpstreamError(
                    f"SSH host key verification failed for {payload.name} ({payload.host}). "
                    "Add the host key to a trusted known_hosts file or configure known_hosts_path."
                ) from exc
            raise UpstreamError(f"SSH transport error for {payload.name} ({payload.host}): {message}") from exc

    async def upload_file(
        self,
        integration: dict | SSHIntegrationInput | RegisteredSystem,
        local_path: str | Path,
        remote_path: str,
        *,
        timeout_seconds: float | None = 120.0,
    ) -> None:
        """Upload a local file to the remote machine via SFTP.

        Uses the same credential resolution and host-key verification as
        ``run_command``.  Blocking paramiko I/O runs in a thread.
        """
        _reject_unsafe_path(remote_path, kind="remote")
        local_path = Path(local_path)
        if not local_path.is_file():
            raise ValidationError(f"Local file does not exist: {local_path}")

        if isinstance(integration, dict):
            payload = self._to_ssh_integration(RegisteredSystem.model_validate(integration))
        elif isinstance(integration, RegisteredSystem):
            payload = self._to_ssh_integration(integration)
        else:
            payload = integration

        password = await self._resolve_password(payload)
        connect_kwargs = await self._build_connect_kwargs(payload, password, 15.0)

        await asyncio.to_thread(
            self._upload_file_blocking, payload, str(local_path), remote_path,
            timeout_seconds, connect_kwargs,
        )

    def _upload_file_blocking(
        self,
        payload: SSHIntegrationInput,
        local_path: str,
        remote_path: str,
        timeout_seconds: float | None,
        connect_kwargs: dict,
    ) -> None:
        """Blocking SFTP upload -- runs inside asyncio.to_thread."""
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if payload.known_hosts_path:
            known_hosts_path = Path(payload.known_hosts_path).resolve()
            if not known_hosts_path.exists():
                raise ValidationError(f"Known hosts file {known_hosts_path} does not exist.")
            client.load_host_keys(str(known_hosts_path))
        # #42: reject unknown host keys on the upload surface too --
        # AutoAddPolicy on a fresh registration would let SFTP land on
        # a MITM host before the caller could ever compare fingerprints.
        _apply_host_key_policy(client, payload)
        try:
            client.connect(**connect_kwargs)
            SSHService._verify_fingerprint(client, payload)
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(60)
            sftp = client.open_sftp()
            try:
                if timeout_seconds is not None:
                    channel = sftp.get_channel()
                    if channel is not None:
                        channel.settimeout(timeout_seconds)
                sftp.put(local_path, remote_path)
            finally:
                sftp.close()
        except paramiko.AuthenticationException as exc:
            raise AuthenticationError(
                f"SSH authentication failed for {payload.name} ({payload.username}@{payload.host}:{payload.port})."
            ) from exc
        except paramiko.SSHException as exc:
            raise UpstreamError(f"SFTP upload failed for {payload.name} ({payload.host}): {exc}") from exc
        finally:
            client.close()

    async def download_file(
        self,
        integration: dict | SSHIntegrationInput | RegisteredSystem,
        remote_path: str,
        local_path: str | Path,
        *,
        timeout_seconds: float | None = 600.0,
    ) -> None:
        """Download a remote file to the local machine via SFTP.

        Counterpart to ``upload_file``. Used by collectors that need to run
        commands whose output exceeds paramiko's ~2 MB stdout window -- they
        redirect to a remote temp file and download it here instead of
        streaming stdout through the deadlock-prone channel path.
        """
        _reject_unsafe_path(remote_path, kind="remote")
        _reject_unsafe_path(str(local_path), kind="local")
        if isinstance(integration, dict):
            payload = self._to_ssh_integration(RegisteredSystem.model_validate(integration))
        elif isinstance(integration, RegisteredSystem):
            payload = self._to_ssh_integration(integration)
        else:
            payload = integration

        password = await self._resolve_password(payload)
        connect_kwargs = await self._build_connect_kwargs(payload, password, 15.0)

        await asyncio.to_thread(
            self._download_file_blocking, payload, remote_path, str(local_path), timeout_seconds, connect_kwargs
        )

    def _download_file_blocking(
        self,
        payload: SSHIntegrationInput,
        remote_path: str,
        local_path: str,
        timeout_seconds: float | None,
        connect_kwargs: dict,
    ) -> None:
        client = paramiko.SSHClient()
        # Load the OS-default known_hosts alongside any operator-declared
        # file so hosts an operator has previously trusted still connect
        # once reject-by-default is in effect (#42). The upload path and
        # both exec paths already do this; the download path used to
        # silently AutoAdd on first connect and skip the system file.
        client.load_system_host_keys()
        if payload.known_hosts_path:
            known_hosts_path = Path(payload.known_hosts_path)
            if not known_hosts_path.exists():
                raise ValidationError(f"Known hosts file {known_hosts_path} does not exist.")
            client.load_host_keys(str(known_hosts_path))
        # #42: reject unknown host keys on the download surface too --
        # a first-connect AutoAdd here would exfiltrate the remote
        # payload from a MITM host with the operator none the wiser.
        _apply_host_key_policy(client, payload)
        try:
            client.connect(**connect_kwargs)
            SSHService._verify_fingerprint(client, payload)
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(60)
            sftp = client.open_sftp()
            try:
                if timeout_seconds is not None:
                    channel = sftp.get_channel()
                    if channel is not None:
                        channel.settimeout(timeout_seconds)
                sftp.get(remote_path, local_path)
            finally:
                sftp.close()
        except paramiko.AuthenticationException as exc:
            raise AuthenticationError(
                f"SSH authentication failed for {payload.name} ({payload.username}@{payload.host}:{payload.port})."
            ) from exc
        except paramiko.SSHException as exc:
            raise UpstreamError(f"SFTP download failed for {payload.name} ({payload.host}): {exc}") from exc
        finally:
            client.close()

    @staticmethod
    def _verify_fingerprint(client: paramiko.SSHClient, payload: SSHIntegrationInput) -> None:
        """Verify the server's host key against the configured fingerprint."""
        if not payload.host_key_fingerprint:
            return
        transport = client.get_transport()
        if transport is None:
            raise UpstreamError(f"SSH transport for {payload.name} is not available after connection.")
        server_key = transport.get_remote_server_key()
        expected = payload.host_key_fingerprint.strip()
        if expected.startswith("SHA256:"):
            actual = SSHService._sha256_fingerprint(server_key)
            if actual != expected:
                raise UpstreamError(
                    f"SSH host key fingerprint mismatch for {payload.name} ({payload.host}). "
                    f"Expected {expected}, got {actual}."
                )
            return

        actual_md5 = SSHService._md5_fingerprint(server_key)
        normalized_expected = expected.lower().replace("-", ":")
        if ":" not in normalized_expected and len(normalized_expected) == 32:
            normalized_expected = ":".join(
                normalized_expected[index : index + 2] for index in range(0, len(normalized_expected), 2)
            )
        if actual_md5 != normalized_expected:
            raise UpstreamError(
                f"SSH host key fingerprint mismatch for {payload.name} ({payload.host}). "
                f"Expected {expected}, got {actual_md5}."
            )

    @staticmethod
    def _sha256_fingerprint(server_key) -> str:
        digest = hashlib.sha256(server_key.asbytes()).digest()
        encoded = base64.b64encode(digest).decode("ascii").rstrip("=")
        return f"SHA256:{encoded}"

    @staticmethod
    def _md5_fingerprint(server_key) -> str:
        digest = server_key.get_fingerprint().hex()
        return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))

    async def _resolve_password(self, payload: SSHIntegrationInput) -> str | None:
        """Load the SSH password from SecretStore if a password_secret_id is configured."""
        if payload.password_secret_id:
            async with async_session_scope(self.settings) as session:
                password = await self.secret_store.get_secret_by_id(session, payload.password_secret_id)
            if not password:
                raise ValidationError(f"Stored password secret {payload.password_secret_id} could not be loaded.")
            return password
        return None

    async def _resolve_private_key_material(
        self, payload: SSHIntegrationInput,
    ) -> tuple[str | None, str | None]:
        """Return ``(pem_text, passphrase)`` from SecretStore for ``payload``.

        Both values default to ``None`` when the corresponding secret id is
        unset. A configured id that resolves to no plaintext raises
        :class:`ValidationError`, mirroring :meth:`_resolve_password`.
        """
        pem: str | None = None
        passphrase: str | None = None
        needs = payload.private_key_secret_id or payload.private_key_passphrase_secret_id
        if not needs:
            return None, None
        async with async_session_scope(self.settings) as session:
            if payload.private_key_secret_id:
                pem = await self.secret_store.get_secret_by_id(
                    session, payload.private_key_secret_id,
                )
                if not pem:
                    raise ValidationError(
                        f"Stored private-key secret {payload.private_key_secret_id} could not be loaded.",
                    )
            if payload.private_key_passphrase_secret_id:
                passphrase = await self.secret_store.get_secret_by_id(
                    session, payload.private_key_passphrase_secret_id,
                )
                if not passphrase:
                    raise ValidationError(
                        f"Stored private-key passphrase secret {payload.private_key_passphrase_secret_id} could not be loaded.",
                    )
        return pem, passphrase

    @staticmethod
    def _parse_private_key(pem: str, passphrase: str | None) -> paramiko.PKey:
        """Parse a PEM/OpenSSH private key blob into a paramiko ``PKey``.

        Tries the base ``PKey.from_private_key`` auto-detector first, then
        falls back through the concrete key classes in the order most
        common on modern hosts (Ed25519, RSA, ECDSA, DSS). Every parser
        gets a fresh ``StringIO`` cursor -- ``from_private_key`` reads to
        EOF and does not rewind.

        Raises :class:`AuthenticationError` when every parser rejects the
        material: either the passphrase is wrong or the blob is not one
        of the four key formats paramiko understands. The narrow
        ``(paramiko.SSHException, ValueError)`` catch keeps genuine
        programming errors (``TypeError``, ``AttributeError``, ...)
        surfacing untouched.
        """
        # ``DSSKey`` was removed from paramiko 5.x; append it only when
        # the running paramiko still exposes it so operators on either
        # side of that boundary get the same behaviour without a hard
        # ``AttributeError`` at import.
        parsers: list = [
            paramiko.PKey,
            paramiko.Ed25519Key,
            paramiko.RSAKey,
            paramiko.ECDSAKey,
        ]
        dss_key_cls = getattr(paramiko, "DSSKey", None)
        if dss_key_cls is not None:
            parsers.append(dss_key_cls)
        password = passphrase or None
        last_exc: Exception | None = None
        for parser in parsers:
            try:
                return parser.from_private_key(io.StringIO(pem), password=password)
            except (paramiko.SSHException, ValueError, TypeError) as exc:
                # ``TypeError`` narrowly covers the paramiko 5.x quirk
                # where ``PKey.from_private_key`` (the auto-detecting
                # base call) forwards ``file_obj`` to a subclass
                # ``__init__`` that never accepted it. Falling through
                # to the concrete key classes still works there.
                last_exc = exc
                continue
        raise AuthenticationError(
            "private key could not be decrypted -- wrong passphrase or unsupported key format",
        ) from last_exc

    async def _build_connect_kwargs(
        self,
        payload: SSHIntegrationInput,
        password: str | None,
        connect_timeout: float,
    ) -> dict:
        """Assemble the ``paramiko.SSHClient.connect`` kwargs for ``payload``.

        Single source of truth for the four SSH surfaces (exec, exec-full,
        upload, download) -- historically each site inlined its own
        password/key-file plumbing, so a change to key handling had to be
        applied in four places and any drift silently degraded that one
        surface. Contract:

        * ``pkey`` takes priority: when ``private_key_secret_id`` resolves
          to PEM material we parse it here and hand paramiko a ready
          ``PKey``. This is the pasted-key path.
        * ``key_filename`` is the legacy on-disk fallback used when only
          ``private_key_path`` is set. Paramiko honours ``passphrase``
          alongside ``key_filename`` to decrypt encrypted key files, so
          we pass both.
        * ``password`` is set when :meth:`_resolve_password` produced one.
        """
        pem, passphrase = await self._resolve_private_key_material(payload)
        connect_kwargs: dict = {
            "hostname": payload.host,
            "port": payload.port,
            "username": payload.username,
            "timeout": connect_timeout,
        }
        if pem:
            connect_kwargs["pkey"] = self._parse_private_key(pem, passphrase)
        elif payload.private_key_path:
            connect_kwargs["key_filename"] = payload.private_key_path
            if passphrase:
                connect_kwargs["passphrase"] = passphrase
        if password:
            connect_kwargs["password"] = password
        return connect_kwargs

    @staticmethod
    def _to_ssh_integration(system: RegisteredSystem) -> SSHIntegrationInput:
        return SSHIntegrationInput(
            name=system.name,
            host=system.host,
            username=system.username,
            port=system.port,
            distro=system.distro,
            description=system.description,
            private_key_path=system.private_key_path,
            private_key_secret_id=system.private_key_secret_id,
            private_key_passphrase_secret_id=system.private_key_passphrase_secret_id,
            password_secret_id=system.password_secret_id,
            known_hosts_path=system.known_hosts_path,
            host_key_fingerprint=system.host_key_fingerprint,
        )
