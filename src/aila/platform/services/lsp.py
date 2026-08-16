"""Platform LSP subsystem (issue #154) -- LSP-guided retrieval alongside
the graph + semantic stack.

Fronts off-the-shelf language servers (pyright + gopls today; more
languages plug in by extending :data:`LANGUAGE_SPECS`) per indexed root
and exposes the four core operations the platform tool layer publishes
as ``lsp.definition`` / ``lsp.references`` / ``lsp.hover`` /
``lsp.diagnostics``:

* :meth:`LspService.definition` -- ``textDocument/definition`` for the
  symbol under ``file`` + ``line`` + ``character``.
* :meth:`LspService.references` -- ``textDocument/references`` with
  ``includeDeclaration=True`` by default.
* :meth:`LspService.hover` -- ``textDocument/hover`` returning the
  server's rendered signature / documentation blob.
* :meth:`LspService.diagnostics` -- collects the latest
  ``textDocument/publishDiagnostics`` push for the requested file,
  waiting up to a bounded window for the server to finish the initial
  scan after ``textDocument/didOpen``.

Design principles:

* **Fail-open.** A missing binary, a dead process, or a per-request
  timeout NEVER raises through the public API. The caller sees a
  typed :class:`LspResult` with ``status == "unavailable"`` and an
  empty payload. Callers must be able to run with LSP disabled or
  the binaries absent without any code path change.
* **Bounded lifecycle.** One server process per ``(root, language)``.
  The service caches handles across calls (LSP startup is expensive,
  typically 1-5 s) and stops them on :meth:`close` / interpreter
  exit. A crashed server is detected on the next request; the handle
  is dropped and the caller sees ``unavailable`` on that call, then
  the next call re-launches.
* **No third-party dep.** Speaks LSP JSON-RPC directly over the
  server's stdio (Content-Length framed). Reads run on a dedicated
  reader thread so the subprocess I/O works under every event-loop
  policy the codebase supports on Windows and Linux.
* **Gate behind a flag.** ``platform.lsp_enabled`` defaults False,
  so a fresh install is byte-identical to the pre-issue-#154 path.
  Flip it via ``PUT /config/platform/lsp_enabled`` or the
  ``AILA_PLATFORM_LSP_ENABLED`` env var; the flip lands on the next
  request without a worker restart.
* **No new table.** Observations land in the shared knowledge store
  through :func:`aila.platform.agents.observation.record_observation`
  under ``{module}.observation.workspace.{workspace_id}`` with kinds
  ``lsp.definition`` / ``lsp.references`` / ``lsp.hover`` /
  ``lsp.diagnostics``. The tool layer is the single writer; this
  module owns transport and lifecycle only.
"""

from __future__ import annotations

import asyncio
import atexit
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
import weakref
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from aila.storage.registry import ConfigRegistry

__all__ = [
    "LANGUAGE_SPECS",
    "LanguageSpec",
    "LspResult",
    "LspService",
    "get_lsp_service",
    "language_for_path",
    "reset_lsp_service",
]

_log = logging.getLogger(__name__)

# Sanctioned exception tuple for the fail-open surface. Every path that
# can be provoked by an absent binary, a broken pipe, a killed child, a
# malformed frame, or a torn-down subprocess collapses to a typed
# unavailable result. Broader errors (programming faults, KeyboardInterrupt,
# SystemExit) are intentionally NOT caught.
_LSP_FAIL_OPEN = (
    OSError,
    subprocess.SubprocessError,
    BrokenPipeError,
    ConnectionError,
    TimeoutError,
    ValueError,
    RuntimeError,
    json.JSONDecodeError,
)


@dataclass(frozen=True, slots=True)
class LanguageSpec:
    """Static declaration of one language + its LSP server binary.

    ``binary`` is the executable name (or absolute path) resolved via
    :func:`shutil.which` at spawn time; ``args`` is the argv tail
    appended after the binary; ``language_id`` is the LSP
    ``TextDocumentItem.languageId`` string the server expects (per
    LSP spec, e.g. ``"python"``, ``"go"``, ``"typescript"``).

    ``extensions`` is the tuple of lower-case file suffixes that route
    to this language. Path routing walks the map in registration
    order and returns the first suffix match. A path with an
    unrecognised extension is ``unavailable``.

    ``config_key`` names the ConfigRegistry key (under the ``platform``
    namespace) an operator sets to override the default binary path
    without touching env vars. The service reads it at spawn time.
    """

    name: str
    language_id: str
    binary: str
    args: tuple[str, ...]
    extensions: tuple[str, ...]
    config_key: str


LANGUAGE_SPECS: tuple[LanguageSpec, ...] = (
    LanguageSpec(
        name="python",
        language_id="python",
        # pyright ships the LSP entry as ``pyright-langserver``. Some
        # distributions install the compiled binary as ``pyright``
        # (no separate langserver script) -- an operator on that
        # distribution overrides ``platform.lsp_pyright_bin``.
        binary="pyright-langserver",
        args=("--stdio",),
        extensions=(".py", ".pyi"),
        config_key="lsp_pyright_bin",
    ),
    LanguageSpec(
        name="go",
        language_id="go",
        binary="gopls",
        args=("serve",),
        extensions=(".go",),
        config_key="lsp_gopls_bin",
    ),
)


def language_for_path(path: str | Path) -> LanguageSpec | None:
    """Return the :class:`LanguageSpec` that owns ``path`` by extension.

    Returns ``None`` when no language claims the suffix, so a caller can
    short-circuit to an unavailable result without spawning anything.
    Case-insensitive: ``.Py`` and ``.PY`` both route to python.
    """
    suffix = Path(path).suffix.lower()
    if not suffix:
        return None
    for spec in LANGUAGE_SPECS:
        if suffix in spec.extensions:
            return spec
    return None


@dataclass(slots=True)
class LspResult:
    """Typed result envelope returned by every public :class:`LspService`
    entry point.

    ``status`` values:

    * ``"ok"`` -- the request completed; ``payload`` carries the
      normalised body (see per-op contracts below).
    * ``"unavailable"`` -- the flag is off, the binary is missing,
      the server never started, the process died mid-request, or
      the request timed out. ``payload`` is a body-empty default;
      ``reason`` names the specific unavailability cause for
      operator debugging without leaking a traceback.
    * ``"empty"`` -- the server returned cleanly with no result
      (undefined symbol, no references, no hover, no diagnostics).
      ``payload`` is the body-empty default.

    Per-op ``payload`` shape:

    * ``definition`` / ``references`` -- ``{"locations": [Location, ...]}``.
    * ``hover`` -- ``{"contents": "<rendered markdown or plain text>"}``.
    * ``diagnostics`` -- ``{"diagnostics": [Diagnostic, ...]}``.

    Each ``Location`` is ``{"uri", "path", "range": {"start", "end"}}``
    with LSP ``Position`` objects. Each ``Diagnostic`` is the raw LSP
    diagnostic dict (``range``, ``severity``, ``message``, ``source``,
    ``code``).
    """

    status: str
    op: str
    language: str
    payload: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "op": self.op,
            "language": self.language,
            "payload": self.payload,
            "reason": self.reason,
            "elapsed_ms": self.elapsed_ms,
        }


def _pack_message(message: dict[str, Any]) -> bytes:
    """Encode a JSON-RPC message with the LSP Content-Length header."""
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body


def _read_message(stream: Any) -> dict[str, Any] | None:
    """Read one Content-Length framed JSON-RPC message from ``stream``.

    Returns ``None`` on EOF or when the header block terminates
    without producing a valid message; raises ``json.JSONDecodeError``
    on a malformed body so the reader thread degrades the server.
    """
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None
        # A CRLF terminates the header block. Some servers emit LF only.
        stripped = line.rstrip(b"\r\n")
        if not stripped:
            break
        try:
            name, _, value = stripped.decode("ascii").partition(":")
        except UnicodeDecodeError:
            continue
        headers[name.strip().lower()] = value.strip()
    length_raw = headers.get("content-length")
    if length_raw is None:
        return None
    try:
        length = int(length_raw)
    except ValueError:
        _log.debug("lsp: malformed Content-Length header %r", length_raw)
        return None
    if length <= 0:
        return None
    body = stream.read(length)
    if not body or len(body) < length:
        return None
    return json.loads(body.decode("utf-8"))


class _LspServer:
    """One LSP server child process bound to a (root, language) pair.

    Instances are lazy: :meth:`ensure_started` handshakes on first use
    and reuses the child on later requests. All public methods are
    fail-open: an unresolvable binary, a dead child, a broken pipe,
    or a per-request timeout returns ``None`` (definition/references/
    hover) or ``[]`` (diagnostics) and marks the handle dead so the
    parent :class:`LspService` drops the entry and re-launches on the
    next request.
    """

    def __init__(
        self,
        *,
        root: Path,
        spec: LanguageSpec,
        binary_path: str,
        request_timeout_s: float,
        startup_timeout_s: float,
        diagnostics_wait_s: float,
    ) -> None:
        self._root = root
        self._spec = spec
        self._binary_path = binary_path
        self._request_timeout_s = max(0.5, float(request_timeout_s))
        self._startup_timeout_s = max(1.0, float(startup_timeout_s))
        self._diagnostics_wait_s = max(0.0, float(diagnostics_wait_s))

        self._process: subprocess.Popen[bytes] | None = None
        self._write_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._responses_cv = threading.Condition()
        self._responses: dict[int, dict[str, Any]] = {}
        self._diagnostics_cv = threading.Condition()
        self._diagnostics: dict[str, list[dict[str, Any]]] = {}
        self._diagnostics_seen: set[str] = set()
        self._opened: set[str] = set()
        self._next_id = 1
        self._reader_thread: threading.Thread | None = None
        self._started = False
        self._dead = False
        self._dead_reason = ""

    # ---- lifecycle ------------------------------------------------------

    @property
    def dead(self) -> bool:
        return self._dead

    @property
    def dead_reason(self) -> str:
        return self._dead_reason

    def _mark_dead(self, reason: str) -> None:
        with self._state_lock:
            if self._dead:
                return
            self._dead = True
            self._dead_reason = reason
        # Wake anyone blocked on a response so the timeout path returns.
        with self._responses_cv:
            self._responses_cv.notify_all()
        with self._diagnostics_cv:
            self._diagnostics_cv.notify_all()

    def ensure_started(self) -> bool:
        """Spawn the child and finish the LSP initialise handshake.

        Returns ``True`` on success, ``False`` on any failure (missing
        binary, spawn error, timed-out or errored ``initialize``).
        Idempotent: subsequent calls return the cached started state.
        """
        with self._state_lock:
            if self._started:
                return not self._dead
            if self._dead:
                return False
        try:
            self._spawn()
            self._handshake()
        except _LSP_FAIL_OPEN as exc:
            self._mark_dead(f"start-failed: {exc.__class__.__name__}: {exc}")
            self._kill_child()
            _log.warning(
                "lsp server (%s, %s) start failed: %s",
                self._spec.name, self._root, exc,
            )
            return False
        with self._state_lock:
            self._started = True
        return True

    def _spawn(self) -> None:
        argv = [self._binary_path, *self._spec.args]
        # LSP servers close on stdin EOF, so the child is bound to this
        # parent process's lifetime. We keep stdout as bytes so the
        # Content-Length framing is exact on Windows (text mode would
        # translate CRLF -> LF and desynchronise the length).
        creationflags = 0
        startupinfo = None
        if sys.platform == "win32":
            # Suppress the console window a langserver would otherwise
            # pop up on a headless worker.
            creationflags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
            startupinfo = subprocess.STARTUPINFO()  # type: ignore[attr-defined]
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # type: ignore[attr-defined]
        env = os.environ.copy()
        self._process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(self._root),
            env=env,
            bufsize=0,
            creationflags=creationflags,
            startupinfo=startupinfo,
        )
        reader = threading.Thread(
            target=self._reader_loop,
            name=f"lsp-reader-{self._spec.name}",
            daemon=True,
        )
        self._reader_thread = reader
        reader.start()
        stderr_thread = threading.Thread(
            target=self._stderr_drain,
            name=f"lsp-stderr-{self._spec.name}",
            daemon=True,
        )
        stderr_thread.start()

    def _handshake(self) -> None:
        # LSP initialize -- rootUri is required; capabilities is a
        # deliberately minimal client declaration (definition, references,
        # hover, publishDiagnostics). Servers gate feature emission by
        # what the client advertises here.
        root_uri = _path_to_uri(self._root)
        params: dict[str, Any] = {
            "processId": os.getpid(),
            "clientInfo": {"name": "aila-platform-lsp", "version": "1"},
            "locale": "en",
            "rootUri": root_uri,
            "rootPath": str(self._root),
            "workspaceFolders": [{"uri": root_uri, "name": self._root.name or "root"}],
            "capabilities": {
                "textDocument": {
                    "synchronization": {
                        "dynamicRegistration": False,
                        "willSave": False,
                        "willSaveWaitUntil": False,
                        "didSave": False,
                    },
                    "definition": {"linkSupport": False},
                    "references": {"dynamicRegistration": False},
                    "hover": {"contentFormat": ["markdown", "plaintext"]},
                    "publishDiagnostics": {"relatedInformation": True},
                    # LSP 3.17 pull-based diagnostics -- the primary
                    # path for servers that only emit on request
                    # (recent pyright / gopls). The push-based
                    # ``publishDiagnostics`` fallback still runs
                    # when the server sends unsolicited pushes.
                    "diagnostic": {
                        "dynamicRegistration": False,
                        "relatedDocumentSupport": False,
                    },
                },
                "workspace": {
                    "workspaceFolders": True,
                    "configuration": True,
                },
            },
            "initializationOptions": {},
        }
        # Wait a bit longer than a normal request for the initial scan
        # some servers do inside initialize.
        response = self._request_sync(
            "initialize", params, timeout_s=self._startup_timeout_s,
        )
        if response is None:
            raise TimeoutError("initialize timed out")
        if "error" in response:
            raise RuntimeError(f"initialize error: {response['error']}")
        self._notify("initialized", {})

    def close(self) -> None:
        """Send ``shutdown``/``exit`` and reap the child, best-effort."""
        with self._state_lock:
            if self._dead and self._process is None:
                return
        try:
            if self._process is not None and self._process.poll() is None:
                # Best-effort graceful stop; hard-kill on timeout.
                try:
                    self._request_sync("shutdown", None, timeout_s=1.5)
                except _LSP_FAIL_OPEN:
                    pass
                try:
                    self._notify("exit", None)
                except _LSP_FAIL_OPEN:
                    pass
        finally:
            self._kill_child()
            self._mark_dead("closed")

    def _kill_child(self) -> None:
        proc = self._process
        if proc is None:
            return
        try:
            proc.terminate()
        except _LSP_FAIL_OPEN:
            pass
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except _LSP_FAIL_OPEN:
                pass
        # Drain the reader pipes so the daemon thread can exit; ignore
        # any errors on a torn-down handle.
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe is None:
                continue
            try:
                pipe.close()
            except _LSP_FAIL_OPEN:
                pass

    # ---- reader / dispatch ---------------------------------------------

    def _reader_loop(self) -> None:
        proc = self._process
        if proc is None or proc.stdout is None:
            return
        try:
            while True:
                if proc.poll() is not None:
                    break
                message = _read_message(proc.stdout)
                if message is None:
                    break
                self._dispatch(message)
        except _LSP_FAIL_OPEN as exc:
            self._mark_dead(f"reader: {exc.__class__.__name__}: {exc}")
            return
        # Reader hit EOF -- the child exited.
        code = proc.returncode if proc.returncode is not None else "unknown"
        self._mark_dead(f"child exited (rc={code})")

    def _stderr_drain(self) -> None:
        proc = self._process
        if proc is None or proc.stderr is None:
            return
        try:
            for raw in iter(proc.stderr.readline, b""):
                line = raw.decode("utf-8", errors="replace").rstrip()
                if line:
                    _log.debug("lsp[%s] stderr: %s", self._spec.name, line)
        except _LSP_FAIL_OPEN as exc:
            _log.debug("lsp[%s] stderr drain ended: %s", self._spec.name, exc)
            return

    def _dispatch(self, message: dict[str, Any]) -> None:
        if "id" in message and ("result" in message or "error" in message):
            msg_id = message["id"]
            try:
                key = int(msg_id)
            except (TypeError, ValueError):
                _log.debug("lsp: non-integer JSON-RPC id %r; dropping", msg_id)
                return
            with self._responses_cv:
                self._responses[key] = message
                self._responses_cv.notify_all()
            return
        method = message.get("method")
        if method == "textDocument/publishDiagnostics":
            params = message.get("params") or {}
            uri = params.get("uri")
            if isinstance(uri, str):
                diags_raw = params.get("diagnostics") or []
                diags = [d for d in diags_raw if isinstance(d, dict)]
                with self._diagnostics_cv:
                    self._diagnostics[uri] = diags
                    self._diagnostics_seen.add(uri)
                    self._diagnostics_cv.notify_all()
            return
        # Some servers issue reverse-request calls (workspace/configuration,
        # workspace/applyEdit). Answer the ones we must (respond with a
        # null result); ignore notifications.
        if "id" in message and "method" in message:
            self._respond_null(message["id"])

    def _respond_null(self, request_id: Any) -> None:
        response = {"jsonrpc": "2.0", "id": request_id, "result": None}
        try:
            self._write(response)
        except _LSP_FAIL_OPEN as exc:
            self._mark_dead(f"reverse-respond: {exc.__class__.__name__}")

    # ---- write path -----------------------------------------------------

    def _write(self, message: dict[str, Any]) -> None:
        proc = self._process
        if proc is None or proc.stdin is None:
            raise BrokenPipeError("child stdin unavailable")
        payload = _pack_message({"jsonrpc": "2.0", **message})
        with self._write_lock:
            proc.stdin.write(payload)
            proc.stdin.flush()

    def _notify(self, method: str, params: Any) -> None:
        self._write({"method": method, "params": params})

    def _next_request_id(self) -> int:
        with self._state_lock:
            rid = self._next_id
            self._next_id += 1
            return rid

    def _request_sync(
        self, method: str, params: Any, *, timeout_s: float,
    ) -> dict[str, Any] | None:
        if self._dead:
            return None
        request_id = self._next_request_id()
        try:
            self._write({"id": request_id, "method": method, "params": params})
        except _LSP_FAIL_OPEN as exc:
            self._mark_dead(f"write: {exc.__class__.__name__}: {exc}")
            return None
        deadline = time.monotonic() + max(0.1, timeout_s)
        with self._responses_cv:
            while True:
                response = self._responses.pop(request_id, None)
                if response is not None:
                    return response
                if self._dead:
                    return None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._responses_cv.wait(timeout=remaining)

    # ---- textDocument sync ---------------------------------------------

    def ensure_open(self, path: Path) -> bool:
        uri = _path_to_uri(path)
        if uri in self._opened:
            return True
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except _LSP_FAIL_OPEN as exc:
            _log.debug("lsp: cannot read %s: %s", path, exc)
            return False
        params = {
            "textDocument": {
                "uri": uri,
                "languageId": self._spec.language_id,
                "version": 1,
                "text": text,
            },
        }
        try:
            self._notify("textDocument/didOpen", params)
        except _LSP_FAIL_OPEN as exc:
            self._mark_dead(f"didOpen: {exc.__class__.__name__}: {exc}")
            return False
        self._opened.add(uri)
        return True

    # ---- public request surface (returns raw response or None) ---------

    def request(
        self, method: str, params: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Send ``method`` and return the response body (``result``).

        Returns ``None`` on timeout, transport error, or a JSON-RPC
        error envelope. NEVER raises; every failure path marks the
        server dead so the parent service drops the handle.
        """
        response = self._request_sync(
            method, params, timeout_s=self._request_timeout_s,
        )
        if response is None:
            return None
        if "error" in response:
            _log.debug(
                "lsp[%s] %s error: %s",
                self._spec.name, method, response["error"],
            )
            return None
        return response.get("result")

    def wait_for_diagnostics(
        self, uri: str, *, wait_s: float | None = None,
    ) -> list[dict[str, Any]]:
        """Return the latest ``publishDiagnostics`` payload for ``uri``.

        Blocks up to ``wait_s`` (defaults to :attr:`_diagnostics_wait_s`)
        waiting for the FIRST push after ``didOpen`` when none has
        arrived yet -- most servers push once as soon as the initial
        scan completes. If a push has already been observed, returns
        it immediately even if newer material would still arrive.
        """
        window = wait_s if wait_s is not None else self._diagnostics_wait_s
        deadline = time.monotonic() + max(0.0, float(window))
        with self._diagnostics_cv:
            while True:
                if uri in self._diagnostics_seen:
                    return list(self._diagnostics.get(uri, []))
                if self._dead:
                    return []
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return list(self._diagnostics.get(uri, []))
                self._diagnostics_cv.wait(timeout=remaining)


def _path_to_uri(path: Path) -> str:
    """Return the ``file://`` URI a LSP server expects for ``path``.

    :meth:`Path.as_uri` handles the drive-letter + backslash quirks on
    Windows and the POSIX case on Linux/macOS. The parent :class:`Path`
    is resolved first so a relative ``.`` never leaks into the URI.
    """
    return path.resolve().as_uri()


def _uri_to_path(uri: str) -> str:
    """Return a filesystem path for a ``file://`` URI, best-effort."""
    if not uri.startswith("file://"):
        return uri
    parsed = urlparse(uri)
    raw = unquote(parsed.path or "")
    # On Windows, an absolute path arrives as "/C:/..." -- strip the
    # leading slash so ``Path`` sees the drive letter as the anchor.
    if sys.platform == "win32" and len(raw) >= 3 and raw[0] == "/" and raw[2] == ":":
        raw = raw[1:]
    return raw


def _normalise_location(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalise one LSP ``Location`` / ``LocationLink`` into a stable dict."""
    uri = raw.get("uri") or raw.get("targetUri")
    if not isinstance(uri, str):
        return {}
    range_obj = (
        raw.get("range")
        or raw.get("targetSelectionRange")
        or raw.get("targetRange")
        or {}
    )
    return {
        "uri": uri,
        "path": _uri_to_path(uri),
        "range": range_obj if isinstance(range_obj, dict) else {},
    }


def _normalise_hover_contents(contents: Any) -> str:
    """Flatten the many hover-body shapes servers emit into a single string."""
    if contents is None:
        return ""
    if isinstance(contents, str):
        return contents
    if isinstance(contents, dict):
        value = contents.get("value")
        if isinstance(value, str):
            return value
        return ""
    if isinstance(contents, list):
        parts: list[str] = []
        for item in contents:
            piece = _normalise_hover_contents(item)
            if piece:
                parts.append(piece)
        return "\n\n".join(parts)
    return ""


class LspService:
    """Public LSP subsystem entry point.

    A single instance manages every ``(root, language)`` server. Reads
    all config through the injected :class:`ConfigRegistry` on every
    call, so an operator PUT /config edit lands on the next request.
    """

    def __init__(
        self,
        *,
        registry: ConfigRegistry | None = None,
        which: Callable[[str], str | None] = shutil.which,
    ) -> None:
        self._registry = registry
        self._which = which
        self._servers_lock = threading.Lock()
        self._servers: dict[tuple[str, str], _LspServer] = {}
        # atexit hook -- best-effort process cleanup on interpreter exit.
        # Weak reference so a dropped service does not leak a callback.
        weak_self = weakref.ref(self)

        def _atexit_close() -> None:
            live = weak_self()
            if live is not None:
                live.close()

        atexit.register(_atexit_close)

    # ---- config -------------------------------------------------------

    async def _load_config(self) -> dict[str, Any]:
        registry = self._registry or ConfigRegistry()

        async def _get(key: str, default: Any) -> Any:
            try:
                raw = await registry.get("platform", key)
            except _LSP_FAIL_OPEN as exc:
                _log.debug("lsp: config read %s failed: %s", key, exc)
                return default
            if raw is None:
                return default
            return raw

        enabled_raw = await _get("lsp_enabled", False)
        enabled = (
            bool(enabled_raw) if isinstance(enabled_raw, bool)
            else str(enabled_raw).strip().lower() in ("1", "true", "yes", "on")
        )
        try:
            request_timeout_s = float(await _get("lsp_request_timeout_s", 15.0))
        except (TypeError, ValueError):
            request_timeout_s = 15.0
        try:
            startup_timeout_s = float(await _get("lsp_startup_timeout_s", 30.0))
        except (TypeError, ValueError):
            startup_timeout_s = 30.0
        try:
            diagnostics_wait_s = float(await _get("lsp_diagnostics_wait_s", 3.0))
        except (TypeError, ValueError):
            diagnostics_wait_s = 3.0

        binaries: dict[str, str] = {}
        for spec in LANGUAGE_SPECS:
            raw = await _get(spec.config_key, spec.binary)
            binaries[spec.name] = str(raw).strip() or spec.binary

        return {
            "enabled": enabled,
            "request_timeout_s": max(0.5, request_timeout_s),
            "startup_timeout_s": max(1.0, startup_timeout_s),
            "diagnostics_wait_s": max(0.0, diagnostics_wait_s),
            "binaries": binaries,
        }

    # ---- server acquisition -------------------------------------------

    def _acquire_server(
        self,
        *,
        root: Path,
        spec: LanguageSpec,
        cfg: Mapping[str, Any],
    ) -> _LspServer | tuple[None, str]:
        """Return a started :class:`_LspServer` or a ``(None, reason)`` tuple.

        The tuple form encodes the unavailability cause an ``LspResult``
        surfaces to the caller.
        """
        binary_hint = cfg["binaries"].get(spec.name) or spec.binary
        resolved = self._which(binary_hint)
        if resolved is None and Path(binary_hint).is_absolute():
            resolved = binary_hint if Path(binary_hint).exists() else None
        if resolved is None:
            return (None, f"binary-not-found: {binary_hint}")

        try:
            root_resolved = root.resolve()
        except _LSP_FAIL_OPEN as exc:
            return (None, f"root-resolve-failed: {exc}")
        key = (str(root_resolved), spec.name)
        with self._servers_lock:
            server = self._servers.get(key)
            if server is not None and server.dead:
                del self._servers[key]
                server = None
            if server is None:
                server = _LspServer(
                    root=root_resolved,
                    spec=spec,
                    binary_path=resolved,
                    request_timeout_s=cfg["request_timeout_s"],
                    startup_timeout_s=cfg["startup_timeout_s"],
                    diagnostics_wait_s=cfg["diagnostics_wait_s"],
                )
                self._servers[key] = server
        if not server.ensure_started():
            with self._servers_lock:
                self._servers.pop(key, None)
            return (None, f"server-start-failed: {server.dead_reason or 'unknown'}")
        return server

    # ---- public entry points ------------------------------------------

    async def definition(
        self, *, root: str | Path, file: str | Path,
        line: int, character: int,
    ) -> LspResult:
        return await self._locations_op(
            op="definition",
            method="textDocument/definition",
            root=root, file=file, line=line, character=character,
        )

    async def references(
        self, *, root: str | Path, file: str | Path,
        line: int, character: int, include_declaration: bool = True,
    ) -> LspResult:
        return await self._locations_op(
            op="references",
            method="textDocument/references",
            root=root, file=file, line=line, character=character,
            extra={"context": {"includeDeclaration": bool(include_declaration)}},
        )

    async def hover(
        self, *, root: str | Path, file: str | Path,
        line: int, character: int,
    ) -> LspResult:
        started = time.monotonic()
        prep = await self._prepare(root=root, file=file, op="hover")
        if isinstance(prep, LspResult):
            return prep
        server, path, spec = prep
        params = {
            "textDocument": {"uri": _path_to_uri(path)},
            "position": {"line": int(line), "character": int(character)},
        }
        # didOpen + hover both run on the shared reader/writer thread pool.
        raw = await asyncio.to_thread(self._hover_sync, server, path, params)
        elapsed_ms = (time.monotonic() - started) * 1000.0
        if raw is None:
            if server.dead:
                return _result(
                    "unavailable", "hover", spec.name,
                    reason=f"server-died: {server.dead_reason}",
                    elapsed_ms=elapsed_ms,
                )
            return _result(
                "empty", "hover", spec.name,
                payload={"contents": ""}, elapsed_ms=elapsed_ms,
            )
        contents = _normalise_hover_contents(raw.get("contents") if isinstance(raw, dict) else None)
        if not contents:
            return _result(
                "empty", "hover", spec.name,
                payload={"contents": ""}, elapsed_ms=elapsed_ms,
            )
        return _result(
            "ok", "hover", spec.name,
            payload={"contents": contents}, elapsed_ms=elapsed_ms,
        )

    async def diagnostics(
        self, *, root: str | Path, file: str | Path,
        wait_s: float | None = None,
    ) -> LspResult:
        started = time.monotonic()
        prep = await self._prepare(root=root, file=file, op="diagnostics")
        if isinstance(prep, LspResult):
            return prep
        server, path, spec = prep
        # Pull-based LSP 3.17 diagnostic request goes first -- modern
        # pyright / gopls only guarantee an answer here; push-based
        # ``publishDiagnostics`` may never fire without extra client
        # capabilities or workspace config. When the server does not
        # implement the pull method it responds with a JSON-RPC error
        # (returns None below); we then fall back to waiting for the
        # push channel we do capture.
        diags = await asyncio.to_thread(self._diagnostics_sync, server, path)
        if not diags:
            uri = _path_to_uri(path)
            diags = await asyncio.to_thread(
                server.wait_for_diagnostics, uri, wait_s=wait_s,
            )
        elapsed_ms = (time.monotonic() - started) * 1000.0
        if server.dead and not diags:
            return _result(
                "unavailable", "diagnostics", spec.name,
                reason=f"server-died: {server.dead_reason}",
                elapsed_ms=elapsed_ms,
            )
        if not diags:
            return _result(
                "empty", "diagnostics", spec.name,
                payload={"diagnostics": []}, elapsed_ms=elapsed_ms,
            )
        return _result(
            "ok", "diagnostics", spec.name,
            payload={"diagnostics": diags}, elapsed_ms=elapsed_ms,
        )

    @staticmethod
    def _diagnostics_sync(server: _LspServer, path: Path) -> list[dict[str, Any]]:
        if not server.ensure_open(path):
            return []
        params = {"textDocument": {"uri": _path_to_uri(path)}}
        raw = server.request("textDocument/diagnostic", params)
        if not isinstance(raw, dict):
            return []
        # LSP 3.17 DocumentDiagnosticReport shapes:
        #   full: { kind: "full", items: [Diagnostic, ...] }
        #   unchanged: { kind: "unchanged", resultId: ... } -- empty
        kind = raw.get("kind")
        if kind == "unchanged":
            return []
        items = raw.get("items")
        if not isinstance(items, list):
            return []
        return [d for d in items if isinstance(d, dict)]

    # ---- shared helpers ------------------------------------------------

    async def _prepare(
        self, *, root: str | Path, file: str | Path, op: str,
    ) -> tuple[_LspServer, Path, LanguageSpec] | LspResult:
        cfg = await self._load_config()
        if not cfg["enabled"]:
            return _result(
                "unavailable", op, "unknown", reason="flag-off",
            )
        file_path = Path(file)
        if not file_path.is_absolute():
            file_path = Path(root) / file_path
        spec = language_for_path(file_path)
        if spec is None:
            return _result(
                "unavailable", op, "unknown",
                reason=f"language-not-supported: {file_path.suffix or 'no-suffix'}",
            )
        if not file_path.exists():
            return _result(
                "unavailable", op, spec.name,
                reason=f"file-not-found: {file_path}",
            )
        acquired = self._acquire_server(root=Path(root), spec=spec, cfg=cfg)
        if isinstance(acquired, tuple):
            _, reason = acquired
            return _result("unavailable", op, spec.name, reason=reason)
        return acquired, file_path, spec

    async def _locations_op(
        self, *, op: str, method: str,
        root: str | Path, file: str | Path,
        line: int, character: int,
        extra: dict[str, Any] | None = None,
    ) -> LspResult:
        started = time.monotonic()
        prep = await self._prepare(root=root, file=file, op=op)
        if isinstance(prep, LspResult):
            return prep
        server, path, spec = prep
        params: dict[str, Any] = {
            "textDocument": {"uri": _path_to_uri(path)},
            "position": {"line": int(line), "character": int(character)},
        }
        if extra:
            params.update(extra)
        raw = await asyncio.to_thread(self._locations_sync, server, path, method, params)
        elapsed_ms = (time.monotonic() - started) * 1000.0
        if raw is None:
            if server.dead:
                return _result(
                    "unavailable", op, spec.name,
                    reason=f"server-died: {server.dead_reason}",
                    elapsed_ms=elapsed_ms,
                )
            return _result(
                "empty", op, spec.name,
                payload={"locations": []}, elapsed_ms=elapsed_ms,
            )
        locations = _flatten_locations(raw)
        if not locations:
            return _result(
                "empty", op, spec.name,
                payload={"locations": []}, elapsed_ms=elapsed_ms,
            )
        return _result(
            "ok", op, spec.name,
            payload={"locations": locations}, elapsed_ms=elapsed_ms,
        )

    @staticmethod
    def _locations_sync(
        server: _LspServer, path: Path, method: str, params: dict[str, Any],
    ) -> Any:
        if not server.ensure_open(path):
            return None
        return server.request(method, params)

    @staticmethod
    def _hover_sync(
        server: _LspServer, path: Path, params: dict[str, Any],
    ) -> Any:
        if not server.ensure_open(path):
            return None
        return server.request("textDocument/hover", params)

    # ---- introspection / lifecycle ------------------------------------

    def live_servers(self) -> list[dict[str, Any]]:
        """Return a snapshot of the currently spawned servers.

        Exposed for operator-facing status probes (readiness, admin
        surfaces) so a caller can enumerate ``(root, language)`` pairs
        without touching the internal dict.
        """
        with self._servers_lock:
            return [
                {
                    "root": root,
                    "language": language,
                    "dead": server.dead,
                    "reason": server.dead_reason,
                }
                for (root, language), server in self._servers.items()
            ]

    def close(self) -> None:
        """Shut down every managed server. Idempotent."""
        with self._servers_lock:
            servers = list(self._servers.values())
            self._servers.clear()
        for server in servers:
            try:
                server.close()
            except _LSP_FAIL_OPEN as exc:
                _log.debug("lsp: server close error: %s", exc)


def _flatten_locations(raw: Any) -> list[dict[str, Any]]:
    """Reduce the several LSP location response shapes to a plain list."""
    if raw is None:
        return []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, Sequence):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        loc = _normalise_location(item)
        if loc:
            out.append(loc)
    return out


def _result(
    status: str, op: str, language: str,
    *,
    payload: dict[str, Any] | None = None,
    reason: str = "",
    elapsed_ms: float = 0.0,
) -> LspResult:
    default_payload: dict[str, Any]
    if op in ("definition", "references"):
        default_payload = {"locations": []}
    elif op == "hover":
        default_payload = {"contents": ""}
    elif op == "diagnostics":
        default_payload = {"diagnostics": []}
    else:
        default_payload = {}
    return LspResult(
        status=status,
        op=op,
        language=language,
        payload=payload if payload is not None else default_payload,
        reason=reason,
        elapsed_ms=elapsed_ms,
    )


_singleton_lock = threading.Lock()
_singleton: LspService | None = None


def get_lsp_service(*, registry: ConfigRegistry | None = None) -> LspService:
    """Return the process-wide :class:`LspService` singleton.

    A caller that constructs its own registry may pass it once; later
    calls receive the cached instance regardless of the argument (so
    the singleton stays stable across the process). Test suites use
    :func:`reset_lsp_service` to drop the singleton between cases.
    """
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = LspService(registry=registry)
        return _singleton


def reset_lsp_service() -> None:
    """Drop the process-wide singleton, closing any live servers."""
    global _singleton
    with _singleton_lock:
        current = _singleton
        _singleton = None
    if current is not None:
        current.close()
