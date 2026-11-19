"""Shared plumbing for the sandbox backends.

Every backend goes through the same lifecycle:

1. mktemp a per-run workdir on the sandbox host so multiple concurrent
   runs cannot collide;
2. stage :attr:`SandboxSpec.input_files` inside that workdir via SFTP
   (:meth:`SSHService.upload_file`);
3. launch the backend (nsjail exec or firecracker microVM);
4. collect :attr:`SandboxSpec.output_globs` matches back to the caller
   (:meth:`SSHService.download_file`);
5. ``rm -rf`` the workdir in a ``finally``.

The helpers here own steps 1, 2, 4, and 5. The backend concrete class
owns step 3. This keeps the per-backend files small and prevents drift
between backends on the "prepare + tear down" contract.
"""
from __future__ import annotations

import logging
import shlex
import tempfile
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import paramiko

from ....exceptions import AILATimeoutError, AuthenticationError, UpstreamError, ValidationError
from ...ssh import SSHService
from ..contracts import (
    SandboxBackend,
    SandboxExecutionError,
    SandboxResult,
    SandboxSpec,
    SandboxUnavailableError,
    validate_output_glob,
)

__all__ = [
    "HostWorkspace",
    "SandboxBackend",
    "SandboxExecutionError",
    "SandboxResult",
    "SandboxSpec",
    "SandboxUnavailableError",
    "collect_outputs",
    "host_workspace",
    "probe_binary",
    "stage_inputs",
]

_log = logging.getLogger(__name__)

# Where per-run host workspaces live. The shared root is created with the
# host's default mode; each run directory beneath it is created owner-only (0700).
_HOST_WORKSPACE_ROOT = "/tmp/aila-sandbox"


class HostWorkspace:
    """One remote workspace directory owned by a single run.

    ``remote_root`` is the absolute POSIX path on the sandbox host;
    ``run_id`` is the uuid used in the directory name (also handy for
    correlating logs). Backends read these two fields and never
    manipulate the workspace lifecycle themselves -- that stays with
    :func:`host_workspace`.
    """

    __slots__ = ("remote_root", "run_id")

    def __init__(self, remote_root: str, run_id: str) -> None:
        self.remote_root = remote_root
        self.run_id = run_id


async def probe_binary(ssh: SSHService, host_payload, binary: str) -> str:
    """Return the absolute path of ``binary`` on the host, or raise.

    Uses ``command -v`` and fallback search locations so custom and
    system paths (/usr/local/bin, /usr/bin) resolve properly.
    """
    quoted = shlex.quote(binary)
    try:
        stdout, stderr, exit_code = await ssh.run_command_full(
            host_payload,
            f"command -v {quoted} || which {quoted} || ls -1 /usr/local/bin/{quoted} /usr/bin/{quoted} 2>/dev/null | head -n 1",
            timeout_seconds=15.0,
            connect_timeout=8.0,
        )
    except (paramiko.SSHException, OSError, TimeoutError) as exc:
        raise SandboxExecutionError(
            f"SSH connection to {host_payload.host}:{host_payload.port} timed out or failed ({exc}). Check that the remote host is powered on and reachable."
        ) from exc

    resolved = stdout.strip().splitlines()[0] if stdout.strip() else ""
    if exit_code != 0 or not resolved:
        raise SandboxExecutionError(
            f"Sandbox isolation binary {binary!r} is not installed on {host_payload.host}. "
            f"Use the '[⚡ Install {binary} on Host]' action in the header to compile/install it automatically over SSH."
        )
    return resolved


@asynccontextmanager
async def host_workspace(ssh: SSHService, host_payload):
    """Create a fresh workspace on the host, yield it, remove it on exit.

    A failed ``mkdir`` raises :class:`SandboxExecutionError` -- the
    caller cannot recover. The final ``rm -rf`` is best-effort: a
    logging failure here MUST NOT mask a real backend exception, so
    the cleanup swallows expected transport errors and only records a
    warning.
    """
    run_id = uuid.uuid4().hex
    remote_root = f"{_HOST_WORKSPACE_ROOT}/run-{run_id}"
    # Two-step mkdir so the top-level root is created lazily (idempotent
    # for concurrent runs) without needing root privileges. The run dir is
    # created owner-only (0700) so other host users cannot read its contents.
    cmd = (
        f"mkdir -p {shlex.quote(_HOST_WORKSPACE_ROOT)} && "
        f"mkdir -m 700 {shlex.quote(remote_root)}"
    )
    try:
        stdout, stderr, exit_code = await ssh.run_command_full(
            host_payload, cmd, timeout_seconds=30.0, connect_timeout=8.0,
        )
    except (paramiko.SSHException, OSError, TimeoutError) as exc:
        raise SandboxExecutionError(
            f"SSH connection to {host_payload.host}:{host_payload.port} timed out or failed ({exc}). Check that the remote host is powered on."
        ) from exc
    if exit_code != 0:
        raise SandboxExecutionError(
            f"sandbox host workspace mkdir failed (exit={exit_code}): {stderr.strip()[:200]}"
        )
    workspace = HostWorkspace(remote_root=remote_root, run_id=run_id)
    try:
        yield workspace
    finally:
        # Best-effort cleanup; a swallowed error here would only surface
        # as accumulated ``run-<uuid>`` directories on the host, which
        # the operator can `rm -rf` at leisure.
        try:
            await ssh.run_command_full(
                host_payload,
                f"rm -rf -- {shlex.quote(remote_root)}",
                timeout_seconds=30.0,
            )
        except (
            paramiko.SSHException,
            AuthenticationError,
            UpstreamError,
            AILATimeoutError,
            ValidationError,
            OSError,
            TimeoutError,
        ) as exc:
            _log.warning(
                "sandbox workspace cleanup failed for %s: %s",
                remote_root, exc,
            )


async def stage_inputs(
    ssh: SSHService,
    host_payload,
    workspace: HostWorkspace,
    files: dict[str, str],
) -> None:
    """Upload ``files`` into ``workspace.remote_root``.

    Each key is a workdir-relative path (already validated by
    :class:`SandboxSpec`). Parent directories are created with a single
    remote ``mkdir -p`` call before each upload; SFTP does not create
    intermediate directories on ``put``.
    """
    for rel_path, content in files.items():
        remote_target = f"{workspace.remote_root}/{rel_path}"
        remote_parent = str(Path(remote_target).parent).replace("\\", "/")
        mk_stdout, mk_stderr, mk_exit = await ssh.run_command_full(
            host_payload,
            f"mkdir -p {shlex.quote(remote_parent)}",
            timeout_seconds=15.0,
        )
        if mk_exit != 0:
            raise SandboxExecutionError(
                f"sandbox input mkdir {remote_parent!r} failed (exit={mk_exit}): {mk_stderr.strip()[:200]}"
            )
        # Write via a local tempfile + upload_file rather than
        # heredoc-piping over SSH: heredocs mangle binary content
        # and inflate the command line beyond argv limits for large
        # inputs. The local tempfile is deleted on function exit.
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as fh:
            fh.write(content)
            local_path = fh.name
        try:
            await ssh.upload_file(host_payload, local_path, remote_target)
        finally:
            try:
                Path(local_path).unlink()
            except OSError:
                pass


async def collect_outputs(
    ssh: SSHService,
    host_payload,
    workspace: HostWorkspace,
    globs: list[str],
    per_file_cap: int,
) -> tuple[dict[str, str], bool]:
    """Materialise ``globs`` matches back onto the caller as a dict.

    Returns ``(files, truncated)`` where ``truncated`` is True iff any
    single collected file was clipped to ``per_file_cap`` bytes. Cap
    is applied per-file (not aggregate) so a large ``result.json``
    cannot silently starve smaller siblings.
    """
    if not globs:
        return {}, False

    # SandboxSpec already validated these; re-check before any remote command is built.
    for pattern in globs:
        try:
            validate_output_glob(pattern)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc

    root = workspace.remote_root
    truncated = False
    files: dict[str, str] = {}
    for pattern in globs:
        # The pattern is already restricted to glob syntax, so the unquoted
        # splice below expands only as a filename glob. Matches are printed
        # NUL-delimited (names may contain newlines) and only those whose
        # realpath stays under the workspace are emitted, which also rejects
        # symlinks that point out of the workspace.
        cmd = (
            f"cd {shlex.quote(root)} && root=$(pwd -P) && "
            f"for f in {pattern}; do "
            '[ -f "$f" ] || continue; '
            'real=$(realpath -- "$f") || continue; '
            'case "$real" in "$root"/*) printf \'%s\\0\' "$f";; esac; '
            "done"
        )
        stdout, _stderr, exit_code = await ssh.run_command_full(
            host_payload, cmd, timeout_seconds=30.0,
        )
        if exit_code != 0:
            # A missing match is not an error; a shell fault is. We
            # cannot distinguish reliably, so we log and skip -- the
            # caller sees an empty ``output_files`` for this pattern.
            _log.warning("sandbox output glob %r on %s exit=%d", pattern, root, exit_code)
            continue
        for rel in filter(None, stdout.split("\0")):
            if rel in files:
                continue
            if not _is_confined_relative(rel):
                _log.warning("sandbox output %r rejected: escapes the workspace", rel)
                continue
            raw, clipped = await _fetch_output(ssh, host_payload, workspace, rel, per_file_cap)
            truncated = truncated or clipped
            files[rel] = raw.decode("utf-8", errors="replace")
    return files, truncated


def _is_confined_relative(rel: str) -> bool:
    """True when ``rel`` is relative and has no ``..`` segment."""
    return bool(rel) and not rel.startswith("/") and ".." not in rel.split("/")


async def _fetch_output(
    ssh: SSHService,
    host_payload,
    workspace: HostWorkspace,
    rel: str,
    per_file_cap: int,
) -> tuple[bytes, bool]:
    """Download one confined output, transferring at most ``per_file_cap`` bytes.

    With a cap, the host writes ``cap + 1`` bytes to a staging file in the
    workspace so the excess is known without transferring it. The staging
    file is removed with the workspace.
    """
    remote_path = f"{workspace.remote_root}/{rel}"
    if per_file_cap > 0:
        staged = f"{workspace.remote_root}/.collect-{uuid.uuid4().hex}"
        _stdout, stderr, exit_code = await ssh.run_command_full(
            host_payload,
            f"head -c {per_file_cap + 1} -- {shlex.quote(remote_path)} > {shlex.quote(staged)}",
            timeout_seconds=30.0,
        )
        if exit_code != 0:
            raise SandboxExecutionError(
                f"sandbox output {rel!r} could not be staged (exit={exit_code}): {stderr.strip()[:200]}"
            )
        remote_path = staged

    with tempfile.NamedTemporaryFile(delete=False) as fh:
        local_path = fh.name
    try:
        await ssh.download_file(host_payload, remote_path, local_path)
        raw = Path(local_path).read_bytes()
    finally:
        try:
            Path(local_path).unlink()
        except OSError:
            pass
    if per_file_cap > 0 and len(raw) > per_file_cap:
        return raw[:per_file_cap], True
    return raw, False
