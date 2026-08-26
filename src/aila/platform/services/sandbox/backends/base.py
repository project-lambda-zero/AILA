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

# Where per-run host workspaces live. ``/tmp/aila-sandbox`` is world-accessible
# with standard 1777 sticky bit so non-root users can write without permissions errors.
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
    # for concurrent runs) without needing root privileges.
    cmd = (
        f"mkdir -p {shlex.quote(_HOST_WORKSPACE_ROOT)} && "
        f"mkdir {shlex.quote(remote_root)}"
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

    # Enumerate matches host-side so the caller sees exactly the files
    # the sandbox produced -- no ordering surprises from doing this
    # locally after downloading. ``find`` is a POSIX baseline.
    truncated = False
    files: dict[str, str] = {}
    for pattern in globs:
        # Use a shell glob under a subshell restricted to the workspace
        # so an accidental absolute-looking pattern still resolves under
        # the workspace root (SandboxSpec already rejects '/'-prefixed
        # patterns; this is defense in depth).
        cmd = (
            f"cd {shlex.quote(workspace.remote_root)} && "
            f"for f in {pattern}; do "
            f"  [ -f \"$f\" ] && printf '%s\\n' \"$f\"; "
            f"done"
        )
        stdout, _stderr, exit_code = await ssh.run_command_full(
            host_payload, cmd, timeout_seconds=30.0,
        )
        if exit_code != 0:
            # A missing match is not an error; a shell fault is. We
            # cannot distinguish reliably, so we log and skip -- the
            # caller sees an empty ``output_files`` for this pattern.
            _log.warning(
                "sandbox output glob %r on %s exit=%d",
                pattern, workspace.remote_root, exit_code,
            )
            continue
        for rel_line in stdout.splitlines():
            rel = rel_line.strip()
            if not rel or rel in files:
                continue
            remote_path = f"{workspace.remote_root}/{rel}"
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
                raw = raw[:per_file_cap]
                truncated = True
            files[rel] = raw.decode("utf-8", errors="replace")
    return files, truncated
