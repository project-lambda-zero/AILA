"""nsjail-backed sandbox executor.

nsjail (https://github.com/google/nsjail) is a Linux namespace + seccomp
sandbox. It shares the host kernel, so it is strictly weaker than a
Firecracker microVM -- use it for developer environments where a kernel
LPE in the guest is acceptable risk, and Firecracker in production.

Backend contract:
    * The sandbox host has the ``nsjail`` binary in its PATH (or at the
      operator-configured absolute path in ``sandbox_nsjail_bin``).
    * Every run mounts a fresh workspace read-write inside the sandbox
      at ``spec.workdir`` and chdirs there.
    * When ``spec.network`` is False the run inherits nsjail's default
      network isolation (a fresh net namespace with no interfaces).
      When ``spec.network`` is True the ``--disable_clone_newnet`` flag
      is passed so the sandbox re-uses the host network namespace.
    * Memory ceiling is enforced via ``--rlimit_as``.
    * Wall-clock timeout is enforced via ``--time_limit``.
"""
from __future__ import annotations

import shlex
import time
from typing import Any

import paramiko

from ....exceptions import AILATimeoutError, AuthenticationError, UpstreamError, ValidationError
from ...ssh import SSHService
from ..contracts import (
    SandboxExecutionError,
    SandboxResult,
    SandboxSpec,
)
from .base import (
    HostWorkspace,
    collect_outputs,
    host_workspace,
    probe_binary,
    stage_inputs,
)

__all__ = ["NsjailBackend", "build_nsjail_argv"]

# nsjail's --time_limit exit code when it kills a program for exceeding
# the wall-clock timeout. Documented in nsjail's source (util.h).
_NSJAIL_TIMEOUT_EXIT = 137  # SIGKILL (128 + 9), which nsjail sends on TL

# Exit code returned when a process is OOM-killed via rlimit_as. glibc
# usually aborts the mmap and the runtime exits with SIGKILL (137);
# some runtimes exit cleanly with 1. We flag either as "possibly OOM"
# only when nsjail reports the rlimit hit in stderr.
_NSJAIL_KILL_EXIT = 137

# Marker nsjail writes to stderr when the memory rlimit is hit. Present
# on every nsjail 3.x release; used to disambiguate a SIGKILL that came
# from OOM vs. a SIGKILL from the timeout.
_NSJAIL_OOM_MARKERS = (
    "rlimit_as",
    "cannot allocate memory",
    "out of memory",
)


def build_nsjail_argv(
    spec: SandboxSpec,
    *,
    nsjail_bin: str,
    workspace_remote_root: str,
) -> list[str]:
    """Compose the nsjail argv that runs ``spec.argv``.

    Kept pure (no I/O) so the test suite can assert the composed argv
    without a live host. The workspace root on the host is bind-mounted
    read-write at ``spec.workdir`` inside the sandbox so the guest sees
    exactly the paths the caller staged.

    Network semantics: nsjail creates a fresh network namespace by
    default (no interfaces, no connectivity). Passing
    ``--disable_clone_newnet`` tells nsjail to re-use the host network
    namespace, which is the "network on" mode. So the flag is present
    iff the (policy-clamped) ``spec.network`` is True.
    """
    argv: list[str] = [
        nsjail_bin,
        "--mode", "o",  # once: run one command and exit
        "--quiet",
        "--chroot", "/",  # keep host FS visible; the bind-mount below is R/W
        "--bindmount", f"{workspace_remote_root}:{spec.workdir}",
        "--cwd", spec.workdir,
        # Wall-clock ceiling. nsjail SIGKILLs the child at expiry.
        "--time_limit", str(int(max(1, round(spec.timeout_s)))),
        # Address-space ceiling (bytes). rlimit_as bounds mmap + malloc.
        "--rlimit_as", str(int(spec.mem_mb)),  # nsjail interprets --rlimit_as in MiB
        # File-descriptor + stack ceilings prevent trivial DoS from
        # unbounded fork/mmap loops; values match nsjail defaults but
        # are explicit so an operator can override by patching argv.
        "--rlimit_nofile", "1024",
        "--rlimit_stack", "64",
    ]
    if spec.network:
        # Re-use host network namespace (grant connectivity). Absence of
        # this flag keeps the default fresh-net-namespace isolation.
        argv.append("--disable_clone_newnet")
    for name, value in sorted(spec.env.items()):
        argv.extend(["--env", f"{name}={value}"])
    # ``--`` terminates nsjail's own flag parsing so a spec.argv[0] that
    # happens to start with a dash is not mistaken for an nsjail flag.
    argv.append("--")
    argv.extend(spec.argv)
    return argv


class NsjailBackend:
    """Concrete :class:`SandboxBackend` implementation for nsjail."""

    name = "nsjail"

    async def run(
        self,
        spec: SandboxSpec,
        *,
        ssh: SSHService,
        host_payload,
        cfg: Any,
    ) -> SandboxResult:
        # Probe first so a missing binary fails cleanly with an
        # actionable message instead of a "127 not found" from bash.
        nsjail_path = await probe_binary(ssh, host_payload, cfg.nsjail_bin)
        async with host_workspace(ssh, host_payload) as workspace:
            await stage_inputs(ssh, host_payload, workspace, spec.input_files)
            result = await self._run_in_workspace(
                spec, ssh, host_payload, cfg, nsjail_path, workspace,
            )
            files, files_truncated = await collect_outputs(
                ssh, host_payload, workspace, spec.output_globs,
                per_file_cap=cfg.output_max_bytes,
            )
        # Merge output truncation into the result flag so the service
        # sees a single ``truncated`` bit regardless of which stream
        # got clipped.
        result.output_files = files
        if files_truncated:
            result.truncated = True
        return result

    async def _run_in_workspace(
        self,
        spec: SandboxSpec,
        ssh: SSHService,
        host_payload,
        cfg: Any,
        nsjail_path: str,
        workspace: HostWorkspace,
    ) -> SandboxResult:
        argv = build_nsjail_argv(
            spec, nsjail_bin=nsjail_path, workspace_remote_root=workspace.remote_root,
        )
        # Compose a bash pipeline so we can feed stdin from a heredoc
        # while still using ``run_command_full`` (which does not expose
        # a stdin channel). The heredoc is quoted so shell-metachars in
        # the stdin payload are treated as data, not shell code.
        cmd_string = " ".join(shlex.quote(a) for a in argv)
        if spec.stdin is not None:
            # Random EOF marker so a literal ``EOF`` inside stdin cannot
            # close the heredoc early.
            eof_marker = f"AILA_SBX_STDIN_{workspace.run_id}"
            wrapped = (
                f"{cmd_string} <<'{eof_marker}'\n"
                f"{spec.stdin}\n"
                f"{eof_marker}"
            )
        else:
            wrapped = f"{cmd_string} </dev/null"

        # nsjail --time_limit is the primary wall-clock ceiling; the
        # SSH-level timeout is an idle timeout, not a wall-clock cap.
        # Add a safety margin so a jailed process that hits its
        # timeout inside the guest can still emit its diagnostic to
        # stderr before we tear the SSH channel down.
        ssh_idle_timeout = float(spec.timeout_s) + 30.0
        start = time.monotonic()
        try:
            stdout, stderr, exit_code = await ssh.run_command_full(
                host_payload, wrapped, timeout_seconds=ssh_idle_timeout,
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
            # Any SSH-level fault surfaces as a backend infra failure so
            # the caller sees a typed SandboxExecutionError instead of a
            # raw transport exception leaking out of the backend layer.
            raise SandboxExecutionError(
                f"nsjail dispatch failed for run {workspace.run_id}: {exc}"
            ) from exc
        duration = time.monotonic() - start

        stdout_bytes = stdout.encode("utf-8", errors="ignore")
        stderr_bytes = stderr.encode("utf-8", errors="ignore")
        cap = cfg.output_max_bytes
        truncated = False
        if cap > 0 and len(stdout_bytes) > cap:
            stdout_bytes = stdout_bytes[:cap]
            truncated = True
        if cap > 0 and len(stderr_bytes) > cap:
            stderr_bytes = stderr_bytes[:cap]
            truncated = True

        timed_out = exit_code == _NSJAIL_TIMEOUT_EXIT
        oom = exit_code == _NSJAIL_KILL_EXIT and any(
            marker in stderr.lower() for marker in _NSJAIL_OOM_MARKERS
        )
        # An OOM kill is not also a timeout; disambiguate.
        if oom:
            timed_out = False

        # ``exit_code`` is meaningless when the program was killed by
        # nsjail before it could report an exit. Present ``None`` so
        # callers can distinguish "child exited with 137" from "sandbox
        # killed the child at 137".
        reported_exit: int | None = exit_code
        if timed_out or oom:
            reported_exit = None

        return SandboxResult(
            backend=self.name,
            exit_code=reported_exit,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            output_files={},  # filled by the caller after collect_outputs
            duration_s=duration,
            timed_out=timed_out,
            oom=oom,
            truncated=truncated,
        )
