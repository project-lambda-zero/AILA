"""OCI container sandbox backend (docker or podman) reached over SSH.

Image-agnostic: the backend runs whatever immutable image the caller pins
in ``SandboxSpec.image``. Image selection is the caller's decision.

Backend contract:
    * The sandbox host has the runtime named by ``platform.sandbox_oci_bin``
      (``docker`` by default) and coreutils ``timeout`` on its PATH.
    * The image must already be present on the host. The backend runs
      ``<runtime> image inspect`` and fails actionably otherwise; it never
      pulls, so a run cannot drift to different bytes than the digest pinned.
    * Containers run as the SSH user's numeric uid:gid, which must not be
      root. The per-run workspace is the only host path mounted, read-write,
      at ``spec.workdir``. The root filesystem is read-only.
    * Network is ``none`` unless ``spec.network`` is granted. Every
      networked run also requires ``spec.egress``; the backend creates a
      per-run bridge and nftables policy and never joins a shared bridge or
      the host network namespace.
    * The wall clock is enforced by coreutils ``timeout`` wrapped around the
      runtime client; exit 124 maps to ``timed_out``. The named container is
      force-removed in ``finally`` on every path.
    * ``oom`` is never inferred: exit codes alone cannot distinguish an OOM
      kill from other SIGKILLs, so it is always False.
"""
from __future__ import annotations

import logging
import math
import re
import shlex
import time
from contextlib import nullcontext
from typing import Any

import paramiko

from ....exceptions import AILATimeoutError, AuthenticationError, UpstreamError, ValidationError
from ...ssh import CommandCancelledError, SSHService
from ..contracts import (
    CancelCheck,
    SandboxExecutionError,
    SandboxResult,
    SandboxSpec,
    StreamCallback,
)
from .base import (
    HostWorkspace,
    collect_outputs,
    host_workspace,
    probe_binary,
    stage_inputs,
)
from .oci_egress import scoped_conntrack_collector, scoped_oci_egress
from .oci_flow import (
    ConntrackFlowLedger,
    OciFlowTelemetry,
    OciTelemetryMode,
    conntrack_mark_for_run,
)

__all__ = ["OciBackend", "build_oci_run_argv"]

_log = logging.getLogger(__name__)

# coreutils ``timeout`` exit status when the wall-clock limit fired.
_TIMEOUT_EXIT = 124
# Grace period between SIGTERM and SIGKILL when the limit fires.
_KILL_AFTER = "5s"
# SSH idle-timeout margin on top of the wall-clock limit, matching nsjail.
_SSH_IDLE_MARGIN_S = 30.0

_TRANSPORT_ERRORS: tuple[type[BaseException], ...] = (
    paramiko.SSHException,
    AuthenticationError,
    UpstreamError,
    AILATimeoutError,
    ValidationError,
    OSError,
    TimeoutError,
)

# Characters allowed in a bind-mount destination. Anything else (commas,
# equals signs) would reshape the ``--mount`` option string.
_MOUNT_PATH_RE = re.compile(r"[A-Za-z0-9._/-]+")
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Home and XDG base directories, each relative to the workdir. The root
# filesystem is read-only, so these must point into the writable workspace
# bind mount; a caller may override them only with a path under the workdir.
_WORKDIR_ENV_SUFFIXES: dict[str, str] = {
    "HOME": "",
    "XDG_CACHE_HOME": "/.cache",
    "XDG_CONFIG_HOME": "/.config",
    "XDG_DATA_HOME": "/.local/share",
}
# Proxy variables are blanked on every run so an image-baked proxy cannot
# route around the per-run egress policy. Callers may not set them.
_PROXY_ENV_NAMES: tuple[str, ...] = (
    "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy",
)
_NO_PROXY_ENV: dict[str, str] = {"NO_PROXY": "*", "no_proxy": "*"}


def _is_reserved_proxy_name(name: str) -> bool:
    lowered = name.lower()
    return lowered == "no_proxy" or lowered.endswith("_proxy")


def _confined_to_workdir(value: str, workdir: str) -> bool:
    if not _MOUNT_PATH_RE.fullmatch(value) or ".." in value.split("/"):
        return False
    return value == workdir or value.startswith(f"{workdir}/")


def _check_guest_layout(spec: SandboxSpec) -> None:
    """Reject workdir and env values that would corrupt the runtime argv or escape the workspace."""
    if spec.workdir == "/" or not _MOUNT_PATH_RE.fullmatch(spec.workdir):
        raise SandboxExecutionError(
            f"oci sandbox workdir {spec.workdir!r} must be an absolute path of letters, digits, "
            "'.', '_', '-' and '/' (not '/' itself)."
        )
    for name, value in spec.env.items():
        if not _ENV_NAME_RE.fullmatch(name):
            raise SandboxExecutionError(f"oci sandbox env name {name!r} is not a valid variable name.")
        if _is_reserved_proxy_name(name):
            raise SandboxExecutionError(
                f"oci sandbox env {name!r} is reserved: the backend sets the guest proxy policy."
            )
        if name in _WORKDIR_ENV_SUFFIXES and not _confined_to_workdir(value, spec.workdir):
            raise SandboxExecutionError(
                f"oci sandbox env {name!r}={value!r} must be a path under workdir {spec.workdir!r}."
            )


def _guest_env(spec: SandboxSpec) -> dict[str, str]:
    """Return the full guest environment: writable home/XDG, blanked proxies, caller env.

    Assumes ``_check_guest_layout`` has already validated ``spec.env``.
    """
    env = {name: f"{spec.workdir}{suffix}" for name, suffix in _WORKDIR_ENV_SUFFIXES.items()}
    env.update(spec.env)
    env.update({name: "" for name in _PROXY_ENV_NAMES})
    env.update(_NO_PROXY_ENV)
    return env


def build_oci_run_argv(
    spec: SandboxSpec,
    *,
    runtime: str,
    timeout_bin: str,
    image: str,
    container_name: str,
    workspace_remote_root: str,
    uid: int,
    gid: int,
    network_mode: str,
) -> list[str]:
    """Compose the remote argv that runs ``spec.argv`` in ``image``.

    Pure (no I/O) so tests can pin the exact hardening flags. ``--entrypoint=``
    clears the image ENTRYPOINT so ``spec.argv`` is the exec vector, not an
    argument to the image's entrypoint. ``--interactive`` is added only when
    stdin is supplied, so the heredoc reaches the container.
    """
    memory = f"{int(spec.mem_mb)}m"
    argv: list[str] = [
        timeout_bin,
        f"--kill-after={_KILL_AFTER}",
        f"{max(1, math.ceil(spec.timeout_s))}s",
        runtime,
        "run",
        "--rm",
        "--name", container_name,
        "--user", f"{uid}:{gid}",
        "--entrypoint=",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(int(spec.pids_limit)),
        "--memory", memory,
        "--cpus", str(int(spec.vcpu)),
        "--tmpfs", f"/tmp:rw,noexec,nosuid,size={memory}",
        "--mount", f"type=bind,src={workspace_remote_root},dst={spec.workdir}",
        "--workdir", spec.workdir,
        "--network", network_mode,
    ]
    if spec.shm_mb:
        argv.extend(["--shm-size", f"{int(spec.shm_mb)}m"])
    if spec.egress is not None:
        for destination in spec.egress.destinations:
            if destination.host is not None:
                argv.extend(["--add-host", f"{destination.host}:{destination.address}"])
    if spec.stdin is not None:
        argv.append("--interactive")
    for name, value in sorted(_guest_env(spec).items()):
        argv.extend(["-e", f"{name}={value}"])
    argv.append(image)
    argv.extend(spec.argv)
    return argv


class OciBackend:
    """Concrete :class:`SandboxBackend` implementation for docker/podman."""

    name = "oci"
    supports_network = True
    enforces_egress = True

    def __init__(self, *, flow_telemetry: OciFlowTelemetry | None = None) -> None:
        self._flow_telemetry = flow_telemetry

    async def run(
        self,
        spec: SandboxSpec,
        *,
        ssh: SSHService,
        host_payload,
        cfg: Any,
        on_stdout: StreamCallback | None = None,
        on_stderr: StreamCallback | None = None,
        cancel_requested: CancelCheck | None = None,
    ) -> SandboxResult:
        if spec.image is None:
            raise SandboxExecutionError(
                "oci backend requires SandboxSpec.image set to an immutable 'name@sha256:<digest>' reference."
            )
        if spec.network and spec.egress is None:
            raise SandboxExecutionError(
                "networked OCI execution requires SandboxSpec.egress; an unrestricted bridge is never used"
            )
        _check_guest_layout(spec)

        runtime = await probe_binary(ssh, host_payload, cfg.oci_bin)
        timeout_bin = await probe_binary(ssh, host_payload, "timeout")
        telemetry = self._flow_telemetry
        telemetry_on = telemetry is not None and telemetry.mode is not OciTelemetryMode.OFF
        egress_tools: dict[str, str] = {}
        if spec.network:
            for binary in ("nft", "sudo", "ip"):
                egress_tools[binary] = await probe_binary(ssh, host_payload, binary)
        if spec.network and telemetry_on:
            egress_tools["conntrack"] = await probe_binary(ssh, host_payload, "conntrack")
        uid, gid = await _resolve_identity(ssh, host_payload)
        await _require_local_image(ssh, host_payload, runtime, spec.image)

        async with host_workspace(ssh, host_payload) as workspace:
            run_id = workspace.run_id
            ledger: ConntrackFlowLedger | None = None
            conntrack_mark: int | None = None
            if spec.network and telemetry is not None and telemetry_on:
                conntrack_mark = conntrack_mark_for_run(run_id)
                ledger = ConntrackFlowLedger(
                    telemetry, sandbox_run_id=run_id, conntrack_mark=conntrack_mark
                )
            if spec.network:
                if spec.egress is None:
                    raise SandboxExecutionError("networked OCI execution requires an exact egress policy")
                egress_context = scoped_oci_egress(
                    ssh,
                    host_payload,
                    runtime=runtime,
                    nft=egress_tools["nft"],
                    sudo=egress_tools["sudo"],
                    ip=egress_tools["ip"],
                    run_id=run_id,
                    policy=spec.egress,
                    conntrack_mark=conntrack_mark,
                )
            else:
                egress_context = nullcontext("none")
            try:
                async with egress_context as network_mode:
                    collector_context = (
                        scoped_conntrack_collector(
                            ssh,
                            host_payload,
                            sudo=egress_tools["sudo"],
                            conntrack=egress_tools["conntrack"],
                            ledger=ledger,
                            run_id=run_id,
                            conntrack_mark=conntrack_mark,
                            enforce=telemetry.mode is OciTelemetryMode.ENFORCE,
                            timeout_seconds=spec.timeout_s,
                        )
                        if ledger is not None and telemetry is not None
                        else nullcontext()
                    )
                    async with collector_context:
                        if ledger is not None:
                            await ledger.start()
                        await stage_inputs(ssh, host_payload, workspace, spec.input_files)
                        result = await self._run_in_workspace(
                            spec, ssh, host_payload, cfg,
                            runtime=runtime,
                            timeout_bin=timeout_bin,
                            image=spec.image,
                            uid=uid,
                            gid=gid,
                            network_mode=network_mode,
                            workspace=workspace,
                            on_stdout=on_stdout,
                            on_stderr=on_stderr,
                            cancel_requested=cancel_requested,
                        )
                        output_cap = min(cfg.output_max_bytes, spec.max_output_bytes or cfg.output_max_bytes)
                        files, files_truncated = await collect_outputs(
                            ssh, host_payload, workspace, spec.output_globs,
                            per_file_cap=output_cap, aggregate_cap=output_cap,
                        )
            finally:
                if ledger is not None:
                    await ledger.finish()
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
        *,
        runtime: str,
        timeout_bin: str,
        image: str,
        uid: int,
        gid: int,
        network_mode: str,
        workspace: HostWorkspace,
        on_stdout: StreamCallback | None = None,
        on_stderr: StreamCallback | None = None,
        cancel_requested: CancelCheck | None = None,
    ) -> SandboxResult:
        container_name = f"aila-sandbox-{workspace.run_id}"
        argv = build_oci_run_argv(
            spec,
            runtime=runtime,
            timeout_bin=timeout_bin,
            image=image,
            container_name=container_name,
            workspace_remote_root=workspace.remote_root,
            uid=uid,
            gid=gid,
            network_mode=network_mode,
        )
        cmd_string = " ".join(shlex.quote(a) for a in argv)
        if spec.stdin is not None:
            eof_marker = f"AILA_SBX_STDIN_{workspace.run_id}"
            wrapped = f"{cmd_string} <<'{eof_marker}'\n{spec.stdin}\n{eof_marker}"
        else:
            wrapped = f"{cmd_string} </dev/null"

        ssh_idle_timeout = float(spec.timeout_s) + _SSH_IDLE_MARGIN_S
        streaming = on_stdout is not None or on_stderr is not None or cancel_requested is not None
        # Cancelling kills the named container; the remote client's SIGHUP on
        # channel close alone would leave the container running.
        cancel_command = f"{shlex.quote(runtime)} rm -f {container_name}" if streaming else None

        start = time.monotonic()
        try:
            try:
                if streaming:
                    stdout, stderr, exit_code = await ssh.run_command_streaming(
                        host_payload, wrapped, timeout_seconds=ssh_idle_timeout,
                        on_stdout=on_stdout, on_stderr=on_stderr,
                        cancel_requested=cancel_requested, cancel_command=cancel_command,
                    )
                else:
                    stdout, stderr, exit_code = await ssh.run_command_full(
                        host_payload, wrapped, timeout_seconds=ssh_idle_timeout,
                    )
            except CommandCancelledError as exc:
                raise SandboxExecutionError(f"oci run {workspace.run_id} cancelled") from exc
            except _TRANSPORT_ERRORS as exc:
                raise SandboxExecutionError(
                    f"oci dispatch failed for run {workspace.run_id}: {exc}"
                ) from exc
            duration = time.monotonic() - start
        finally:
            await _force_remove(ssh, host_payload, runtime, container_name)

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

        timed_out = exit_code == _TIMEOUT_EXIT
        return SandboxResult(
            backend=self.name,
            exit_code=None if timed_out else exit_code,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            output_files={},  # filled by the caller after collect_outputs
            duration_s=duration,
            timed_out=timed_out,
            oom=False,
            truncated=truncated,
        )


async def _remote(
    ssh: SSHService,
    host_payload,
    command: str,
    *,
    what: str,
    timeout_seconds: float,
) -> tuple[str, str, int]:
    try:
        return await ssh.run_command_full(host_payload, command, timeout_seconds=timeout_seconds)
    except _TRANSPORT_ERRORS as exc:
        raise SandboxExecutionError(f"oci {what} failed on the sandbox host: {exc}") from exc


async def _resolve_identity(ssh: SSHService, host_payload) -> tuple[int, int]:
    """Return the sandbox ssh user's (uid, gid); refuse root."""
    stdout, stderr, exit_code = await _remote(
        ssh, host_payload, "id -u && id -g", what="identity probe", timeout_seconds=15.0,
    )
    fields = stdout.split()
    if exit_code != 0 or len(fields) != 2 or not all(field.isdigit() for field in fields):
        raise SandboxExecutionError(
            f"could not resolve the sandbox ssh user's uid/gid (exit={exit_code}): {stderr.strip()[:200]}"
        )
    uid, gid = int(fields[0]), int(fields[1])
    if uid == 0 or gid == 0:
        raise SandboxExecutionError(
            f"oci sandbox refuses to run as root (uid={uid}, gid={gid}); run the sandbox ssh user unprivileged."
        )
    return uid, gid


async def _require_local_image(ssh: SSHService, host_payload, runtime: str, image: str) -> None:
    """Fail unless ``image`` is already present on the host. Never pulls."""
    _, stderr, exit_code = await _remote(
        ssh,
        host_payload,
        f"{shlex.quote(runtime)} image inspect {shlex.quote(image)} >/dev/null",
        what="image check",
        timeout_seconds=30.0,
    )
    if exit_code != 0:
        raise SandboxExecutionError(
            f"oci image {image!r} is not present on the sandbox host (exit={exit_code}). "
            "aila never pulls images; pre-pull this exact digest on the host first. "
            f"{stderr.strip()[:200]}"
        )


async def _force_remove(ssh: SSHService, host_payload, runtime: str, container_name: str) -> None:
    """Best-effort removal of this run's named container; never raises."""
    try:
        _stdout, stderr, exit_code = await ssh.run_command_full(
            host_payload,
            f"{shlex.quote(runtime)} rm -f {container_name}",
            timeout_seconds=15.0,
        )
        # A normal --rm run leaves no container, so "no such container" is the
        # expected outcome and is not worth a warning.
        if exit_code != 0 and "no such container" not in stderr.lower():
            _log.warning(
                "oci sandbox could not force-remove container %s (exit=%d): %s",
                container_name, exit_code, stderr.strip()[:200],
            )
    except (*_TRANSPORT_ERRORS, RuntimeError) as exc:
        _log.warning("oci sandbox could not force-remove container %s: %s", container_name, exc)
