"""Firecracker microVM sandbox backend.

Firecracker (https://firecracker-microvm.github.io/) boots a KVM-backed
minimal Linux VM in tens of milliseconds. It is a proper microVM (its
own kernel, its own memory), so a kernel LPE in the guest does NOT
escalate to the sandbox host -- unlike nsjail, which shares the host
kernel. Use this backend in production for anything running
adversarial or agent-generated code.

Deploy prerequisites (documented so the operator can wire the host):

* The sandbox host is Linux with ``/dev/kvm`` accessible.
* ``firecracker`` and ``jailer`` binaries are installed (paths overridable
  via ``platform.sandbox_firecracker_bin`` / ``sandbox_jailer_bin``).
* ``platform.sandbox_kernel_path`` points at a Firecracker-compatible
  ``vmlinux`` image on the sandbox host.
* ``platform.sandbox_rootfs_path`` points at an ext4 rootfs image on the
  sandbox host whose ``/sbin/init`` (or ``/init``) implements the
  guest-runner contract described below.

Guest-runner contract (rootfs responsibility):

    On boot, /init MUST:
      1. Mount /dev/vdb (the per-run work drive) at ``/work``.
      2. Read ``/work/cmd.json`` -- a JSON object with keys
         ``argv`` (list[str]), ``env`` (dict[str, str]),
         ``stdin`` (str or null), ``workdir`` (str), ``timeout_s`` (float).
      3. Execute ``argv`` with those env vars, feeding ``stdin`` on
         stdin, chdir'd into ``workdir``, capturing stdout + stderr.
      4. Write a JSON object to ``/work/result.json`` with keys
         ``exit_code`` (int or null), ``stdout`` (str), ``stderr`` (str),
         ``duration_s`` (float), ``timed_out`` (bool), ``oom`` (bool).
      5. ``sync`` and ``reboot -f`` (or ``poweroff -f``) so Firecracker
         exits and the host can read ``/work/result.json`` back.

The host side of this backend prepares the per-run work drive, boots
the microVM via ``firecracker --config-file`` (through ``jailer`` for
namespace isolation of the hypervisor process itself), waits up to
``timeout_s + boot_margin`` for the VM to halt, and reads back
``/work/result.json`` plus any ``spec.output_globs`` matches.
"""
from __future__ import annotations

import json
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

__all__ = ["FirecrackerBackend", "build_vm_config"]

# Host-side padding around ``spec.timeout_s`` for VM boot + shutdown.
# 5s covers a warm-cached rootfs boot; 15s covers cold-cache + init
# script setup. Firecracker's own uVM boot is sub-second, so almost
# all of this budget is consumed by the guest init.
_BOOT_MARGIN_S = 15.0

# Work-drive size (bytes). 128 MiB is enough for cmd.json + input_files
# + collected output files under the default output_max_bytes cap.
# Operators who need larger workspaces can override by patching
# _WORK_DRIVE_SIZE_MB (constant, not runtime config, to keep the wire
# format stable across upgrades).
_WORK_DRIVE_SIZE_MB = 128


def build_vm_config(
    *,
    kernel_path: str,
    rootfs_path: str,
    work_drive_path: str,
    vcpu: int,
    mem_mb: int,
    network: bool,
) -> dict[str, Any]:
    """Compose the Firecracker JSON config file for a single microVM boot.

    Pure: no I/O. Kept separate so the test suite can assert the shape
    without a live host. Firecracker's schema is at
    https://github.com/firecracker-microvm/firecracker/blob/main/src/api_server/swagger/firecracker.yaml.
    """
    config: dict[str, Any] = {
        "boot-source": {
            # ``console=ttyS0`` gives the guest an early-boot log path;
            # ``reboot=k`` picks the KVM reboot vector so ``reboot -f``
            # from the guest actually stops the VM.
            "kernel_image_path": kernel_path,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off",
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": rootfs_path,
                "is_root_device": True,
                "is_read_only": True,
            },
            {
                "drive_id": "work",
                "path_on_host": work_drive_path,
                "is_root_device": False,
                "is_read_only": False,
            },
        ],
        "machine-config": {
            "vcpu_count": int(vcpu),
            "mem_size_mib": int(mem_mb),
            "smt": False,
        },
    }
    if network:
        # A single tap interface named ``fc0`` -- the operator must
        # provision the tap on the host (``ip tuntap add fc0 mode tap``)
        # and bridge it into whatever egress policy the deployment wants.
        # We intentionally do NOT ship default egress: if the operator
        # wants network access from a sandboxed run, they explicitly
        # provision the tap and set ``sandbox_allow_network=true``.
        config["network-interfaces"] = [
            {"iface_id": "eth0", "host_dev_name": "fc0"},
        ]
    return config


class FirecrackerBackend:
    """Concrete :class:`SandboxBackend` implementation for Firecracker."""

    name = "firecracker"

    async def run(
        self,
        spec: SandboxSpec,
        *,
        ssh: SSHService,
        host_payload,
        cfg: Any,
    ) -> SandboxResult:
        if not cfg.rootfs_path:
            raise SandboxExecutionError(
                "firecracker backend requires platform.sandbox_rootfs_path "
                "to point at an ext4 rootfs image on the sandbox host."
            )
        if not cfg.kernel_path:
            raise SandboxExecutionError(
                "firecracker backend requires platform.sandbox_kernel_path "
                "to point at a Firecracker-compatible vmlinux on the sandbox host."
            )

        firecracker_path = await probe_binary(ssh, host_payload, cfg.firecracker_bin)
        jailer_path = await probe_binary(ssh, host_payload, cfg.jailer_bin)

        async with host_workspace(ssh, host_payload) as workspace:
            await stage_inputs(ssh, host_payload, workspace, spec.input_files)
            await self._write_cmd_json(ssh, host_payload, workspace, spec)
            await self._build_work_drive(ssh, host_payload, workspace)
            result = await self._boot_vm(
                spec, ssh, host_payload, cfg,
                firecracker_path, jailer_path, workspace,
            )
            # ``result.json`` is inside the work drive; the boot step
            # mounts + unmounts the drive so we already read it.
            files, files_truncated = await collect_outputs(
                ssh, host_payload, workspace, spec.output_globs,
                per_file_cap=cfg.output_max_bytes,
            )
        result.output_files = files
        if files_truncated:
            result.truncated = True
        return result

    async def _write_cmd_json(
        self,
        ssh: SSHService,
        host_payload,
        workspace: HostWorkspace,
        spec: SandboxSpec,
    ) -> None:
        """Stage the guest-runner input as ``cmd.json`` inside the workspace.

        The workspace is staged onto the host filesystem here; a later
        step (``_build_work_drive``) mkfs's an ext4 image, mounts it,
        and copies the staged files in. Two-step so the input_files
        upload path is identical to the nsjail backend and the drive
        assembly stays localised.
        """
        payload = {
            "argv": list(spec.argv),
            "env": dict(spec.env),
            "stdin": spec.stdin,
            "workdir": spec.workdir,
            "timeout_s": float(spec.timeout_s),
        }
        cmd_json = json.dumps(payload, ensure_ascii=False)
        # A small heredoc write is fine here (cmd.json is < 4 KiB).
        eof = f"AILA_CMDJSON_{workspace.run_id}"
        cmd = (
            f"cat > {shlex.quote(f'{workspace.remote_root}/cmd.json')} <<'{eof}'\n"
            f"{cmd_json}\n"
            f"{eof}"
        )
        _stdout, stderr, exit_code = await ssh.run_command_full(
            host_payload, cmd, timeout_seconds=15.0,
        )
        if exit_code != 0:
            raise SandboxExecutionError(
                f"firecracker cmd.json write failed (exit={exit_code}): {stderr.strip()[:200]}"
            )

    async def _build_work_drive(
        self,
        ssh: SSHService,
        host_payload,
        workspace: HostWorkspace,
    ) -> None:
        """Create + mkfs the per-run work drive; populate from the workspace.

        The staged tree lives at ``<workspace.remote_root>/*`` on the
        host filesystem; the drive image is written next to it as
        ``work.ext4``. Loop-mount + rsync populates it before boot.
        Requires the sandbox host user to have passwordless sudo for
        ``mount`` / ``umount`` (documented deploy requirement).
        """
        root = shlex.quote(workspace.remote_root)
        size_mb = _WORK_DRIVE_SIZE_MB
        # ``truncate -s`` is O(1); ``mkfs.ext4 -F`` skips confirmation;
        # ``mount -o loop`` needs sudo on stock distros -- the operator
        # provisions passwordless sudo for mount/umount as documented.
        cmd = (
            f"set -e && "
            f"cd {root} && "
            f"truncate -s {size_mb}M work.ext4 && "
            f"mkfs.ext4 -F -q work.ext4 && "
            f"mkdir -p mnt && "
            f"sudo -n mount -o loop work.ext4 mnt && "
            f"sudo -n chown -R $(id -u):$(id -g) mnt && "
            # Move every staged file EXCEPT the drive image and mount
            # point into the drive itself.
            f"find . -mindepth 1 -maxdepth 1 "
            f"  ! -name work.ext4 ! -name mnt -exec mv {{}} mnt/ \\; && "
            f"sync && "
            f"sudo -n umount mnt"
        )
        _stdout, stderr, exit_code = await ssh.run_command_full(
            host_payload, cmd, timeout_seconds=60.0,
        )
        if exit_code != 0:
            raise SandboxExecutionError(
                f"firecracker work-drive build failed (exit={exit_code}): {stderr.strip()[:200]}. "
                "Ensure the sandbox host user has passwordless sudo for mount/umount."
            )

    async def _boot_vm(
        self,
        spec: SandboxSpec,
        ssh: SSHService,
        host_payload,
        cfg: Any,
        firecracker_path: str,
        jailer_path: str,
        workspace: HostWorkspace,
    ) -> SandboxResult:
        """Write vm-config.json, boot via jailer + firecracker, wait, harvest.

        Uses config-file boot (``--config-file``) which starts the VM
        immediately with no API socket -- simpler and enough for the
        "run once, read result, exit" model. Wall-clock deadline is
        enforced host-side with ``timeout(1)``; the guest-side runner
        also honours its own ``timeout_s`` so a hung guest still gets
        killed.
        """
        vm_config = build_vm_config(
            kernel_path=cfg.kernel_path,
            rootfs_path=cfg.rootfs_path,
            work_drive_path=f"{workspace.remote_root}/work.ext4",
            vcpu=spec.vcpu,
            mem_mb=spec.mem_mb,
            network=spec.network,
        )
        config_json = json.dumps(vm_config, ensure_ascii=False)
        # Stage vm-config.json alongside the work drive.
        eof = f"AILA_VMCFG_{workspace.run_id}"
        stage_cmd = (
            f"cat > {shlex.quote(f'{workspace.remote_root}/vm-config.json')} <<'{eof}'\n"
            f"{config_json}\n"
            f"{eof}"
        )
        _stdout, stderr, exit_code = await ssh.run_command_full(
            host_payload, stage_cmd, timeout_seconds=15.0,
        )
        if exit_code != 0:
            raise SandboxExecutionError(
                f"firecracker vm-config.json write failed (exit={exit_code}): {stderr.strip()[:200]}"
            )

        wall_deadline = int(round(spec.timeout_s + _BOOT_MARGIN_S))
        # Jailer expects a numeric --id, --uid, and --gid for the
        # jail chroot. We use the run_id fragment for --id (jailer
        # requires it to be filesystem-safe -- uuid hex fits) and
        # 1000/1000 as the drop-privileges target; the operator can
        # override the drop target by wrapping the jailer invocation.
        # ``exec-file`` is the firecracker binary itself, which jailer
        # copies into the jail chroot before launch.
        vm_config_path = f"{workspace.remote_root}/vm-config.json"
        boot_cmd = (
            f"timeout --signal=KILL {wall_deadline}s "
            f"{shlex.quote(jailer_path)} "
            f"--id {shlex.quote(workspace.run_id)} "
            f"--uid 1000 --gid 1000 "
            f"--exec-file {shlex.quote(firecracker_path)} "
            f"--chroot-base-dir {shlex.quote(workspace.remote_root)} "
            f"-- --no-api --config-file {shlex.quote(vm_config_path)}"
        )
        start = time.monotonic()
        try:
            stdout, stderr, exit_code = await ssh.run_command_full(
                host_payload, boot_cmd, timeout_seconds=wall_deadline + 30.0,
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
            raise SandboxExecutionError(
                f"firecracker boot dispatch failed for run {workspace.run_id}: {exc}"
            ) from exc
        duration = time.monotonic() - start

        # ``timeout(1)`` exits 124 when it fires SIGKILL on wall-clock
        # expiry (137 when the child ignores SIGTERM and needs KILL).
        # Either way the guest never got to write result.json.
        host_timed_out = exit_code in (124, 137)

        result_payload = await self._read_result_json(
            ssh, host_payload, workspace,
        )
        if result_payload is None:
            # No result.json => guest died before the runner completed.
            # Report whatever the hypervisor emitted so the operator
            # can see the boot failure.
            return SandboxResult(
                backend=self.name,
                exit_code=None,
                stdout=stdout[: cfg.output_max_bytes] if cfg.output_max_bytes > 0 else stdout,
                stderr=stderr[: cfg.output_max_bytes] if cfg.output_max_bytes > 0 else stderr,
                output_files={},
                duration_s=duration,
                timed_out=host_timed_out,
                oom=False,
                truncated=False,
            )

        # Cap the guest-reported strings so the service policy holds
        # even when the guest returned huge stdout/stderr.
        guest_stdout = str(result_payload.get("stdout") or "")
        guest_stderr = str(result_payload.get("stderr") or "")
        truncated = False
        cap = cfg.output_max_bytes
        if cap > 0 and len(guest_stdout.encode("utf-8", "ignore")) > cap:
            guest_stdout = guest_stdout.encode("utf-8", "ignore")[:cap].decode(
                "utf-8", errors="replace"
            )
            truncated = True
        if cap > 0 and len(guest_stderr.encode("utf-8", "ignore")) > cap:
            guest_stderr = guest_stderr.encode("utf-8", "ignore")[:cap].decode(
                "utf-8", errors="replace"
            )
            truncated = True

        guest_exit = result_payload.get("exit_code")
        guest_timeout = bool(result_payload.get("timed_out", False))
        guest_oom = bool(result_payload.get("oom", False))
        return SandboxResult(
            backend=self.name,
            exit_code=None if guest_exit is None else int(guest_exit),
            stdout=guest_stdout,
            stderr=guest_stderr,
            output_files={},  # filled by caller
            duration_s=float(result_payload.get("duration_s", duration)),
            timed_out=guest_timeout or host_timed_out,
            oom=guest_oom,
            truncated=truncated,
        )

    async def _read_result_json(
        self,
        ssh: SSHService,
        host_payload,
        workspace: HostWorkspace,
    ) -> dict[str, Any] | None:
        """Mount the work drive read-only and cat ``result.json``.

        Returns None when the file is missing (guest crashed before
        producing it). Any other failure raises
        :class:`SandboxExecutionError` because it means the sandbox
        infrastructure itself failed.
        """
        root = shlex.quote(workspace.remote_root)
        cmd = (
            f"set -e && "
            f"cd {root} && "
            f"mkdir -p mnt && "
            f"sudo -n mount -o loop,ro work.ext4 mnt && "
            f"(if [ -f mnt/result.json ]; then cat mnt/result.json; else echo __AILA_SBX_NO_RESULT__; fi) && "
            f"sudo -n umount mnt"
        )
        stdout, stderr, exit_code = await ssh.run_command_full(
            host_payload, cmd, timeout_seconds=60.0,
        )
        if exit_code != 0:
            raise SandboxExecutionError(
                f"firecracker result.json read failed (exit={exit_code}): {stderr.strip()[:200]}"
            )
        text = stdout.strip()
        if text.endswith("__AILA_SBX_NO_RESULT__") or text == "__AILA_SBX_NO_RESULT__":
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise SandboxExecutionError(
                f"firecracker result.json is not valid JSON: {exc}. "
                f"Raw payload (first 200 chars): {text[:200]!r}"
            ) from exc
