"""Platform-owned sandbox execution service (issue #147).

The one entry point every module goes through when it needs to execute
agent-derived or untrusted code with real isolation. Delegates to a
concrete :class:`SandboxBackend` (nsjail or Firecracker) reached over
SSH; when no backend is provisioned, callers see
:class:`SandboxUnavailableError` and there is deliberately no local
un-isolated fallback -- a fallback would defeat the whole point.

Policy the service enforces before dispatch:

* ``spec.timeout_s`` is clamped to ``platform.sandbox_max_timeout_s``.
* ``spec.network`` is forced to ``False`` unless
  ``platform.sandbox_allow_network`` is enabled at the platform level.
* When ``spec.vcpu`` / ``spec.mem_mb`` were left at their SandboxSpec
  defaults, the platform defaults from config take precedence so an
  operator can tune every run's ceilings without touching module code.
* Every result has its ``stdout`` / ``stderr`` and per-file output cap
  applied to :attr:`SandboxResult.truncated`.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

import paramiko
from sqlmodel import select

from ....storage.database import async_session_scope
from ....storage.db_models import ManagedSystemRecord
from ....storage.registry import ConfigRegistry
from ...config import PlatformSettings
from ...contracts.platform import SSHIntegrationInput
from ...exceptions import AILATimeoutError, AuthenticationError, UpstreamError, ValidationError
from ..ssh import SSHService
from .backends import FirecrackerBackend, NsjailBackend
from .contracts import (
    SandboxBackend,
    SandboxExecutionError,
    SandboxResult,
    SandboxSpec,
    SandboxUnavailableError,
)

__all__ = ["SandboxConfig", "SandboxProbe", "SandboxService"]

_log = logging.getLogger(__name__)

# ``SandboxSpec`` defaults -- if a caller left one of these values
# unchanged, the platform default from ConfigRegistry wins. Callers
# that pass a non-default explicitly (``vcpu=4``) are honoured up to
# the policy cap.
_SPEC_DEFAULT_VCPU = 1
_SPEC_DEFAULT_MEM_MB = 512


@dataclass(frozen=True, slots=True)
class SandboxConfig:
    """Point-in-time snapshot of every ``sandbox_*`` platform config key.

    Read once per :meth:`SandboxService.run` invocation via
    :class:`ConfigRegistry` so an operator PUT /config edit lands on
    the next dispatch without a worker restart -- same convention every
    other platform service follows.
    """

    backend: str
    ssh_host: str
    ssh_user: str
    ssh_port: int
    default_timeout_s: float
    max_timeout_s: float
    allow_network: bool
    default_vcpu: int
    default_mem_mb: int
    output_max_bytes: int
    nsjail_bin: str
    firecracker_bin: str
    jailer_bin: str
    rootfs_path: str
    kernel_path: str
    system_name: str = ""
    system_id: int | None = None


@dataclass(frozen=True, slots=True)
class SandboxProbe:
    """Result of a bounded live SSH round-trip to the sandbox host."""

    ok: bool
    detail: str
    duration_ms: int


class SandboxService:
    """Facade over :class:`SandboxBackend` implementations.

    Constructed with the platform :class:`PlatformSettings`; the
    :class:`SSHService` and :class:`ConfigRegistry` may be injected for
    tests (they default to the process-wide singletons the rest of the
    platform uses).
    """

    def __init__(
        self,
        settings: PlatformSettings,
        *,
        ssh_service: SSHService | None = None,
        config_registry: ConfigRegistry | None = None,
        backends: dict[str, SandboxBackend] | None = None,
    ) -> None:
        self._settings = settings
        self._ssh = ssh_service or SSHService(settings)
        self._registry = config_registry or ConfigRegistry()
        # Tests may inject a fake backend map; production uses the real
        # nsjail + firecracker backends.
        self._backends: dict[str, SandboxBackend] = backends or {
            NsjailBackend.name: NsjailBackend(),
            FirecrackerBackend.name: FirecrackerBackend(),
        }

    async def run(self, spec: SandboxSpec) -> SandboxResult:
        """Execute ``spec`` in a sandbox and return the result.

        Raises :class:`SandboxUnavailableError` when the operator has
        not provisioned a backend for this deployment (backend = "none"
        or empty ssh host). NEVER falls back to running ``spec.argv``
        un-isolated on the local host: the sandbox is the primitive,
        not a nice-to-have.
        """
        cfg = await self._load_config()

        if cfg.backend == "none" or not cfg.backend.strip():
            raise SandboxUnavailableError(
                "platform sandbox backend not configured; set "
                "platform.sandbox_backend to 'nsjail' or 'firecracker' "
                "and platform.sandbox_ssh_host to a Linux host."
            )
        if not cfg.ssh_host.strip():
            raise SandboxUnavailableError(
                f"platform sandbox backend {cfg.backend!r} is selected but "
                "platform.sandbox_ssh_host is empty; point it at a Linux "
                "sandbox host reachable via SSH."
            )

        backend = self._backends.get(cfg.backend)
        if backend is None:
            # An unknown backend is an operator misconfiguration, not
            # something the caller can act on. Fail closed.
            raise SandboxUnavailableError(
                f"platform.sandbox_backend={cfg.backend!r} is not a known "
                f"backend (supported: {sorted(self._backends)})."
            )

        normalized = self._apply_policy(spec, cfg)
        managed_sys = await self._resolve_managed_system(
            system_name=cfg.system_name,
            system_id=cfg.system_id,
            host=cfg.ssh_host,
        )
        host_payload = self._build_host_payload(cfg, managed_sys)

        _log.info(
            "sandbox.dispatch backend=%s argv0=%s timeout_s=%.1f network=%s",
            backend.name,
            normalized.argv[0] if normalized.argv else "",
            normalized.timeout_s,
            normalized.network,
        )
        try:
            result = await backend.run(
                normalized, ssh=self._ssh, host_payload=host_payload, cfg=cfg,
            )
        except SandboxExecutionError:
            # Backend already produced the right taxonomy; do not
            # double-wrap.
            raise
        except (
            AuthenticationError,
            UpstreamError,
            AILATimeoutError,
            ValidationError,
        ) as exc:
            # SSH-level faults surface as backend faults from the
            # caller's perspective.
            raise SandboxExecutionError(
                f"sandbox backend {backend.name} SSH transport failed: {exc}"
            ) from exc
        except (paramiko.SSHException, OSError, TimeoutError) as exc:
            raise SandboxExecutionError(
                f"sandbox backend {backend.name} infra failure: {exc}"
            ) from exc

        # Belt-and-braces stdout/stderr cap in case a backend forgot
        # to apply it. Backends already cap; this only clips if a
        # future backend regresses.
        return self._enforce_output_cap(result, cfg.output_max_bytes)

    # ------------------------------------------------------------------
    # Helpers -- kept package-private so tests can call them directly.
    # ------------------------------------------------------------------

    def _apply_policy(self, spec: SandboxSpec, cfg: SandboxConfig) -> SandboxSpec:
        """Return a copy of ``spec`` with the platform policy applied."""
        effective_timeout = min(float(spec.timeout_s), float(cfg.max_timeout_s))
        if effective_timeout <= 0.0:
            # A misconfigured max_timeout_s of 0 would otherwise clamp
            # every dispatch to 0s; keep at least 1s so the backend can
            # produce a coherent timeout result.
            effective_timeout = max(1.0, float(cfg.default_timeout_s))
        effective_network = bool(spec.network) if cfg.allow_network else False
        effective_vcpu = spec.vcpu if spec.vcpu != _SPEC_DEFAULT_VCPU else cfg.default_vcpu
        effective_mem = spec.mem_mb if spec.mem_mb != _SPEC_DEFAULT_MEM_MB else cfg.default_mem_mb
        return spec.model_copy(update={
            "timeout_s": effective_timeout,
            "network": effective_network,
            "vcpu": max(1, int(effective_vcpu)),
            "mem_mb": max(1, int(effective_mem)),
        })

    async def _resolve_managed_system(
        self,
        *,
        system_name: str = "",
        system_id: int | None = None,
        host: str = "",
    ) -> ManagedSystemRecord | None:
        """Resolve a ManagedSystemRecord from the platform systems registry.

        Resolution precedence:
        1. Explicit system_id from config
        2. Explicit system_name from config
        3. Registered system with role == "sandbox"
        4. Registered system matching the configured host IP/hostname
        """
        try:
            async with async_session_scope() as session:
                if system_id is not None:
                    row = await session.get(ManagedSystemRecord, system_id)
                    if row is not None:
                        return row
                if system_name:
                    stmt = select(ManagedSystemRecord).where(ManagedSystemRecord.name == system_name)
                    row = (await session.exec(stmt)).first()
                    if row is not None:
                        return row
                # Fallback: check for system explicitly tagged with role == "sandbox"
                stmt = select(ManagedSystemRecord).where(ManagedSystemRecord.role == "sandbox")
                row = (await session.exec(stmt)).first()
                if row is not None:
                    return row
                # Fallback: check for registered system matching the host
                if host:
                    stmt = select(ManagedSystemRecord).where(ManagedSystemRecord.host == host)
                    row = (await session.exec(stmt)).first()
                    if row is not None:
                        return row
        except (OSError, RuntimeError, TimeoutError, ValueError, AttributeError) as exc:
            _log.debug("failed to resolve managed system for sandbox: %s", exc)
        return None

    def _build_host_payload(
        self,
        cfg: SandboxConfig,
        managed_sys: Any | None = None,
    ) -> SSHIntegrationInput:
        """Compose the SSH integration payload for the sandbox host.

        When a registered system from the platform Systems Registry
        (:class:`ManagedSystemRecord`) is resolved, its stored credentials,
        private key secret, and known host keys are passed directly so
        operators configure SSH authentication once in the fleet registry.
        """
        if managed_sys is not None:
            return SSHIntegrationInput(
                name=managed_sys.name or "sandbox-host",
                host=managed_sys.host,
                username=managed_sys.username or cfg.ssh_user or "root",
                port=managed_sys.port or cfg.ssh_port or 22,
                distro=managed_sys.distro or "linux",
                description=managed_sys.description or "Platform managed sandbox host.",
                private_key_path=managed_sys.private_key_path,
                private_key_secret_id=managed_sys.private_key_secret_id,
                private_key_passphrase_secret_id=managed_sys.private_key_passphrase_secret_id,
                password_secret_id=managed_sys.password_secret_id,
                known_hosts_path=managed_sys.known_hosts_path,
                host_key_fingerprint=managed_sys.host_key_fingerprint,
            )
        return SSHIntegrationInput(
            name="sandbox-host",
            host=cfg.ssh_host,
            username=cfg.ssh_user or "root",
            port=cfg.ssh_port,
            distro="linux",
            description="Platform sandbox host (issue #147).",
        )

    def _enforce_output_cap(self, result: SandboxResult, cap: int) -> SandboxResult:
        """Clip stdout / stderr to ``cap`` bytes if the backend did not."""
        if cap <= 0:
            return result
        truncated = result.truncated
        stdout_bytes = result.stdout.encode("utf-8", errors="ignore")
        stderr_bytes = result.stderr.encode("utf-8", errors="ignore")
        new_stdout = result.stdout
        new_stderr = result.stderr
        if len(stdout_bytes) > cap:
            new_stdout = stdout_bytes[:cap].decode("utf-8", errors="replace")
            truncated = True
        if len(stderr_bytes) > cap:
            new_stderr = stderr_bytes[:cap].decode("utf-8", errors="replace")
            truncated = True
        # ``output_files`` cap is already applied by ``collect_outputs``.
        if truncated == result.truncated and new_stdout is result.stdout and new_stderr is result.stderr:
            return result
        return result.model_copy(update={
            "stdout": new_stdout,
            "stderr": new_stderr,
            "truncated": truncated,
        })

    async def probe(self, *, connect_timeout: float = 5.0, command_timeout: float = 8.0) -> SandboxProbe:
        """Bounded live SSH round-trip using the configured sandbox host.

        Returns ok=False with an actionable detail (never raises) when the
        backend is 'none', the host is empty, or the SSH round-trip fails.
        """
        cfg = await self._load_config()
        if cfg.backend == "none" or not cfg.backend.strip():
            return SandboxProbe(
                ok=False,
                detail=(
                    "sandbox_backend is 'none'; set it to 'nsjail' or "
                    "'firecracker' and select a registered system or set sandbox_ssh_host."
                ),
                duration_ms=0,
            )
        if not cfg.ssh_host.strip():
            return SandboxProbe(
                ok=False,
                detail="No sandbox host configured or registered; select a registered system or set sandbox_ssh_host.",
                duration_ms=0,
            )
        managed_sys = await self._resolve_managed_system(
            system_name=cfg.system_name,
            system_id=cfg.system_id,
            host=cfg.ssh_host,
        )
        payload = self._build_host_payload(cfg, managed_sys)
        start = time.monotonic()
        try:
            _, _, exit_code = await asyncio.wait_for(
                self._ssh.run_command_full(
                    payload,
                    "true",
                    timeout_seconds=command_timeout,
                    connect_timeout=connect_timeout,
                ),
                timeout=connect_timeout + command_timeout + 5.0,
            )
        except (AuthenticationError, UpstreamError, AILATimeoutError, ValidationError) as exc:
            return SandboxProbe(
                ok=False,
                detail=f"SSH probe failed: {exc}",
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        except (paramiko.SSHException, OSError, TimeoutError) as exc:
            return SandboxProbe(
                ok=False,
                detail=f"SSH probe failed: {exc}",
                duration_ms=int((time.monotonic() - start) * 1000),
            )
        duration_ms = int((time.monotonic() - start) * 1000)
        sys_desc = f" [{managed_sys.name}]" if managed_sys and managed_sys.name else ""
        if exit_code == 0:
            return SandboxProbe(
                ok=True,
                detail=f"ssh round-trip ok ({payload.username}@{payload.host}:{payload.port}){sys_desc}",
                duration_ms=duration_ms,
            )
        return SandboxProbe(
            ok=False,
            detail=f"remote probe command exited {exit_code}",
            duration_ms=duration_ms,
        )

    async def describe(self) -> SandboxConfig:
        """Public live snapshot of the sandbox config for admin/status surfaces.

        Reads the same ConfigRegistry-resolved values ``run`` uses, so a
        readiness probe reflects operator PUT /config edits without a restart.
        """
        return await self._load_config()

    async def _load_config(self) -> SandboxConfig:
        """Read every ``sandbox_*`` platform key from ConfigRegistry."""
        async def _get(name: str, default: Any) -> Any:
            raw = await self._registry.get("platform", name)
            if raw is None:
                return default
            return raw

        backend = str(await _get("sandbox_backend", "none")).strip() or "none"
        ssh_host = str(await _get("sandbox_ssh_host", "")).strip()
        ssh_user = str(await _get("sandbox_ssh_user", "")).strip()
        system_name = str(await _get("sandbox_system_name", "")).strip()
        try:
            system_id_raw = await _get("sandbox_system_id", None)
            system_id = int(system_id_raw) if system_id_raw is not None else None
        except (TypeError, ValueError):
            system_id = None
        try:
            ssh_port = int(await _get("sandbox_ssh_port", 22))
        except (TypeError, ValueError):
            ssh_port = 22
        try:
            default_timeout_s = float(await _get("sandbox_default_timeout_s", 30.0))
        except (TypeError, ValueError):
            default_timeout_s = 30.0
        try:
            max_timeout_s = float(await _get("sandbox_max_timeout_s", 300.0))
        except (TypeError, ValueError):
            max_timeout_s = 300.0
        allow_network_raw = await _get("sandbox_allow_network", False)
        allow_network = bool(allow_network_raw) if isinstance(allow_network_raw, bool) else (
            str(allow_network_raw).strip().lower() in ("1", "true", "yes", "on")
        )
        try:
            default_vcpu = int(await _get("sandbox_vcpu", 1))
        except (TypeError, ValueError):
            default_vcpu = 1
        try:
            default_mem_mb = int(await _get("sandbox_mem_mb", 512))
        except (TypeError, ValueError):
            default_mem_mb = 512
        try:
            output_max_bytes = int(await _get("sandbox_output_max_bytes", 1_048_576))
        except (TypeError, ValueError):
            output_max_bytes = 1_048_576

        nsjail_bin = str(await _get("sandbox_nsjail_bin", "nsjail")).strip() or "nsjail"
        firecracker_bin = str(await _get("sandbox_firecracker_bin", "firecracker")).strip() or "firecracker"
        jailer_bin = str(await _get("sandbox_jailer_bin", "jailer")).strip() or "jailer"
        rootfs_path = str(await _get("sandbox_rootfs_path", "")).strip()
        kernel_path = str(await _get("sandbox_kernel_path", "")).strip()

        # If ssh_host is unset or system_name/id is specified, resolve from Systems Registry
        if not ssh_host or system_name or system_id is not None:
            managed_sys = await self._resolve_managed_system(
                system_name=system_name,
                system_id=system_id,
                host=ssh_host,
            )
            if managed_sys is not None:
                ssh_host = managed_sys.host or ssh_host
                ssh_user = managed_sys.username or ssh_user or "root"
                ssh_port = managed_sys.port or ssh_port or 22
                system_name = managed_sys.name or system_name
                system_id = managed_sys.id or system_id

        return SandboxConfig(
            backend=backend,
            ssh_host=ssh_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            default_timeout_s=default_timeout_s,
            max_timeout_s=max_timeout_s,
            allow_network=allow_network,
            default_vcpu=default_vcpu,
            default_mem_mb=default_mem_mb,
            output_max_bytes=output_max_bytes,
            nsjail_bin=nsjail_bin,
            firecracker_bin=firecracker_bin,
            jailer_bin=jailer_bin,
            rootfs_path=rootfs_path,
            kernel_path=kernel_path,
            system_name=system_name,
            system_id=system_id,
        )
