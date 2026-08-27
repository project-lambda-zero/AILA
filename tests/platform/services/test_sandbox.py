"""DB-light unit tests for the platform sandbox service (issue #147).

These tests exercise the pure logic paths -- policy enforcement, argv
composition, output caps, spec validation -- with the SSH transport
mocked out. No live Linux sandbox host is needed. The Firecracker /
nsjail live-execution paths are covered by the (deploy-time) integration
harness on a real sandbox host.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any

import pytest
from pydantic import ValidationError as PydanticValidationError

from aila.platform.services.sandbox import (
    SandboxExecutionError,
    SandboxResult,
    SandboxService,
    SandboxSpec,
    SandboxUnavailableError,
)
from aila.platform.services.sandbox.backends.nsjail import (
    NsjailBackend,
    build_nsjail_argv,
)
from aila.platform.services.sandbox.service import SandboxConfig

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeRegistry:
    """Minimal :class:`ConfigRegistry` stand-in returning a fixed dict."""

    def __init__(self, values: dict[str, Any]) -> None:
        self._values = values

    async def get(self, namespace: str, key: str) -> Any:
        assert namespace == "platform"
        return self._values.get(key)


class _FakeSSH:
    """Stand-in for :class:`SSHService` that records every dispatched command."""

    def __init__(self, *, run_command_full=None) -> None:
        self.commands: list[tuple[str, float | None]] = []
        self._run_command_full = run_command_full

    async def run_command_full(
        self,
        integration,
        command: str,
        timeout_seconds: float | None = None,
        pool=None,
        connect_timeout: float = 15.0,
    ) -> tuple[str, str, int]:
        del integration, pool, connect_timeout
        self.commands.append((command, timeout_seconds))
        if self._run_command_full is not None:
            return await self._run_command_full(command, timeout_seconds)
        return "", "", 0

    async def upload_file(self, integration, local_path, remote_path, *, timeout_seconds=None):
        del integration, local_path, remote_path, timeout_seconds

    async def download_file(self, integration, remote_path, local_path, *, timeout_seconds=None):
        del integration, remote_path, local_path, timeout_seconds


class _StubBackend:
    """Predictable backend used to assert the service policy pipeline."""

    name = "stub"

    def __init__(self, response: SandboxResult) -> None:
        self.response = response
        self.received: SandboxSpec | None = None
        self.received_cfg: SandboxConfig | None = None

    async def run(self, spec, *, ssh, host_payload, cfg):
        del ssh, host_payload
        self.received = spec
        self.received_cfg = cfg
        return self.response


def _cfg(**overrides: Any) -> SandboxConfig:
    """Build a fully-populated :class:`SandboxConfig` for policy tests."""
    base = SandboxConfig(
        backend="stub",
        ssh_host="sandbox.internal",
        ssh_user="sandbox",
        ssh_port=22,
        default_timeout_s=30.0,
        max_timeout_s=300.0,
        allow_network=False,
        default_vcpu=1,
        default_mem_mb=512,
        output_max_bytes=1024,
        nsjail_bin="nsjail",
        firecracker_bin="firecracker",
        jailer_bin="jailer",
        rootfs_path="",
        kernel_path="",
    )
    return replace(base, **overrides)


def _make_service(cfg: SandboxConfig, backend: _StubBackend, *, ssh: _FakeSSH | None = None) -> SandboxService:
    """Wire a SandboxService against fakes without hitting ConfigRegistry."""
    service = SandboxService.__new__(SandboxService)
    service._settings = object()  # type: ignore[attr-defined]
    service._ssh = ssh or _FakeSSH()  # type: ignore[attr-defined]
    service._registry = None  # type: ignore[attr-defined]
    service._backends = {backend.name: backend}  # type: ignore[attr-defined]
    # ``run`` reads config via _load_config; stub it to return ``cfg`` directly.
    async def _load() -> SandboxConfig:
        return cfg
    service._load_config = _load  # type: ignore[attr-defined]
    return service


# ---------------------------------------------------------------------------
# 1. SandboxSpec validation
# ---------------------------------------------------------------------------


def test_sandboxspec_rejects_empty_argv() -> None:
    with pytest.raises(PydanticValidationError):
        SandboxSpec(argv=[])


def test_sandboxspec_rejects_empty_string_in_argv() -> None:
    with pytest.raises(PydanticValidationError):
        SandboxSpec(argv=["ls", ""])


def test_sandboxspec_rejects_absolute_input_file_path() -> None:
    with pytest.raises(PydanticValidationError):
        SandboxSpec(argv=["cat", "/etc/passwd"], input_files={"/etc/passwd": "root:x:0:0"})


def test_sandboxspec_rejects_dotdot_input_file_path() -> None:
    with pytest.raises(PydanticValidationError):
        SandboxSpec(argv=["cat", "foo"], input_files={"../escape": "x"})


def test_sandboxspec_rejects_dotdot_output_glob() -> None:
    with pytest.raises(PydanticValidationError):
        SandboxSpec(argv=["ls"], output_globs=["../*"])


def test_sandboxspec_rejects_zero_timeout() -> None:
    with pytest.raises(PydanticValidationError):
        SandboxSpec(argv=["ls"], timeout_s=0.0)


def test_sandboxspec_rejects_relative_workdir() -> None:
    with pytest.raises(PydanticValidationError):
        SandboxSpec(argv=["ls"], workdir="work")


# ---------------------------------------------------------------------------
# 2. SandboxUnavailableError -- backend=none / host empty
# ---------------------------------------------------------------------------


def _run(service: SandboxService, spec: SandboxSpec) -> SandboxResult:
    return asyncio.get_event_loop().run_until_complete(service.run(spec))


def test_service_raises_unavailable_when_backend_none() -> None:
    cfg = _cfg(backend="none", ssh_host="sandbox.internal")
    backend = _StubBackend(response=SandboxResult(backend="stub", exit_code=0))
    service = _make_service(cfg, backend)
    with pytest.raises(SandboxUnavailableError, match="platform sandbox backend not configured"):
        asyncio.run(service.run(SandboxSpec(argv=["/bin/true"])))


def test_service_raises_unavailable_when_ssh_host_empty() -> None:
    cfg = _cfg(backend="stub", ssh_host="")
    backend = _StubBackend(response=SandboxResult(backend="stub", exit_code=0))
    service = _make_service(cfg, backend)
    with pytest.raises(SandboxUnavailableError, match="sandbox_ssh_host is empty"):
        asyncio.run(service.run(SandboxSpec(argv=["/bin/true"])))


def test_service_raises_unavailable_on_unknown_backend() -> None:
    cfg = _cfg(backend="qemu", ssh_host="sandbox.internal")
    backend = _StubBackend(response=SandboxResult(backend="stub", exit_code=0))
    service = _make_service(cfg, backend)
    with pytest.raises(SandboxUnavailableError, match="is not a known"):
        asyncio.run(service.run(SandboxSpec(argv=["/bin/true"])))


# ---------------------------------------------------------------------------
# 3. Policy enforcement -- clamp timeout, force-off network, defaults
# ---------------------------------------------------------------------------


def test_policy_clamps_timeout_to_max() -> None:
    cfg = _cfg(max_timeout_s=60.0)
    backend = _StubBackend(response=SandboxResult(backend="stub", exit_code=0))
    service = _make_service(cfg, backend)
    asyncio.run(service.run(SandboxSpec(argv=["/bin/true"], timeout_s=600.0)))
    assert backend.received is not None
    assert backend.received.timeout_s == pytest.approx(60.0)


def test_policy_forces_network_off_when_not_allowed() -> None:
    cfg = _cfg(allow_network=False)
    backend = _StubBackend(response=SandboxResult(backend="stub", exit_code=0))
    service = _make_service(cfg, backend)
    asyncio.run(service.run(SandboxSpec(argv=["/bin/true"], network=True)))
    assert backend.received is not None
    assert backend.received.network is False


def test_policy_permits_network_when_allowed() -> None:
    cfg = _cfg(allow_network=True)
    backend = _StubBackend(response=SandboxResult(backend="stub", exit_code=0))
    service = _make_service(cfg, backend)
    asyncio.run(service.run(SandboxSpec(argv=["/bin/true"], network=True)))
    assert backend.received is not None
    assert backend.received.network is True


def test_policy_applies_platform_vcpu_and_mem_defaults_when_spec_default() -> None:
    cfg = _cfg(default_vcpu=4, default_mem_mb=2048)
    backend = _StubBackend(response=SandboxResult(backend="stub", exit_code=0))
    service = _make_service(cfg, backend)
    asyncio.run(service.run(SandboxSpec(argv=["/bin/true"])))
    assert backend.received is not None
    # Spec defaults are 1 vcpu / 512 MiB; the platform defaults override
    # exactly when the caller left them alone.
    assert backend.received.vcpu == 4
    assert backend.received.mem_mb == 2048


def test_policy_honours_explicit_non_default_vcpu_and_mem() -> None:
    cfg = _cfg(default_vcpu=4, default_mem_mb=2048)
    backend = _StubBackend(response=SandboxResult(backend="stub", exit_code=0))
    service = _make_service(cfg, backend)
    asyncio.run(service.run(
        SandboxSpec(argv=["/bin/true"], vcpu=2, mem_mb=768)
    ))
    assert backend.received is not None
    assert backend.received.vcpu == 2
    assert backend.received.mem_mb == 768


# ---------------------------------------------------------------------------
# 4. Output cap -- stdout > cap sets truncated=True
# ---------------------------------------------------------------------------


def test_output_truncation_sets_truncated_flag() -> None:
    huge = "x" * 4096
    cfg = _cfg(output_max_bytes=128)
    backend = _StubBackend(response=SandboxResult(
        backend="stub", exit_code=0, stdout=huge, stderr="",
    ))
    service = _make_service(cfg, backend)
    result = asyncio.run(service.run(SandboxSpec(argv=["/bin/true"])))
    assert result.truncated is True
    assert len(result.stdout.encode("utf-8")) == 128


def test_output_not_truncated_below_cap() -> None:
    cfg = _cfg(output_max_bytes=1024)
    backend = _StubBackend(response=SandboxResult(
        backend="stub", exit_code=0, stdout="hello", stderr="",
    ))
    service = _make_service(cfg, backend)
    result = asyncio.run(service.run(SandboxSpec(argv=["/bin/true"])))
    assert result.truncated is False
    assert result.stdout == "hello"


# ---------------------------------------------------------------------------
# 5. Backend infra failure is rewrapped as SandboxExecutionError
# ---------------------------------------------------------------------------


class _FaultyBackend:
    name = "stub"

    async def run(self, spec, *, ssh, host_payload, cfg):
        del spec, ssh, host_payload, cfg
        raise OSError("broken pipe")


def test_service_rewraps_infra_failure_as_execution_error() -> None:
    cfg = _cfg(backend="stub", ssh_host="sandbox.internal")
    service = SandboxService.__new__(SandboxService)
    service._settings = object()  # type: ignore[attr-defined]
    service._ssh = _FakeSSH()  # type: ignore[attr-defined]
    service._registry = None  # type: ignore[attr-defined]
    service._backends = {"stub": _FaultyBackend()}  # type: ignore[attr-defined]
    async def _load() -> SandboxConfig:
        return cfg
    service._load_config = _load  # type: ignore[attr-defined]
    with pytest.raises(SandboxExecutionError, match="infra failure"):
        asyncio.run(service.run(SandboxSpec(argv=["/bin/true"])))


# ---------------------------------------------------------------------------
# 6. build_nsjail_argv composition
# ---------------------------------------------------------------------------


def test_nsjail_argv_contains_network_off_rlimit_timelimit_and_argv() -> None:
    spec = SandboxSpec(
        argv=["/bin/echo", "hello"],
        timeout_s=45.0,
        mem_mb=256,
        network=False,
        workdir="/work",
    )
    argv = build_nsjail_argv(spec, nsjail_bin="/usr/bin/nsjail", workspace_remote_root="/tmp/aila-sbx/x")
    # network off: --disable_clone_newnet must be absent (its presence
    # means "grant host network"; nsjail default is fresh net-namespace
    # isolation).
    assert "--disable_clone_newnet" not in argv
    # rlimit_as is present with the mem_mb value.
    assert "--rlimit_as" in argv
    assert argv[argv.index("--rlimit_as") + 1] == "256"
    # time_limit is present with the wall-clock timeout (rounded up).
    assert "--time_limit" in argv
    assert argv[argv.index("--time_limit") + 1] == "45"
    # /tmp is bind-mounted read-write, covering the /tmp/aila-sbx/x workspace.
    assert "--bindmount" in argv
    assert argv[argv.index("--bindmount") + 1] == "/tmp"
    # cwd is applied to workspace.
    assert "--cwd" in argv
    assert argv[argv.index("--cwd") + 1] == "/tmp/aila-sbx/x"
    # The spec's argv appears after the terminating '--'.
    dash_idx = argv.index("--")
    assert argv[dash_idx + 1 :] == ["/bin/echo", "hello"]
    # nsjail binary is argv[0].
    assert argv[0] == "/usr/bin/nsjail"


def test_nsjail_argv_flips_network_flag_when_allowed() -> None:
    spec = SandboxSpec(argv=["/bin/true"], network=True, timeout_s=30.0)
    argv = build_nsjail_argv(spec, nsjail_bin="nsjail", workspace_remote_root="/tmp/x")
    assert "--disable_clone_newnet" in argv


def test_nsjail_argv_wraps_bare_command_in_shell() -> None:
    spec = SandboxSpec(argv=["uname", "-a"])
    argv = build_nsjail_argv(spec, nsjail_bin="nsjail", workspace_remote_root="/tmp/x")
    dash_idx = argv.index("--")
    assert argv[dash_idx + 1 :] == ["/bin/sh", "-c", "uname -a"]


def test_nsjail_argv_exports_env_vars() -> None:
    spec = SandboxSpec(argv=["/bin/env"], env={"FOO": "bar", "BAZ": "qux"})
    argv = build_nsjail_argv(spec, nsjail_bin="nsjail", workspace_remote_root="/tmp/x")
    # env is emitted in sorted order for determinism and ensures PATH is populated.
    env_pairs = [argv[i + 1] for i, tok in enumerate(argv) if tok == "--env"]
    assert "BAZ=qux" in env_pairs
    assert "FOO=bar" in env_pairs
    assert any(p.startswith("PATH=") for p in env_pairs)


# ---------------------------------------------------------------------------
# 7. NsjailBackend end-to-end with a fake SSH (verifies command captured)
# ---------------------------------------------------------------------------


def test_nsjail_backend_dispatches_wrapped_command_over_ssh() -> None:
    """End-to-end shape: probe -> mkdir -> nsjail command -> cleanup."""
    async def fake_run_command_full(cmd: str, timeout: float | None):
        if cmd.startswith("command -v"):
            return "/usr/bin/nsjail\n", "", 0
        if cmd.startswith("mkdir"):
            return "", "", 0
        if cmd.startswith("rm -rf"):
            return "", "", 0
        # The nsjail invocation itself: no stdin, program returns "hi".
        if "/usr/bin/nsjail" in cmd:
            return "hi\n", "", 0
        return "", "", 0

    ssh = _FakeSSH(run_command_full=fake_run_command_full)
    cfg = _cfg(backend="nsjail", ssh_host="sandbox.internal", output_max_bytes=1024)
    backend = NsjailBackend()
    result = asyncio.run(backend.run(
        SandboxSpec(argv=["/bin/echo", "hi"], timeout_s=10.0, network=False),
        ssh=ssh, host_payload=object(), cfg=cfg,
    ))
    assert result.backend == "nsjail"
    assert result.exit_code == 0
    assert result.stdout.strip() == "hi"
    assert result.timed_out is False
    assert result.oom is False
    # The captured commands include an nsjail invocation composed by
    # build_nsjail_argv -- assert the shape is right.
    nsjail_commands = [c for c, _ in ssh.commands if "/usr/bin/nsjail" in c and "--mode" in c]
    assert nsjail_commands, "no nsjail command dispatched over ssh"
    nsjail_cmd = nsjail_commands[0]
    assert "--time_limit" in nsjail_cmd
    assert "--rlimit_as" in nsjail_cmd
    assert "--bindmount" in nsjail_cmd
    # network=False -> flag absent
    assert "--disable_clone_newnet" not in nsjail_cmd
