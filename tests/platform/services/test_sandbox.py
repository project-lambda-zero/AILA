"""DB-light unit tests for the platform sandbox service (issue #147).

These tests exercise the pure logic paths -- policy enforcement, argv
composition, output caps, spec validation -- with the SSH transport
mocked out. No live Linux sandbox host is needed. The Firecracker /
nsjail live-execution paths are covered by the (deploy-time) integration
harness on a real sandbox host.
"""
from __future__ import annotations

import asyncio
import shlex
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError as PydanticValidationError

from aila.platform.exceptions import ValidationError as AILAValidationError
from aila.platform.services.sandbox import (
    SandboxExecutionError,
    SandboxPolicyError,
    SandboxResult,
    SandboxService,
    SandboxSpec,
    SandboxUnavailableError,
)
from aila.platform.services.sandbox.backends.base import (
    HostWorkspace,
    collect_outputs,
    host_workspace,
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
    supports_network = True
    enforces_egress = True

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

    async def _no_managed_system(**kwargs: Any) -> None:
        return None

    service._resolve_managed_system = _no_managed_system  # type: ignore[attr-defined]
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


def test_policy_rejects_networked_spec_when_not_allowed() -> None:
    cfg = _cfg(allow_network=False)
    backend = _StubBackend(response=SandboxResult(backend="stub", exit_code=0))
    service = _make_service(cfg, backend)
    with pytest.raises(SandboxPolicyError, match="sandbox_allow_network is disabled"):
        asyncio.run(service.run(SandboxSpec(argv=["/bin/true"], network=True)))
    assert backend.received is None


def test_policy_rejects_networked_spec_when_backend_cannot_enforce_egress() -> None:
    cfg = _cfg(allow_network=True)
    backend = _StubBackend(response=SandboxResult(backend="stub", exit_code=0))
    backend.enforces_egress = False
    service = _make_service(cfg, backend)
    with pytest.raises(SandboxPolicyError, match="cannot enforce per-run egress"):
        asyncio.run(service.run(SandboxSpec(argv=["/bin/true"], network=True)))
    assert backend.received is None


def test_policy_rejects_networked_spec_when_backend_lacks_network_support() -> None:
    cfg = _cfg(allow_network=True)
    backend = _StubBackend(response=SandboxResult(backend="stub", exit_code=0))
    backend.supports_network = False
    service = _make_service(cfg, backend)
    with pytest.raises(SandboxPolicyError, match="does not support network access"):
        asyncio.run(service.run(SandboxSpec(argv=["/bin/true"], network=True)))
    assert backend.received is None


def test_policy_accepts_offline_spec_when_network_not_allowed() -> None:
    cfg = _cfg(allow_network=False)
    backend = _StubBackend(response=SandboxResult(backend="stub", exit_code=0))
    service = _make_service(cfg, backend)
    asyncio.run(service.run(SandboxSpec(argv=["/bin/true"], network=False)))
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

    async def _no_managed_system(**kwargs: Any) -> None:
        return None

    service._resolve_managed_system = _no_managed_system  # type: ignore[attr-defined]
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
    # Fresh in-memory bounded tmpfs for /tmp isolates from host /tmp.
    assert "--tmpfsmount" in argv
    assert argv[argv.index("--tmpfsmount") + 1] == "/tmp:size=256M"
    # Specific workspace directory is bind-mounted to spec.workdir R/W.
    assert "--bindmount" in argv
    assert "/tmp/aila-sbx/x:/work" in argv
    # Host device tree and /home are omitted.
    assert "/dev" not in argv
    assert "--hostname" in argv
    assert argv[argv.index("--hostname") + 1] == "sandbox"
    # Process, file-size, and core ceilings are enforced.
    assert "--rlimit_nproc" in argv
    assert argv[argv.index("--rlimit_nproc") + 1] == "512"
    assert "--rlimit_fsize" in argv
    assert "--rlimit_core" in argv
    # System runtime trees are mounted read-only; host /home is not mounted.
    assert "--bindmount_ro" in argv
    assert "/usr" in argv
    assert "--chroot" not in argv
    # cwd is applied to workspace.
    assert "--cwd" in argv
    assert argv[argv.index("--cwd") + 1] == "/work"
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


# ---------------------------------------------------------------------------
# 8. Output collection hardening
# ---------------------------------------------------------------------------

_ROOT = "/tmp/aila-sandbox/run-test"
_WORKSPACE = HostWorkspace(remote_root=_ROOT, run_id="test")


class _FakeHost:
    """Scripted host for output collection.

    Answers the enumeration command (``for f in <pattern>``) from ``matches``,
    the staging command (``head -c N -- <src> > <dst>``) against ``files``,
    and SFTP ``download_file`` by reading ``files``.
    """

    def __init__(self, files: dict[str, bytes], matches: dict[str, list[str]]) -> None:
        self.files = dict(files)
        self.matches = matches
        self.commands: list[str] = []
        self.downloads: list[str] = []

    async def run_command_full(self, integration, command, timeout_seconds=None, pool=None, connect_timeout=15.0):
        del integration, timeout_seconds, pool, connect_timeout
        self.commands.append(command)
        if command.startswith("head "):
            tokens = shlex.split(command)
            count, source, staged = int(tokens[2]), tokens[4], tokens[6]
            self.files[staged] = self.files[source][:count]
            return "", "", 0
        if command.startswith("cd "):
            pattern = command.split("for f in ", 1)[1].split(";", 1)[0]
            return "".join(name + "\0" for name in self.matches.get(pattern, [])), "", 0
        return "", "", 0

    async def download_file(self, integration, remote_path, local_path, *, timeout_seconds=None):
        del integration, timeout_seconds
        self.downloads.append(remote_path)
        Path(local_path).write_bytes(self.files[remote_path])


@pytest.mark.parametrize(
    "pattern",
    [
        "$(touch /tmp/pwned)",
        "`id`",
        "out;touch /tmp/pwned",
        "out|tee /tmp/pwned",
        "out&&touch /tmp/pwned",
        "$HOME/*",
        "out/*'x'",
        "out/* > /tmp/pwned",
        "{a,b}",
        "~/out",
    ],
)
def test_output_glob_with_shell_syntax_is_rejected_before_any_command(pattern: str) -> None:
    host = _FakeHost(files={}, matches={})
    with pytest.raises(AILAValidationError):
        asyncio.run(collect_outputs(host, object(), _WORKSPACE, [pattern], per_file_cap=0))
    assert host.commands == []


@pytest.mark.parametrize("pattern", ["/etc/*", "../*", "out/../../*"])
def test_output_glob_absolute_or_traversal_is_rejected(pattern: str) -> None:
    host = _FakeHost(files={}, matches={})
    with pytest.raises(AILAValidationError):
        asyncio.run(collect_outputs(host, object(), _WORKSPACE, [pattern], per_file_cap=0))
    assert host.commands == []


def test_enumerated_names_escaping_the_workspace_are_never_downloaded() -> None:
    host = _FakeHost(
        files={f"{_ROOT}/ok.txt": b"fine", "/etc/passwd": b"root:x:0:0"},
        matches={"*": ["../../../etc/passwd", "/etc/passwd", "ok.txt"]},
    )
    files, truncated = asyncio.run(collect_outputs(host, object(), _WORKSPACE, ["*"], per_file_cap=0))
    assert files == {"ok.txt": "fine"}
    assert truncated is False
    assert host.downloads == [f"{_ROOT}/ok.txt"]


def test_legitimate_relative_globs_collect_inside_workspace() -> None:
    host = _FakeHost(
        files={
            f"{_ROOT}/out/a.json": b'{"a": 1}',
            f"{_ROOT}/out/b.json": b'{"b": 2}',
            f"{_ROOT}/result.txt": b"done",
        },
        matches={
            "out/*.json": ["out/a.json", "out/b.json"],
            "result.txt": ["result.txt"],
        },
    )
    files, truncated = asyncio.run(
        collect_outputs(host, object(), _WORKSPACE, ["out/*.json", "result.txt"], per_file_cap=0),
    )
    assert files == {"out/a.json": '{"a": 1}', "out/b.json": '{"b": 2}', "result.txt": "done"}
    assert truncated is False
    assert "for f in out/*.json; do" in host.commands[0]


def test_per_file_cap_transfers_at_most_cap_plus_one_bytes() -> None:
    host = _FakeHost(
        files={f"{_ROOT}/out/big.log": b"x" * 10},
        matches={"out/big.log": ["out/big.log"]},
    )
    files, truncated = asyncio.run(
        collect_outputs(host, object(), _WORKSPACE, ["out/big.log"], per_file_cap=4),
    )
    assert files == {"out/big.log": "xxxx"}
    assert truncated is True
    assert any(command.startswith("head -c 5 -- ") for command in host.commands)
    assert len(host.downloads) == 1
    assert host.downloads[0].startswith(f"{_ROOT}/.collect-")


# ---------------------------------------------------------------------------
# 9. Workspace permissions and nsjail identity
# ---------------------------------------------------------------------------


def test_host_workspace_run_dir_is_created_owner_only() -> None:
    host = _FakeSSH()

    async def scenario() -> str:
        async with host_workspace(host, object()) as workspace:
            return workspace.remote_root

    root = asyncio.run(scenario())
    commands = [command for command, _ in host.commands]
    assert commands[0] == f"mkdir -p /tmp/aila-sandbox && mkdir -m 700 {root}"
    assert commands[-1] == f"rm -rf -- {root}"


def test_nsjail_argv_runs_payload_as_unprivileged_user() -> None:
    spec = SandboxSpec(argv=["/bin/echo", "hi"], timeout_s=10.0, network=False)
    argv = build_nsjail_argv(spec, nsjail_bin="nsjail", workspace_remote_root="/tmp/x")
    separator = argv.index("--")
    assert argv[argv.index("--user") + 1] == "65534"
    assert argv[argv.index("--group") + 1] == "65534"
    assert argv.index("--user") < separator
    assert argv.index("--group") < separator


@pytest.mark.parametrize(
    "pattern",
    [
        "$(touch /tmp/pwned)",
        "out;touch /tmp/pwned",
        "out/* > /tmp/pwned",
        "{a,b}",
        "~/out",
    ],
)
def test_sandbox_spec_rejects_shell_syntax_output_globs_at_construction(pattern: str) -> None:
    with pytest.raises(PydanticValidationError):
        SandboxSpec(argv=["/bin/echo"], output_globs=[pattern])


def test_sandbox_spec_accepts_legitimate_output_globs() -> None:
    spec = SandboxSpec(argv=["/bin/echo"], output_globs=["out/*.json", "result.txt", "logs/?.txt"])
    assert spec.output_globs == ["out/*.json", "result.txt", "logs/?.txt"]
