"""Deterministic tests for the OCI container sandbox backend (docker/podman over SSH).

Every SSH interaction is faked, so these tests never require a docker or
podman binary, a sandbox host, or network access. They pin the hardening
argv, the validation that runs before any SSH traffic, the workspace
input/output flow, streaming and cancellation cleanup, and output caps.
"""
from __future__ import annotations

import asyncio
import inspect
import shlex
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import paramiko
import pytest
from pydantic import ValidationError as PydanticValidationError

from aila.platform.services.sandbox import (
    SandboxExecutionError,
    SandboxResult,
    SandboxService,
    SandboxSpec,
)
from aila.platform.services.sandbox.backends import OciBackend, build_oci_run_argv
from aila.platform.services.sandbox.service import SandboxConfig
from aila.platform.services.ssh import CommandCancelledError

_DOCKER = "/usr/bin/docker"
_TIMEOUT = "/usr/bin/timeout"
_IMAGE = "aila/probe@sha256:" + "ab" * 32
_PAYLOAD = SimpleNamespace(host="sandbox.internal", port=22)


class _OciSSH:
    """Stand-in for :class:`SSHService` that routes commands by shape."""

    def __init__(
        self,
        *,
        run: tuple[str, str, int] = ("", "", 0),
        id_result: tuple[str, str, int] = ("1000\n1000\n", "", 0),
        image_result: tuple[str, str, int] = ("", "", 0),
        glob_stdout: str = "",
        run_raises: BaseException | None = None,
        cancel_raises: BaseException | None = None,
    ) -> None:
        self.run_result = run
        self.id_result = id_result
        self.image_result = image_result
        self.glob_stdout = glob_stdout
        self.run_raises = run_raises
        self.cancel_raises = cancel_raises
        self.commands: list[str] = []
        self.stream_calls: list[dict[str, Any]] = []
        self.uploads: list[tuple[str, str]] = []
        self.downloads: list[str] = []
        self.download_payload = b"hello"

    def _route(self, command: str) -> tuple[str, str, int]:
        if command.startswith("command -v "):
            name = command.split()[2]
            path = _TIMEOUT if name == "timeout" else f"/usr/bin/{name}"
            return f"{path}\n", "", 0
        if command == "id -u && id -g":
            return self.id_result
        if " image inspect " in command:
            return self.image_result
        if "--kill-after=" in command:
            return self.run_result
        if command.startswith("cd "):
            return self.glob_stdout, "", 0
        return "", "", 0

    async def run_command_full(
        self,
        integration,
        command: str,
        timeout_seconds: float | None = None,
        pool=None,
        connect_timeout: float = 15.0,
    ) -> tuple[str, str, int]:
        del integration, timeout_seconds, pool, connect_timeout
        self.commands.append(command)
        if "--kill-after=" in command and self.run_raises is not None:
            raise self.run_raises
        return self._route(command)

    async def run_command_streaming(
        self,
        integration,
        command: str,
        timeout_seconds: float | None = None,
        on_stdout=None,
        on_stderr=None,
        cancel_requested=None,
        cancel_command: str | None = None,
    ) -> tuple[str, str, int]:
        del integration
        self.commands.append(command)
        self.stream_calls.append({
            "command": command,
            "timeout_seconds": timeout_seconds,
            "on_stdout": on_stdout,
            "on_stderr": on_stderr,
            "cancel_requested": cancel_requested,
            "cancel_command": cancel_command,
        })
        if self.cancel_raises is not None:
            raise self.cancel_raises
        if on_stdout is not None:
            callback_result = on_stdout("stdout chunk")
            if inspect.isawaitable(callback_result):
                await callback_result
        return self.run_result

    async def upload_file(self, integration, local_path, remote_path, *, timeout_seconds=None):
        del integration, timeout_seconds
        self.uploads.append((Path(local_path).read_text(encoding="utf-8"), remote_path))

    async def download_file(self, integration, remote_path, local_path, *, timeout_seconds=None):
        del integration, timeout_seconds
        self.downloads.append(remote_path)
        Path(local_path).write_bytes(self.download_payload)


def _cfg(**overrides: Any) -> SandboxConfig:
    base = SandboxConfig(
        backend="oci",
        ssh_host="sandbox.internal",
        ssh_user="sandbox",
        ssh_port=22,
        default_timeout_s=30.0,
        max_timeout_s=300.0,
        allow_network=True,
        default_vcpu=1,
        default_mem_mb=512,
        output_max_bytes=1024,
        nsjail_bin="nsjail",
        firecracker_bin="firecracker",
        jailer_bin="jailer",
        rootfs_path="",
        kernel_path="",
        oci_bin="docker",
        oci_network="bridge",
    )
    return replace(base, **overrides)


def _spec(**overrides: Any) -> SandboxSpec:
    fields: dict[str, Any] = {"argv": ["true"], "image": _IMAGE}
    fields.update(overrides)
    return SandboxSpec(**fields)


def _backend_run(spec: SandboxSpec, ssh: _OciSSH, cfg: SandboxConfig | None = None, **callbacks: Any) -> SandboxResult:
    # _OciSSH is a duck-typed fake of SSHService (only the methods the backend calls).
    return asyncio.run(
        OciBackend().run(spec, ssh=ssh, host_payload=_PAYLOAD, cfg=cfg or _cfg(), **callbacks)  # type: ignore[arg-type]
    )


def _run_command(ssh: _OciSSH) -> str:
    return next(c for c in ssh.commands if "--kill-after=" in c)


def _flag_value(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


def _argv(spec: SandboxSpec, *, network_mode: str = "none", uid: int = 1000, gid: int = 1000) -> list[str]:
    return build_oci_run_argv(
        spec,
        runtime=_DOCKER,
        timeout_bin=_TIMEOUT,
        image=_IMAGE,
        container_name="aila-sandbox-r1",
        workspace_remote_root="/tmp/aila/r1",
        uid=uid,
        gid=gid,
        network_mode=network_mode,
    )


def _result(backend: str) -> SandboxResult:
    return SandboxResult(
        backend=backend,
        exit_code=0,
        stdout="",
        stderr="",
        output_files={},
        duration_s=0.0,
        timed_out=False,
        oom=False,
        truncated=False,
    )


class _StubBackend:
    name = "stub"

    def __init__(self, backend_name: str) -> None:
        self.name = backend_name
        self.calls = 0

    async def run(self, spec, *, ssh, host_payload, cfg):
        del spec, ssh, host_payload, cfg
        self.calls += 1
        return _result(self.name)


def _service(cfg: SandboxConfig, backend: Any, ssh: _OciSSH) -> SandboxService:
    service = SandboxService.__new__(SandboxService)
    service._settings = object()  # type: ignore[attr-defined]
    service._ssh = ssh  # type: ignore[attr-defined]
    service._registry = None  # type: ignore[attr-defined]
    service._backends = {backend.name: backend}  # type: ignore[attr-defined]

    async def _load() -> SandboxConfig:
        return cfg

    async def _no_managed_system(**_kwargs: Any) -> None:
        return None

    service._load_config = _load  # type: ignore[attr-defined]
    service._resolve_managed_system = _no_managed_system  # type: ignore[attr-defined]
    return service


# ---------------------------------------------------------------------------
# Image pinning
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "image",
    ["alpine:3.19", "alpine:latest", "alpine", "alpine@sha256:abc", "docker.io/library/alpine"],
)
def test_mutable_or_malformed_image_rejected(image: str) -> None:
    with pytest.raises(PydanticValidationError):
        SandboxSpec(argv=["true"], image=image)


def test_immutable_digest_image_accepted() -> None:
    assert _spec().image == _IMAGE


def test_oci_service_requires_image() -> None:
    service = _service(_cfg(backend="oci"), OciBackend(), _OciSSH())
    with pytest.raises(SandboxExecutionError):
        asyncio.run(service.run(SandboxSpec(argv=["true"])))


def test_nsjail_service_refuses_image() -> None:
    backend = _StubBackend("nsjail")
    service = _service(_cfg(backend="nsjail"), backend, _OciSSH())
    with pytest.raises(SandboxExecutionError):
        asyncio.run(service.run(_spec()))
    assert backend.calls == 0


def test_service_dispatches_oci_end_to_end() -> None:
    ssh = _OciSSH()
    service = _service(_cfg(), OciBackend(), ssh)
    result = asyncio.run(service.run(_spec()))
    assert result.backend == "oci"
    assert result.exit_code == 0
    assert any("--kill-after=" in c for c in ssh.commands)


# ---------------------------------------------------------------------------
# Hardening argv
# ---------------------------------------------------------------------------


def test_hardening_flags_present() -> None:
    argv = _argv(_spec())
    assert "--entrypoint=" in argv
    assert "--read-only" in argv
    assert _flag_value(argv, "--cap-drop") == "ALL"
    assert _flag_value(argv, "--security-opt") == "no-new-privileges"
    assert _flag_value(argv, "--pids-limit") == "128"
    assert _flag_value(argv, "--user") == "1000:1000"
    assert _flag_value(argv, "--memory") == "512m"
    assert _flag_value(argv, "--tmpfs").startswith("/tmp:rw,noexec,nosuid,size=512m")


def test_no_privileged_or_host_namespace_flags() -> None:
    argv = _argv(_spec(), network_mode="none")
    assert "--privileged" not in argv
    assert "--pid" not in argv
    assert "--net" not in argv
    assert "--ipc" not in argv
    assert not any("docker.sock" in element for element in argv)
    assert _flag_value(argv, "--network") == "none"


def test_image_entrypoint_cleared_and_argv_is_exec_vector() -> None:
    argv = _argv(_spec(argv=["python3", "-c", "print(1)"]))
    assert argv[-4:] == [_IMAGE, "python3", "-c", "print(1)"]


def test_interactive_only_with_stdin() -> None:
    assert "--interactive" not in _argv(_spec())
    assert "--interactive" in _argv(_spec(stdin="payload"))


# ---------------------------------------------------------------------------
# Network policy
# ---------------------------------------------------------------------------


def test_network_none_when_not_granted() -> None:
    ssh = _OciSSH()
    _backend_run(_spec(network=False), ssh, _cfg(oci_network="bridge"))
    assert _flag_value(shlex.split(_run_command(ssh)), "--network") == "none"


def test_configured_network_when_granted() -> None:
    ssh = _OciSSH()
    _backend_run(_spec(network=True), ssh, _cfg(oci_network="bridge"))
    assert _flag_value(shlex.split(_run_command(ssh)), "--network") == "bridge"


@pytest.mark.parametrize("bad_network", ["host", "container:web", "bad name"])
def test_host_or_container_namespace_refused(bad_network: str) -> None:
    ssh = _OciSSH()
    with pytest.raises(SandboxExecutionError):
        _backend_run(_spec(network=True), ssh, _cfg(oci_network=bad_network))
    assert ssh.commands == []


# ---------------------------------------------------------------------------
# Env and argv injection
# ---------------------------------------------------------------------------


def test_env_value_is_single_argv_element() -> None:
    argv = _argv(_spec(env={"GREETING": "a b;c $(id)"}))
    index = argv.index("GREETING=a b;c $(id)")
    assert argv[index - 1] == "-e"


def test_spec_argv_stays_one_element_each_after_shell_round_trip() -> None:
    ssh = _OciSSH()
    _backend_run(_spec(argv=["sh", "-c", "echo $X; rm -rf /"], env={"X": "1 2"}), ssh)
    tokens = shlex.split(_run_command(ssh))
    assert tokens[-1] == "</dev/null"
    assert tokens[-4:-1] == ["sh", "-c", "echo $X; rm -rf /"]
    assert "X=1 2" in tokens


@pytest.mark.parametrize("env", [{"BAD-NAME": "x"}, {"1LEAD": "x"}])
def test_invalid_env_name_refused_before_ssh(env: dict[str, str]) -> None:
    ssh = _OciSSH()
    with pytest.raises(SandboxExecutionError):
        _backend_run(_spec(env=env), ssh)
    assert ssh.commands == []


@pytest.mark.parametrize("workdir", ["/", "/work,evil", "/work with space"])
def test_unsafe_workdir_refused_before_ssh(workdir: str) -> None:
    ssh = _OciSSH()
    with pytest.raises(SandboxExecutionError):
        _backend_run(_spec(workdir=workdir), ssh)
    assert ssh.commands == []


# ---------------------------------------------------------------------------
# Identity and image presence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("id_stdout", ["0\n0\n", "1000\n0\n", "0\n1000\n"])
def test_root_identity_refused(id_stdout: str) -> None:
    ssh = _OciSSH(id_result=(id_stdout, "", 0))
    with pytest.raises(SandboxExecutionError, match="root"):
        _backend_run(_spec(), ssh)
    assert not any("--kill-after=" in c for c in ssh.commands)


def test_missing_image_refused_without_pull() -> None:
    ssh = _OciSSH(image_result=("", "no such image", 1))
    with pytest.raises(SandboxExecutionError, match="not present"):
        _backend_run(_spec(), ssh)
    assert not any("--kill-after=" in c for c in ssh.commands)
    assert not any(" pull " in c for c in ssh.commands)


# ---------------------------------------------------------------------------
# Probing, workspace flow, and cleanup
# ---------------------------------------------------------------------------


def test_probe_uses_configured_runtime_and_timeout() -> None:
    ssh = _OciSSH()
    _backend_run(_spec(), ssh, _cfg(oci_bin="podman"))
    assert any(c.startswith("command -v podman") for c in ssh.commands)
    assert any(c.startswith("command -v timeout") for c in ssh.commands)
    assert not any(c.startswith("command -v docker") for c in ssh.commands)
    run_command = _run_command(ssh)
    assert run_command.startswith(_TIMEOUT)
    assert "/usr/bin/podman run" in run_command


def test_workspace_input_output_flow_and_cleanup() -> None:
    ssh = _OciSSH(glob_stdout="out/a.txt\0")
    result = _backend_run(
        _spec(input_files={"in/a.txt": "hi"}, output_globs=["out/*.txt"]),
        ssh,
    )
    assert len(ssh.uploads) == 1
    uploaded_content, remote = ssh.uploads[0]
    assert uploaded_content == "hi"
    assert remote.endswith("/in/a.txt")
    assert any("for f in out/*.txt" in c for c in ssh.commands)
    assert len(ssh.downloads) == 1
    assert result.output_files == {"out/a.txt": "hello"}
    assert any("rm -rf --" in c for c in ssh.commands)


def test_timeout_exit_maps_to_timed_out() -> None:
    result = _backend_run(_spec(), _OciSSH(run=("", "", 124)))
    assert result.timed_out is True
    assert result.exit_code is None
    assert result.oom is False


def test_output_is_clipped_to_cap_and_marked_truncated() -> None:
    result = _backend_run(
        _spec(),
        _OciSSH(run=("abcdefgh", "ijklmnop", 0)),
        _cfg(output_max_bytes=4),
    )
    assert result.stdout == "abcd"
    assert result.stderr == "ijkl"
    assert result.truncated is True


# ---------------------------------------------------------------------------
# Streaming, cancellation, and transport failure
# ---------------------------------------------------------------------------


def test_streaming_callbacks_forwarded_and_cancel_kills_named_container() -> None:
    ssh = _OciSSH()

    def on_stdout(_chunk: str) -> None:
        return None

    def on_stderr(_chunk: str) -> None:
        return None

    def cancel_requested() -> bool:
        return False

    _backend_run(
        _spec(),
        ssh,
        on_stdout=on_stdout,
        on_stderr=on_stderr,
        cancel_requested=cancel_requested,
    )
    call = ssh.stream_calls[0]
    assert call["on_stdout"] is on_stdout
    assert call["on_stderr"] is on_stderr
    assert call["cancel_requested"] is cancel_requested
    cancel_command = call["cancel_command"]
    assert cancel_command.startswith(f"{_DOCKER} rm -f aila-sandbox-")
    container = cancel_command.removeprefix(f"{_DOCKER} rm -f ")
    assert f"--name {container}" in call["command"]


def test_cancellation_maps_to_sandbox_error_and_still_removes_container() -> None:
    ssh = _OciSSH(cancel_raises=CommandCancelledError("cancelled"))
    with pytest.raises(SandboxExecutionError, match="cancelled"):
        _backend_run(_spec(), ssh, cancel_requested=lambda: True)
    assert any(c.startswith(f"{_DOCKER} rm -f aila-sandbox-") for c in ssh.commands)


def test_transport_failure_maps_to_sandbox_error_and_still_removes_container() -> None:
    ssh = _OciSSH(run_raises=paramiko.SSHException("connection dropped"))
    with pytest.raises(SandboxExecutionError, match="oci dispatch failed for run"):
        _backend_run(_spec(), ssh)
    assert any(c.startswith(f"{_DOCKER} rm -f aila-sandbox-") for c in ssh.commands)


def test_callback_failure_propagates_and_still_removes_container() -> None:
    ssh = _OciSSH()

    async def fail_callback(_chunk: str) -> None:
        raise RuntimeError("evidence callback failed")

    with pytest.raises(RuntimeError, match="evidence callback failed"):
        _backend_run(_spec(), ssh, on_stdout=fail_callback)
    assert any(c.startswith(f"{_DOCKER} rm -f aila-sandbox-") for c in ssh.commands)
