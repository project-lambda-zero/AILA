"""Live SSH output streaming, cancellation, and the firecracker streaming rejection.

The fake channel never reaches the network. Blocking reads are bounded so a
regression fails the test instead of hanging it.
"""

from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, patch

import paramiko
import pytest

from aila.platform.config import PlatformSettings
from aila.platform.contracts.platform import SSHIntegrationInput
from aila.platform.services import ssh as ssh_module
from aila.platform.services.sandbox.backends import nsjail as nsjail_module
from aila.platform.services.sandbox.backends.firecracker import FirecrackerBackend
from aila.platform.services.sandbox.contracts import SandboxExecutionError, SandboxResult, SandboxSpec
from aila.platform.services.sandbox.service import SandboxConfig, SandboxService
from aila.platform.services.ssh import CommandCancelledError, SSHService

_READ_BOUND_S = 10.0


class _ScriptedChannel:
    """Feeds scripted stdout/stderr chunks; optionally blocks reads until closed."""

    def __init__(
        self,
        *,
        stdout: list[bytes] | None = None,
        stderr: list[bytes] | None = None,
        block_until_closed: bool = False,
        exit_status: int = 0,
    ) -> None:
        self._stdout = list(stdout or [])
        self._stderr = list(stderr or [])
        self._block = block_until_closed
        self._exit_status = exit_status
        self.closed = threading.Event()
        self.close_calls = 0

    def settimeout(self, _seconds: float) -> None:
        return None

    def recv(self, _nbytes: int) -> bytes:
        if self._block:
            self.closed.wait(timeout=_READ_BOUND_S)
            return b""
        return self._stdout.pop(0) if self._stdout else b""

    def recv_stderr(self, _nbytes: int) -> bytes:
        return self._stderr.pop(0) if self._stderr else b""

    def exit_status_ready(self) -> bool:
        # A closed channel never reports an exit status, matching the real transport.
        return not self.closed.is_set()

    def recv_exit_status(self) -> int:
        return self._exit_status

    def close(self) -> None:
        self.close_calls += 1
        self.closed.set()


def _client(*channels: _ScriptedChannel) -> MagicMock:
    """Client whose successive ``exec_command`` calls return ``channels`` in order."""
    client = MagicMock(spec=paramiko.SSHClient)
    transport = MagicMock()
    transport.is_active.return_value = True
    client.get_transport.return_value = transport
    client.exec_command.side_effect = [
        (MagicMock(), SimpleNamespace(channel=channel), MagicMock()) for channel in channels
    ]
    return client


def _service() -> SSHService:
    # The streaming path never reads settings; bypass __init__ so no SecretStore is built.
    service = SSHService.__new__(SSHService)
    service.settings = cast(PlatformSettings, None)
    return service


def _payload() -> SSHIntegrationInput:
    return SSHIntegrationInput(name="fake", host="127.0.0.1", username="user", port=22)


async def _run_streaming(
    *,
    on_stdout=None,
    on_stderr=None,
    cancel_requested=None,
    cancel_command: str | None = None,
) -> tuple[str, str, int]:
    return await _service().run_command_streaming(
        _payload(),
        "echo go",
        timeout_seconds=None,
        on_stdout=on_stdout,
        on_stderr=on_stderr,
        cancel_requested=cancel_requested,
        cancel_command=cancel_command,
        pool=None,
        connect_timeout=15.0,
    )


async def test_callbacks_receive_decoded_text_in_order() -> None:
    # "é" is split across two chunks: decoding must be incremental, not per-chunk.
    channel = _ScriptedChannel(stdout=[b"caf\xc3", b"\xa9\n"])
    seen: list[object] = []

    async def on_stdout(text: str) -> None:
        seen.append(text)

    with patch.object(ssh_module.paramiko, "SSHClient", return_value=_client(channel)):
        stdout, _, exit_code = await _run_streaming(on_stdout=on_stdout)

    assert all(isinstance(item, str) for item in seen)
    assert "".join(cast(list[str], seen)) == "café\n"
    assert stdout == "café\n"
    assert exit_code == 0


async def test_streamed_stderr_matches_redacted_return_value() -> None:
    raw = "first line\nsecond line\n"
    channel = _ScriptedChannel(stderr=[raw.encode()])
    seen: list[str] = []

    async def on_stderr(text: str) -> None:
        seen.append(text)

    with patch.object(ssh_module.paramiko, "SSHClient", return_value=_client(channel)):
        _, stderr, _ = await _run_streaming(on_stderr=on_stderr)

    assert "".join(seen) == stderr == ssh_module.redact_command_line(raw)


async def test_cancel_requested_closes_channel_and_raises() -> None:
    channel = _ScriptedChannel(block_until_closed=True)

    async def cancel_requested() -> bool:
        return True

    with patch.object(ssh_module.paramiko, "SSHClient", return_value=_client(channel)):
        with pytest.raises(CommandCancelledError):
            await _run_streaming(cancel_requested=cancel_requested)

    assert channel.close_calls == 1


async def test_cancel_command_runs_on_fresh_channel_after_cancel() -> None:
    work = _ScriptedChannel(block_until_closed=True)
    cleanup = _ScriptedChannel()
    client = _client(work, cleanup)
    kill = 'kill -KILL -- -"$(cat /run/x/.pgid)" 2>/dev/null; true'

    async def cancel_requested() -> bool:
        return True

    with patch.object(ssh_module.paramiko, "SSHClient", return_value=client):
        with pytest.raises(CommandCancelledError):
            await _run_streaming(cancel_requested=cancel_requested, cancel_command=kill)

    issued = [call.args[0] for call in client.exec_command.call_args_list]
    assert issued == ["echo go", kill]
    assert cleanup.close_calls == 0


async def test_callback_failure_propagates_and_closes_channel() -> None:
    channel = _ScriptedChannel(stdout=[b"payload\n"])

    async def on_stdout(_text: str) -> None:
        raise RuntimeError("sink boom")

    with patch.object(ssh_module.paramiko, "SSHClient", return_value=_client(channel)):
        with pytest.raises(RuntimeError, match="sink boom"):
            await _run_streaming(on_stdout=on_stdout)

    assert channel.close_calls == 1


async def test_firecracker_rejects_live_streaming_before_probing() -> None:
    async def on_stdout(_text: str) -> None:
        return None

    with pytest.raises(SandboxExecutionError, match="does not support live output"):
        await FirecrackerBackend().run(
            cast(Any, None),
            ssh=cast(Any, None),
            host_payload=None,
            cfg=None,
            on_stdout=on_stdout,
        )


def _sandbox_config() -> SandboxConfig:
    return SandboxConfig(
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


class _RecordingBackend:
    name = "stub"

    def __init__(self) -> None:
        self.received_kwargs: dict[str, Any] = {}

    async def run(self, spec: SandboxSpec, *, ssh: Any, host_payload: Any, cfg: Any, **kwargs: Any) -> SandboxResult:
        del spec, ssh, host_payload, cfg
        self.received_kwargs = dict(kwargs)
        return SandboxResult(backend="stub", exit_code=0)


def _sandbox_service(backend: _RecordingBackend) -> Any:
    # Mirrors test_sandbox.py: bypass __init__ and stub config loading.
    service: Any = SandboxService.__new__(SandboxService)
    service._settings = object()
    service._ssh = SimpleNamespace()
    service._registry = None
    service._backends = {backend.name: backend}
    cfg = _sandbox_config()

    async def _load() -> SandboxConfig:
        return cfg

    service._load_config = _load
    return service


async def test_run_streaming_forwards_callbacks_to_backend() -> None:
    backend = _RecordingBackend()

    async def on_stdout(_text: str) -> None:
        return None

    async def on_stderr(_text: str) -> None:
        return None

    async def cancel_requested() -> bool:
        return False

    await _sandbox_service(backend).run_streaming(
        SandboxSpec(argv=["/bin/true"]),
        on_stdout=on_stdout,
        on_stderr=on_stderr,
        cancel_requested=cancel_requested,
    )

    assert backend.received_kwargs == {
        "on_stdout": on_stdout,
        "on_stderr": on_stderr,
        "cancel_requested": cancel_requested,
    }


async def test_run_without_streaming_passes_no_stream_kwargs() -> None:
    backend = _RecordingBackend()

    await _sandbox_service(backend).run(SandboxSpec(argv=["/bin/true"]))

    assert backend.received_kwargs == {}


@asynccontextmanager
async def _fake_workspace(_ssh: Any, _payload: Any):
    yield SimpleNamespace(run_id="run-1", remote_root="/tmp/aila-run-1")


async def test_nsjail_maps_cancelled_stream_to_execution_error() -> None:
    ssh = SimpleNamespace(
        run_command_streaming=AsyncMock(side_effect=CommandCancelledError("closed before exit")),
    )

    async def cancel_requested() -> bool:
        return True

    with (
        patch.object(nsjail_module, "probe_binary", AsyncMock(return_value="/usr/bin/nsjail")),
        patch.object(nsjail_module, "host_workspace", _fake_workspace),
        patch.object(nsjail_module, "stage_inputs", AsyncMock()),
    ):
        with pytest.raises(SandboxExecutionError, match="cancelled"):
            await nsjail_module.NsjailBackend().run(
                SandboxSpec(argv=["/bin/true"]),
                ssh=cast(Any, ssh),
                host_payload=None,
                cfg=_sandbox_config(),
                cancel_requested=cancel_requested,
            )

    kwargs = ssh.run_command_streaming.await_args.kwargs
    assert kwargs["cancel_command"].startswith("kill -KILL")
    assert ".pgid" in kwargs["cancel_command"]
