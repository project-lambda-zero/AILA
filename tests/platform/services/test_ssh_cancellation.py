"""Cancelling the awaiting task of an SSH command closes its exec channel.

The command runs in a worker thread (``asyncio.to_thread``). Cancelling the
awaiting coroutine cannot interrupt that thread, so the service closes the
channel instead: a blocked remote read then returns and the thread unwinds.

The fake channel never reaches the network. Its stdout read blocks until the
channel is closed, which models a remote command that is still running. Every
blocking wait is bounded so a regression fails the test instead of hanging it.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import paramiko
import pytest

from aila.platform.contracts.platform import SSHIntegrationInput
from aila.platform.services import ssh as ssh_module
from aila.platform.services.ssh import SSHService, _ChannelCloser

_READ_BOUND_S = 10.0


class _FakeChannel:
    """Minimal stand-in for ``paramiko.Channel`` covering the calls under test."""

    def __init__(
        self,
        *,
        block_until_closed: bool = False,
        exit_status: int = 0,
        close_error: Exception | None = None,
        stdout_data: bytes = b"",
    ) -> None:
        self._block = block_until_closed
        self._exit_status = exit_status
        self._close_error = close_error
        self._pending_stdout = stdout_data
        self.closed = threading.Event()
        self.close_calls = 0
        self.read_returned = threading.Event()
        self.read_released_by_close: bool | None = None
        self.polls_after_close = 0
        self.polled_after_close = threading.Event()

    def settimeout(self, timeout: float | None) -> None:
        return None

    def exit_status_ready(self) -> bool:
        if self.closed.is_set():
            self.polls_after_close += 1
            self.polled_after_close.set()
        return not self._block

    def recv_exit_status(self) -> int:
        return self._exit_status

    def recv(self, nbytes: int) -> bytes:
        if self._block:
            released = self.closed.wait(timeout=_READ_BOUND_S)
            self.read_released_by_close = released
            self.read_returned.set()
            return b""
        data, self._pending_stdout = self._pending_stdout, b""
        return data

    def recv_stderr(self, nbytes: int) -> bytes:
        return b""

    def close(self) -> None:
        self.close_calls += 1
        self.closed.set()
        if self._close_error is not None:
            raise self._close_error


def _drain_until_eof(channel: _FakeChannel) -> bytes:
    """Mirror ``paramiko.ChannelFile.read()``: pull from the channel until EOF."""
    chunks: list[bytes] = []
    while chunk := channel.recv(4096):
        chunks.append(chunk)
    return b"".join(chunks)


def _fake_client(channel: _FakeChannel) -> MagicMock:
    client = MagicMock(spec=paramiko.SSHClient)
    transport = MagicMock()
    transport.is_active.return_value = True
    client.get_transport.return_value = transport
    stdout = SimpleNamespace(channel=channel, read=lambda: _drain_until_eof(channel))
    stderr = SimpleNamespace(read=lambda: b"")
    client.exec_command.return_value = (MagicMock(), stdout, stderr)
    return client


def _service() -> SSHService:
    service = SSHService.__new__(SSHService)
    service.settings = None
    return service


def _payload() -> SSHIntegrationInput:
    return SSHIntegrationInput(name="fake", host="127.0.0.1", username="user", port=22)


@pytest.mark.parametrize("method", ["run_command", "run_command_full"])
async def test_cancelled_command_closes_channel_and_worker_unwinds(method: str) -> None:
    channel = _FakeChannel(block_until_closed=True)
    with patch.object(ssh_module.paramiko, "SSHClient", return_value=_fake_client(channel)):
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(getattr(_service(), method)(_payload(), "sleep 1000"), timeout=0.2)
        # The blocked remote read returned because the channel was closed, not
        # because the wait bound expired.
        assert await asyncio.to_thread(channel.read_returned.wait, _READ_BOUND_S)
        assert channel.read_released_by_close is True
        assert channel.close_calls == 1
        # The worker then reaches the exit-status wait exactly once and exits
        # on that poll instead of spinning through the 30s grace period.
        assert await asyncio.to_thread(channel.polled_after_close.wait, _READ_BOUND_S)
        assert channel.polls_after_close == 1


async def test_cancel_surfaces_timeout_even_when_channel_close_fails() -> None:
    channel = _FakeChannel(block_until_closed=True, close_error=OSError("transport gone"))
    with patch.object(ssh_module.paramiko, "SSHClient", return_value=_fake_client(channel)):
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(_service().run_command(_payload(), "sleep 1000"), timeout=0.2)
        assert await asyncio.to_thread(channel.read_returned.wait, _READ_BOUND_S)
    assert channel.close_calls == 1


async def test_completed_command_returns_output_without_closing_channel() -> None:
    channel = _FakeChannel(exit_status=0, stdout_data=b"hello\n")
    with patch.object(ssh_module.paramiko, "SSHClient", return_value=_fake_client(channel)):
        output = await _service().run_command(_payload(), "echo hello")
    full_channel = _FakeChannel(exit_status=0, stdout_data=b"hello\n")
    with patch.object(ssh_module.paramiko, "SSHClient", return_value=_fake_client(full_channel)):
        full = await _service().run_command_full(_payload(), "echo hello")
    assert output == "hello\n"
    assert full == ("hello\n", "", 0)
    assert channel.close_calls == 0
    assert full_channel.close_calls == 0


def test_close_requested_before_register_closes_channel_on_register() -> None:
    closer = _ChannelCloser()
    channel = _FakeChannel()
    closer.close()
    closer.register(channel)
    assert channel.close_calls == 1


def test_close_after_register_closes_registered_channel() -> None:
    closer = _ChannelCloser()
    channel = _FakeChannel()
    closer.register(channel)
    closer.close()
    assert channel.close_calls == 1


def test_register_without_close_leaves_channel_open() -> None:
    closer = _ChannelCloser()
    channel = _FakeChannel()
    closer.register(channel)
    assert channel.close_calls == 0
    assert closer.closed is False
