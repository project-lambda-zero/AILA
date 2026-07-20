"""Tests for SCALE-02: SSH command timeout via channel.settimeout (Phase 21 Plan 01).

Contract update
---------------
``SSHService.run_command`` is now ``async``: it awaits credential resolution and
dispatches the blocking paramiko work through ``asyncio.to_thread``. Callers
that used to invoke it synchronously must ``await`` it. The channel-timeout
plumbing tested below (``channel.settimeout``, re-raise of ``builtins.TimeoutError``
as ``aila.platform.exceptions.TimeoutError``) is unchanged in shape, but the
platform re-raise message was rewritten to "... idle >{timeout}s with no output ..."
instead of the old "timed out" wording.
"""
from __future__ import annotations

import inspect
from unittest.mock import MagicMock, patch

import pytest

from aila.platform.services.ssh import SSHService

_INTEGRATION = {
    "id": 1,
    "name": "test-host",
    "host": "192.168.1.1",
    "username": "user",
    "port": 22,
    "distro": "ubuntu",
    "description": "",
    "private_key_path": None,
    "password_secret_id": None,
    "known_hosts_path": None,
    "host_key_fingerprint": None,
}


def test_run_command_accepts_timeout_seconds_parameter():
    """SSHService.run_command must have a timeout_seconds parameter."""
    sig = inspect.signature(SSHService.run_command)
    assert "timeout_seconds" in sig.parameters


def test_timeout_seconds_defaults_to_none():
    """timeout_seconds must default to None (backward-compat -- existing callers unchanged)."""
    sig = inspect.signature(SSHService.run_command)
    param = sig.parameters["timeout_seconds"]
    assert param.default is None


def test_run_command_is_async():
    """Contract change: SSHService.run_command is a coroutine function."""
    assert inspect.iscoroutinefunction(SSHService.run_command)


async def test_settimeout_called_when_timeout_provided():
    """channel.settimeout() is called with the supplied value when timeout_seconds is not None."""
    mock_settings = MagicMock()
    mock_secret_store = MagicMock()
    mock_secret_store.get_secret_by_id.return_value = None

    service = SSHService(mock_settings, secret_store=mock_secret_store)

    mock_channel = MagicMock()
    mock_stdout = MagicMock()
    mock_stdout.channel = mock_channel
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stdout.read.return_value = b"output"

    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""

    mock_client = MagicMock()
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    with patch("paramiko.SSHClient", return_value=mock_client):
        result = await service.run_command(_INTEGRATION, "dpkg-query -l", timeout_seconds=30.0)

    mock_channel.settimeout.assert_called_once_with(30.0)
    assert result == "output"


async def test_settimeout_not_called_when_timeout_is_none():
    """channel.settimeout() must NOT be called when timeout_seconds is None."""
    mock_settings = MagicMock()
    mock_secret_store = MagicMock()
    mock_secret_store.get_secret_by_id.return_value = None

    service = SSHService(mock_settings, secret_store=mock_secret_store)

    mock_channel = MagicMock()
    mock_stdout = MagicMock()
    mock_stdout.channel = mock_channel
    mock_stdout.channel.recv_exit_status.return_value = 0
    mock_stdout.read.return_value = b"output"

    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""

    mock_client = MagicMock()
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    with patch("paramiko.SSHClient", return_value=mock_client):
        await service.run_command(_INTEGRATION, "dpkg-query -l", timeout_seconds=None)

    mock_channel.settimeout.assert_not_called()


async def test_socket_timeout_reraises_as_platform_timeout_error():
    """A builtins.TimeoutError raised during exec is reraised as the platform
    ``TimeoutError``. The current wording is 'idle >{timeout}s with no output',
    not the old 'timed out' wording -- the match asserts the current message.
    """
    mock_settings = MagicMock()
    mock_secret_store = MagicMock()
    mock_secret_store.get_secret_by_id.return_value = None

    service = SSHService(mock_settings, secret_store=mock_secret_store)

    mock_channel = MagicMock()
    mock_channel.recv_exit_status.side_effect = TimeoutError("timed out")
    mock_stdout = MagicMock()
    mock_stdout.channel = mock_channel
    mock_stdout.read.return_value = b""

    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""

    mock_client = MagicMock()
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    from aila.platform.exceptions import TimeoutError as PlatformTimeoutError

    with patch("paramiko.SSHClient", return_value=mock_client):
        with pytest.raises(PlatformTimeoutError, match=r"idle >5\.0s"):
            await service.run_command(_INTEGRATION, "dpkg-query -l", timeout_seconds=5.0)
