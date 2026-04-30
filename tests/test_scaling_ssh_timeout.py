"""Tests for SCALE-02: SSH command timeout via channel.settimeout (Phase 21 Plan 01)."""
from __future__ import annotations

import inspect
import socket
from unittest.mock import MagicMock, patch

import pytest

from aila.platform.services.ssh import SSHService


def test_run_command_accepts_timeout_seconds_parameter():
    """SSHService.run_command must have a timeout_seconds parameter."""
    sig = inspect.signature(SSHService.run_command)
    assert "timeout_seconds" in sig.parameters


def test_timeout_seconds_defaults_to_none():
    """timeout_seconds must default to None (backward-compat — existing callers unchanged)."""
    sig = inspect.signature(SSHService.run_command)
    param = sig.parameters["timeout_seconds"]
    assert param.default is None


def test_settimeout_called_when_timeout_provided():
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

    integration = {
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

    with patch("paramiko.SSHClient", return_value=mock_client):
        result = service.run_command(integration, "dpkg-query -l", timeout_seconds=30.0)

    mock_channel.settimeout.assert_called_once_with(30.0)
    assert result == "output"


def test_settimeout_not_called_when_timeout_is_none():
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

    integration = {
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

    with patch("paramiko.SSHClient", return_value=mock_client):
        service.run_command(integration, "dpkg-query -l", timeout_seconds=None)

    mock_channel.settimeout.assert_not_called()


def test_socket_timeout_reraises_as_timeout_error():
    """socket.timeout raised during read must be reraised as platform TimeoutError containing 'timed out'."""
    mock_settings = MagicMock()
    mock_secret_store = MagicMock()
    mock_secret_store.get_secret_by_id.return_value = None

    service = SSHService(mock_settings, secret_store=mock_secret_store)

    mock_channel = MagicMock()
    mock_channel.recv_exit_status.side_effect = socket.timeout("timed out")
    mock_stdout = MagicMock()
    mock_stdout.channel = mock_channel

    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""

    mock_client = MagicMock()
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    integration = {
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

    from aila.platform.exceptions import TimeoutError as PlatformTimeoutError

    with patch("paramiko.SSHClient", return_value=mock_client):
        with pytest.raises(PlatformTimeoutError, match="timed out"):
            service.run_command(integration, "dpkg-query -l", timeout_seconds=5.0)
