"""#42 SSH surface rejects unknown host keys by default.

Every SSH code path -- pool + direct connect + upload + download,
and the full-triple variant -- must install ``paramiko.RejectPolicy``
even when no ``known_hosts_path`` is configured. The prior fallback
was ``AutoAddPolicy``, which silently trusted a server's first-seen
key and opened a first-connect MITM window on freshly registered
hosts. Reject-by-default closes that window; hosts an operator has
previously accepted into ``~/.ssh/known_hosts`` (or into an operator
supplied ``known_hosts_path``) still connect because both files are
loaded before the policy fires.

Every blocking path is a sync helper on ``SSHService`` (or on
``SSHConnectionPool``) that constructs a ``paramiko.SSHClient()``
inline; patching ``paramiko.SSHClient`` at import time on the
service module lets us record which policy each site installs
without opening a real socket.
"""
from __future__ import annotations

import inspect
from unittest.mock import MagicMock, patch

import paramiko

from aila.platform.contracts.platform import SSHIntegrationInput
from aila.platform.services import ssh as ssh_module
from aila.platform.services.ssh import (
    SSHConnectionPool,
    SSHService,
    _apply_host_key_policy,
)


def _payload(known_hosts_path: str | None = None) -> SSHIntegrationInput:
    return SSHIntegrationInput(
        name="fake",
        host="127.0.0.1",
        username="user",
        port=22,
        known_hosts_path=known_hosts_path,
    )


# ---------------------------------------------------------------------------
# Direct helper: the reject-by-default policy is centralized so a future
# surface added by a fresh caller inherits the same rule.
# ---------------------------------------------------------------------------


def test_apply_host_key_policy_installs_reject_without_known_hosts() -> None:
    client = paramiko.SSHClient()
    _apply_host_key_policy(client, _payload(known_hosts_path=None))
    assert isinstance(client._policy, paramiko.RejectPolicy)


def test_apply_host_key_policy_installs_reject_with_known_hosts() -> None:
    # An operator-declared trust file is layered on top; the policy for
    # what to do about a MISSING key stays reject-by-default.
    client = paramiko.SSHClient()
    _apply_host_key_policy(client, _payload(known_hosts_path="/tmp/kh"))
    assert isinstance(client._policy, paramiko.RejectPolicy)


def test_apply_host_key_policy_never_uses_autoadd() -> None:
    client = paramiko.SSHClient()
    _apply_host_key_policy(client, _payload())
    assert not isinstance(client._policy, paramiko.AutoAddPolicy)


# ---------------------------------------------------------------------------
# Surface tests: patch paramiko.SSHClient at the ssh module import site so
# every construction inside a blocking helper returns a MagicMock. We record
# the policy each site installs; every one must be RejectPolicy.
# ---------------------------------------------------------------------------


def _fake_client() -> MagicMock:
    client = MagicMock(spec=paramiko.SSHClient)
    # ``connect`` is a no-op; ``get_transport`` returns a live-looking mock so
    # any keepalive setter call doesn't blow up.
    transport = MagicMock()
    transport.is_active.return_value = True
    client.get_transport.return_value = transport
    # SFTP path -- the upload/download helpers open one and set a channel
    # timeout; those are structural calls, not policy calls.
    sftp = MagicMock()
    sftp.get_channel.return_value = MagicMock()
    client.open_sftp.return_value = sftp
    return client


def _run_command_blocking_records_reject() -> paramiko.MissingHostKeyPolicy:
    service = SSHService.__new__(SSHService)
    service.settings = None
    fake = _fake_client()
    with patch.object(ssh_module.paramiko, "SSHClient", return_value=fake):
        with patch.object(
            ssh_module.SSHService, "_exec_command", return_value="ok"
        ):
            service._run_command_blocking(
                _payload(), "echo hi", None, None, {"hostname": "127.0.0.1"}
            )
    # ``set_missing_host_key_policy`` is called exactly once per surface via
    # ``_apply_host_key_policy``; grab the argument it was called with.
    fake.set_missing_host_key_policy.assert_called_once()
    (policy,), _kw = fake.set_missing_host_key_policy.call_args
    return policy


def test_run_command_blocking_installs_reject_policy() -> None:
    policy = _run_command_blocking_records_reject()
    assert isinstance(policy, paramiko.RejectPolicy)


def test_run_command_full_blocking_installs_reject_policy() -> None:
    service = SSHService.__new__(SSHService)
    service.settings = None
    fake = _fake_client()
    with patch.object(ssh_module.paramiko, "SSHClient", return_value=fake):
        with patch.object(
            ssh_module.SSHService, "_exec_command_full", return_value=("ok", "", 0)
        ):
            service._run_command_full_blocking(
                _payload(), "echo hi", None, None, {"hostname": "127.0.0.1"}
            )
    fake.set_missing_host_key_policy.assert_called_once()
    (policy,), _kw = fake.set_missing_host_key_policy.call_args
    assert isinstance(policy, paramiko.RejectPolicy)


def test_upload_file_blocking_installs_reject_policy(tmp_path) -> None:
    service = SSHService.__new__(SSHService)
    service.settings = None
    fake = _fake_client()
    src = tmp_path / "src.bin"
    src.write_bytes(b"payload")
    with patch.object(ssh_module.paramiko, "SSHClient", return_value=fake):
        service._upload_file_blocking(
            _payload(), str(src), "/tmp/out.bin", None, {"hostname": "127.0.0.1"}
        )
    fake.set_missing_host_key_policy.assert_called_once()
    (policy,), _kw = fake.set_missing_host_key_policy.call_args
    assert isinstance(policy, paramiko.RejectPolicy)


def test_download_file_blocking_installs_reject_policy() -> None:
    service = SSHService.__new__(SSHService)
    service.settings = None
    fake = _fake_client()
    with patch.object(ssh_module.paramiko, "SSHClient", return_value=fake):
        service._download_file_blocking(
            _payload(),
            "/var/log/audit.log",
            "/tmp/out.bin",
            None,
            {"hostname": "127.0.0.1"},
        )
    fake.set_missing_host_key_policy.assert_called_once()
    (policy,), _kw = fake.set_missing_host_key_policy.call_args
    assert isinstance(policy, paramiko.RejectPolicy)


def test_connection_pool_installs_reject_policy() -> None:
    pool = SSHConnectionPool()
    fake = _fake_client()
    with patch.object(ssh_module.paramiko, "SSHClient", return_value=fake):
        pool.get_or_connect(_payload(), {"hostname": "127.0.0.1"})
    fake.set_missing_host_key_policy.assert_called_once()
    (policy,), _kw = fake.set_missing_host_key_policy.call_args
    assert isinstance(policy, paramiko.RejectPolicy)


# ---------------------------------------------------------------------------
# Regression: AutoAddPolicy must not surface anywhere in the SSH service
# module (comments are prose, not runtime references). If any live callable
# is reintroduced, this catches it.
# ---------------------------------------------------------------------------


def test_no_autoadd_policy_reachable_from_ssh_service() -> None:
    source = inspect.getsource(ssh_module)
    # Every remaining textual mention lives inside a docstring/comment
    # -- there is no live constructor call. Confirm no bare
    # ``AutoAddPolicy(`` invocation reaches the runtime.
    assert "paramiko.AutoAddPolicy(" not in source
