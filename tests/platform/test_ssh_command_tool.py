"""#42 SSH command-tool audit + redaction.

The dispatch log passes the command through the C6 redaction boundary so an
inline credential never lands verbatim in the structured log, and
forward_trusted (platform-constructed commands) still emits that audit log
instead of running silently.
"""
from __future__ import annotations

import logging

from aila.platform.tools.ssh import SSHCommandTool, _validate_ssh_command


class _FakeSSH:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def run_command(
        self, integration: dict, command: str, timeout_seconds: float | None = None
    ) -> str:
        self.calls.append(command)
        return "ok"


def test_validate_ssh_command_redacts_secret(caplog) -> None:
    with caplog.at_level(logging.INFO):
        _validate_ssh_command("mysql -p hunter2 -e 'show databases'")
    dispatch = [r for r in caplog.records if r.msg == "ssh.command_dispatch"]
    assert dispatch, "no dispatch log emitted"
    logged = getattr(dispatch[0], "command", "")
    assert "[REDACTED]" in logged
    assert "hunter2" not in logged


async def test_forward_trusted_emits_redacted_dispatch_log(caplog) -> None:
    fake = _FakeSSH()
    tool = SSHCommandTool(settings=object(), ssh_service=fake)
    raw = "curl -H 'authorization: bearer sk-live-secret' https://1.1.1.1/"
    with caplog.at_level(logging.INFO):
        result = await tool.forward_trusted({}, raw)
    assert result == "ok"
    # The real command still runs verbatim -- only the log is redacted.
    assert fake.calls == [raw]
    dispatch = [r for r in caplog.records if r.msg == "ssh.command_dispatch"]
    assert dispatch, "forward_trusted must still emit the dispatch audit log"
    logged = getattr(dispatch[0], "command", "")
    assert "[REDACTED]" in logged
    assert "sk-live-secret" not in logged
