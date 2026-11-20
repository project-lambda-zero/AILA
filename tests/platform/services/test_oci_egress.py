from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from aila.platform.services.sandbox.backends.oci_egress import build_nft_script, scoped_oci_egress
from aila.platform.services.sandbox.contracts import (
    SandboxEgressDestination,
    SandboxEgressPolicy,
    SandboxExecutionError,
    SandboxSpec,
)

_RUN = "abcdef1234567890"
_IMAGE = "aila/probe@sha256:" + "ab" * 32


def _policy() -> SandboxEgressPolicy:
    return SandboxEgressPolicy(
        destinations=[
            SandboxEgressDestination(address="192.0.2.10", port=443, protocol="tcp"),
            SandboxEgressDestination(address="2001:db8::/32", port=53, protocol="udp"),
        ]
    )


class _SSH:
    def __init__(self, *, fail: str | None = None, transport_fail: str | None = None) -> None:
        self.fail = fail
        self.transport_fail = transport_fail
        self.commands: list[str] = []

    async def run_command_full(
        self, integration: Any, command: str, timeout_seconds: float | None = None
    ) -> tuple[str, str, int]:
        del integration, timeout_seconds
        self.commands.append(command)
        for needle in (self.fail, self.transport_fail):
            if needle and needle in command:
                if needle == self.transport_fail:
                    raise OSError("ssh transport lost")
                return "", f"forced {needle}", 1
        if "--echo --handle -f -" in command and "insert rule ip filter DOCKER-USER" in command:
            return (
                "insert rule ip filter DOCKER-USER accept # handle 77\n"
                "insert rule ip filter DOCKER-USER accept # handle 78\n"
            ), "", 0
        return "", "", 0


async def _run_context(ssh: _SSH, body: Any = None) -> None:
    async with scoped_oci_egress(
        ssh,  # type: ignore[arg-type]
        object(),
        runtime="/usr/bin/docker",
        nft="/usr/sbin/nft",
        sudo="/usr/bin/sudo",
        ip="/usr/sbin/ip",
        run_id=_RUN,
        policy=_policy(),
    ) as network:
        assert network == f"aila-egress-{_RUN}"
        if body is not None:
            body()


def test_policy_rejects_hostnames_duplicates_unspecified_and_disconnected_use() -> None:
    with pytest.raises(ValidationError):
        SandboxEgressDestination(address="example.com", port=443, protocol="tcp")
    with pytest.raises(ValidationError):
        SandboxEgressDestination(address="0.0.0.0", port=443, protocol="tcp")
    destination = SandboxEgressDestination(address="192.0.2.1", port=443, protocol="tcp")
    with pytest.raises(ValidationError, match="unique"):
        SandboxEgressPolicy(destinations=[destination, destination])
    with pytest.raises(ValidationError, match="requires network=True"):
        SandboxSpec(argv=["true"], image=_IMAGE, egress=SandboxEgressPolicy(destinations=[destination]))


def test_nft_script_is_bridge_scoped_default_deny_and_exact() -> None:
    script = build_nft_script(_RUN, _policy(), "ailaabcdef12345")
    assert "policy drop" not in script
    assert 'iifname "ailaabcdef12345" ip daddr 192.0.2.10 tcp dport 443 accept' in script
    assert 'iifname "ailaabcdef12345" ip6 daddr 2001:db8::/32 udp dport 53 accept' in script
    assert 'forward iifname "ailaabcdef12345" drop' in script
    assert 'forward oifname "ailaabcdef12345" drop' in script
    assert 'input iifname "ailaabcdef12345" drop' in script
    assert "ct state established,related accept" in script
    assert "192.0.2.11" not in script


@pytest.mark.asyncio
async def test_success_installs_before_body_and_cleans_in_reverse_order() -> None:
    ssh = _SSH()
    await _run_context(ssh)
    assert "network create" in ssh.commands[0]
    assert "ip link show" in ssh.commands[1]
    assert "nft -f -" in ssh.commands[2]
    assert "--echo --handle -f -" in ssh.commands[3]
    assert "insert rule ip filter DOCKER-USER" in ssh.commands[3]
    assert "oifname" in ssh.commands[3] and "established,related" in ssh.commands[3]
    assert "delete rule ip filter DOCKER-USER handle 77" in ssh.commands[4]
    assert "delete rule ip filter DOCKER-USER handle 78" in ssh.commands[5]
    assert "delete table inet" in ssh.commands[6]
    assert "network rm" in ssh.commands[7]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["ip link show", "nft -f -", "insert rule ip filter DOCKER-USER"])
async def test_setup_failure_never_enters_body_and_removes_network(failure: str) -> None:
    ssh = _SSH(fail=failure)
    entered = False

    def body() -> None:
        nonlocal entered
        entered = True

    with pytest.raises(SandboxExecutionError):
        await _run_context(ssh, body)
    assert entered is False
    assert any("network rm" in command for command in ssh.commands)
    if failure == "ip link show":
        assert not any("nft -f -" in command for command in ssh.commands)


@pytest.mark.asyncio
async def test_action_failure_still_cleans_and_preserves_original_error() -> None:
    ssh = _SSH()

    def body() -> None:
        raise LookupError("action failed")

    with pytest.raises(LookupError, match="action failed"):
        await _run_context(ssh, body)
    assert any("delete table inet" in command for command in ssh.commands)
    assert any("network rm" in command for command in ssh.commands)


@pytest.mark.asyncio
async def test_firewall_cleanup_transport_failure_does_not_skip_network_cleanup_or_mask_action() -> None:
    ssh = _SSH(transport_fail="delete table inet")

    def body() -> None:
        raise LookupError("action failed")

    with pytest.raises(LookupError, match="action failed"):
        await _run_context(ssh, body)
    assert any("network rm" in command for command in ssh.commands)


@pytest.mark.asyncio
async def test_cleanup_failure_after_success_is_actionable() -> None:
    ssh = _SSH(fail="delete table inet")
    with pytest.raises(SandboxExecutionError, match="firewall cleanup"):
        await _run_context(ssh)


@pytest.mark.asyncio
async def test_cancellation_cleans_resources() -> None:
    ssh = _SSH()

    def body() -> None:
        raise TimeoutError("cancelled action path")

    with pytest.raises(TimeoutError, match="cancelled action path"):
        await _run_context(ssh, body)
    assert any("delete table inet" in command for command in ssh.commands)
    assert any("network rm" in command for command in ssh.commands)
