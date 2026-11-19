"""Per-run remote OCI bridge and nftables egress enforcement.

The SSH user provisions a disposable runtime network. A narrowly pre-provisioned
passwordless sudo rule for nft/ip is required; absence of either fails closed.
"""
from __future__ import annotations

import ipaddress
import re
import shlex
import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import paramiko

from ....exceptions import AILATimeoutError, AuthenticationError, UpstreamError, ValidationError
from ...ssh import SSHService
from ..contracts import SandboxEgressPolicy, SandboxExecutionError

__all__ = ["build_nft_script", "scoped_oci_egress"]

_RUN_ID = re.compile(r"[a-z0-9]{8,64}")
_TRANSPORT_ERRORS = (
    paramiko.SSHException,
    AuthenticationError,
    UpstreamError,
    AILATimeoutError,
    ValidationError,
    OSError,
    TimeoutError,
)


def _names(run_id: str) -> tuple[str, str, str]:
    normalized = run_id.replace("-", "").lower()
    if _RUN_ID.fullmatch(normalized) is None:
        raise SandboxExecutionError("OCI egress run id must be 8-64 lowercase hexadecimal/alphanumeric characters")
    return f"aila-egress-{normalized}", f"aila{normalized[:11]}", f"aila_egress_{normalized}"


def build_nft_script(run_id: str, policy: SandboxEgressPolicy, bridge: str) -> str:
    """Build an atomic inet table affecting only this run's bridge."""
    _, expected_bridge, table = _names(run_id)
    if bridge != expected_bridge:
        raise SandboxExecutionError("OCI egress bridge name does not match the run id")
    quoted_bridge = f'"{bridge}"'
    lines = [
        f"add table inet {table}",
        f"add chain inet {table} forward {{ type filter hook forward priority -100; policy accept; }}",
        f"add chain inet {table} input {{ type filter hook input priority -100; policy accept; }}",
        f"add rule inet {table} forward oifname {quoted_bridge} ct state established,related accept",
    ]
    for destination in policy.destinations:
        parsed = ipaddress.ip_network(destination.address, strict=False)
        family = "ip6" if parsed.version == 6 else "ip"
        lines.append(
            f"add rule inet {table} forward iifname {quoted_bridge} "
            f"{family} daddr {destination.address} {destination.protocol} dport {destination.port} accept"
        )
    lines.extend(
        [
            f"add rule inet {table} forward iifname {quoted_bridge} drop",
            f"add rule inet {table} forward oifname {quoted_bridge} drop",
            f"add rule inet {table} input iifname {quoted_bridge} drop",
        ]
    )
    return "\n".join(lines) + "\n"


async def _remote(
    ssh: SSHService,
    host_payload: Any,
    command: str,
    *,
    what: str,
) -> tuple[str, str, int]:
    try:
        return await ssh.run_command_full(host_payload, command, timeout_seconds=30.0)
    except _TRANSPORT_ERRORS as exc:
        raise SandboxExecutionError(f"OCI egress {what} failed: {exc}") from exc


async def _checked(
    ssh: SSHService,
    host_payload: Any,
    command: str,
    *,
    what: str,
) -> None:
    _, stderr, exit_code = await _remote(ssh, host_payload, command, what=what)
    if exit_code != 0:
        raise SandboxExecutionError(f"OCI egress {what} exited {exit_code}: {stderr.strip()[:300]}")


@asynccontextmanager
async def scoped_oci_egress(
    ssh: SSHService,
    host_payload: Any,
    *,
    runtime: str,
    nft: str,
    sudo: str,
    ip: str,
    run_id: str,
    policy: SandboxEgressPolicy,
) -> AsyncGenerator[str]:
    """Create and tear down one isolated bridge/table; never yield without rules."""
    network, bridge, table = _names(run_id)
    qruntime, qnetwork, qbridge = shlex.quote(runtime), shlex.quote(network), shlex.quote(bridge)
    qsudo, qnft, qip = shlex.quote(sudo), shlex.quote(nft), shlex.quote(ip)
    network_attempted = False
    network_created = False
    cleanup_errors: list[str] = []
    try:
        network_attempted = True
        await _checked(
            ssh,
            host_payload,
            f"{qruntime} network create --driver bridge "
            f"--opt com.docker.network.bridge.name={qbridge} {qnetwork}",
            what="network create",
        )
        network_created = True
        # Runtimes that ignore the bridge option must not run the container.
        await _checked(ssh, host_payload, f"{qip} link show dev {qbridge} >/dev/null", what="bridge verification")
        script = build_nft_script(run_id, policy, bridge)
        marker = f"AILA_NFT_{run_id.replace('-', '')}"
        await _checked(
            ssh,
            host_payload,
            f"{qsudo} -n {qnft} -f - <<'{marker}'\n{script}{marker}",
            what="firewall install",
        )
        yield network
    finally:
        failed_before_cleanup = sys.exc_info()[0] is not None
        if network_created:
            try:
                _, stderr, exit_code = await _remote(
                    ssh,
                    host_payload,
                    f"{qsudo} -n {qnft} delete table inet {table}",
                    what="firewall cleanup",
                )
                if exit_code != 0:
                    cleanup_errors.append(f"firewall cleanup: {stderr.strip()[:200]}")
            except SandboxExecutionError as exc:
                cleanup_errors.append(str(exc))
        if network_attempted:
            try:
                _, stderr, exit_code = await _remote(
                    ssh, host_payload, f"{qruntime} network rm {qnetwork}", what="network cleanup"
                )
                if exit_code != 0:
                    cleanup_errors.append(f"network cleanup: {stderr.strip()[:200]}")
            except SandboxExecutionError as exc:
                cleanup_errors.append(str(exc))
        if cleanup_errors and not failed_before_cleanup:
            raise SandboxExecutionError("; ".join(cleanup_errors))
