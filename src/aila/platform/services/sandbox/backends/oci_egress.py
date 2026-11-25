"""Per-run remote OCI bridge and nftables egress enforcement.

The SSH user provisions a disposable runtime network. A narrowly pre-provisioned
passwordless sudo rule for nft/ip is required; absence of either fails closed.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import shlex
import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import paramiko

from ....exceptions import AILATimeoutError, AuthenticationError, UpstreamError, ValidationError
from ...ssh import CommandCancelledError, SSHService
from ..contracts import SandboxEgressPolicy, SandboxExecutionError

__all__ = ["build_nft_script", "scoped_conntrack_collector", "scoped_oci_egress"]

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


def build_nft_script(
    run_id: str,
    policy: SandboxEgressPolicy,
    bridge: str,
    *,
    conntrack_mark: int | None = None,
) -> str:
    """Build an atomic inet table affecting only this run's bridge.

    When ``conntrack_mark`` is given, every flow entering or leaving the run's
    bridge is tagged with that mark so the flow collector can select this run's
    conntrack entries. Without it the script is unchanged.
    """
    _, expected_bridge, table = _names(run_id)
    if bridge != expected_bridge:
        raise SandboxExecutionError("OCI egress bridge name does not match the run id")
    quoted_bridge = f'"{bridge}"'
    lines = [
        f"add table inet {table}",
        f"add chain inet {table} forward {{ type filter hook forward priority -100; policy accept; }}",
        f"add chain inet {table} input {{ type filter hook input priority -100; policy accept; }}",
    ]
    if conntrack_mark is not None:
        if not 0 < conntrack_mark <= 0xFFFFFFFF:
            raise SandboxExecutionError("OCI egress conntrack mark is out of range")
        lines.extend(
            [
                f"add rule inet {table} forward iifname {quoted_bridge} ct mark set {conntrack_mark}",
                f"add rule inet {table} forward oifname {quoted_bridge} ct mark set {conntrack_mark}",
            ]
        )
    lines.append(f"add rule inet {table} forward oifname {quoted_bridge} ct state established,related accept")
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


_CT_READY_SENTINEL = "AILA_CT_READY"
_CT_READY_TIMEOUT_S = 10.0
_CT_COLLECTOR_MARGIN_S = 30.0


def _collector_marker(run_id: str) -> str:
    return f"aila-ct-{run_id}"


@asynccontextmanager
async def scoped_conntrack_collector(
    ssh: SSHService,
    host_payload: Any,
    *,
    sudo: str,
    conntrack: str,
    ledger: Any,
    run_id: str,
    conntrack_mark: int,
    enforce: bool,
    timeout_seconds: float,
) -> AsyncGenerator[None, None]:
    """Stream this run's conntrack events into ``ledger`` while the body runs.

    The collector carries a per-run marker in its argv so teardown kills exactly
    this run's process. Readiness is a sentinel on stderr, so the body never
    runs before the kernel subscription is live. In ``enforce`` mode a collector
    that is not ready raises before the body. In audit mode the ledger records
    ``collector_unavailable`` and the body runs. The caller owns ``ledger.finish()``.
    """
    pidfile = shlex.quote(f"/tmp/aila-ct-{_collector_marker(run_id)}.pid")
    # The shell records its pid, then execs sudo, so the pid names the sudo
    # process that owns the root-side conntrack child. Teardown signals that pid.
    collector_script = (
        f"echo {_CT_READY_SENTINEL} >&2; echo $$ > {pidfile}; "
        f"exec {sudo} -n {conntrack} -E -o timestamp,extended,id "
        f"-e NEW,UPDATES,DESTROY -m {conntrack_mark}/0xffffffff"
    )
    command = f"sh -c {shlex.quote(collector_script)}"
    kill_script = (
        f'{sudo} -n kill -TERM "$(cat {pidfile} 2>/dev/null)" 2>/dev/null; rm -f {pidfile}; true'
    )
    ready = asyncio.Event()
    stderr_buffer = ""

    async def on_stderr(chunk: str) -> None:
        nonlocal stderr_buffer
        stderr_buffer = (stderr_buffer + chunk)[-256:]
        if _CT_READY_SENTINEL in stderr_buffer:
            ready.set()

    async def on_stdout(chunk: str) -> None:
        ledger.feed_chunk(chunk)

    collector = asyncio.create_task(
        ssh.run_command_streaming(
            host_payload,
            command,
            timeout_seconds=timeout_seconds + _CT_COLLECTOR_MARGIN_S,
            on_stdout=on_stdout,
            on_stderr=on_stderr,
            cancel_command=kill_script,
        )
    )
    ready_wait = asyncio.create_task(ready.wait())
    try:
        await asyncio.wait(
            {collector, ready_wait},
            timeout=_CT_READY_TIMEOUT_S,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if not ready.is_set():
            reason = "collector exited before readiness" if collector.done() else "collector not ready within timeout"
            if enforce:
                raise SandboxExecutionError(f"OCI egress flow telemetry unavailable: {reason}")
            ledger.note_collector_failure("collector_unavailable")
        yield
    finally:
        ready_wait.cancel()
        if not collector.done():
            try:
                await _remote(ssh, host_payload, kill_script, what="conntrack collector stop")
            except SandboxExecutionError:
                ledger.note_collector_failure("collector_stop_failed")
        try:
            await asyncio.wait_for(collector, timeout=_CT_READY_TIMEOUT_S)
        except CommandCancelledError:
            pass
        except TimeoutError:
            collector.cancel()
            ledger.note_collector_failure("collector_stop_timed_out")
        except _TRANSPORT_ERRORS:
            ledger.note_collector_failure("collector_failed")


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


async def _allow_docker_bridge_forward(
    ssh: SSHService,
    host_payload: Any,
    *,
    runtime: str,
    nft: str,
    sudo: str,
    bridge: str,
) -> tuple[int, int] | None:
    """Let Docker forward only traffic already filtered by this run's inet table.

    Docker's inter-bridge isolation runs after the per-run inet base chain and
    otherwise drops approved traffic to targets on another bridge, including
    the established response. The returned handles make the two global-chain
    additions exactly removable. Podman/netavark has no DOCKER-USER chain.
    """
    if runtime.rsplit("/", 1)[-1] != "docker":
        return None
    marker = f"AILA_DOCKER_{bridge}"
    quoted_bridge = shlex.quote(bridge)
    command = (
        f"{shlex.quote(sudo)} -n {shlex.quote(nft)} --echo --handle -f - <<'{marker}'\n"
        f"insert rule ip filter DOCKER-USER iifname {quoted_bridge} accept\n"
        f"insert rule ip filter DOCKER-USER oifname {quoted_bridge} "
        f"ct state established,related accept\n{marker}"
    )
    stdout, stderr, exit_code = await _remote(
        ssh, host_payload, command, what="Docker forward rule install",
    )
    if exit_code != 0:
        raise SandboxExecutionError(
            f"OCI egress Docker forward rule install exited {exit_code}: {stderr.strip()[:300]}"
        )
    handles = re.findall(r"# handle ([0-9]+)", stdout)
    if len(handles) != 2:
        raise SandboxExecutionError("OCI egress Docker forward rule install did not return two rule handles")
    return int(handles[0]), int(handles[1])


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
    conntrack_mark: int | None = None,
) -> AsyncGenerator[str]:
    """Create and tear down one isolated bridge/table; never yield without rules."""
    network, bridge, table = _names(run_id)
    qruntime, qnetwork, qbridge = shlex.quote(runtime), shlex.quote(network), shlex.quote(bridge)
    qsudo, qnft, qip = shlex.quote(sudo), shlex.quote(nft), shlex.quote(ip)
    network_attempted = False
    network_created = False
    docker_forward_handles: tuple[int, int] | None = None
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
        script = build_nft_script(run_id, policy, bridge, conntrack_mark=conntrack_mark)
        marker = f"AILA_NFT_{run_id.replace('-', '')}"
        await _checked(
            ssh,
            host_payload,
            f"{qsudo} -n {qnft} -f - <<'{marker}'\n{script}{marker}",
            what="firewall install",
        )
        docker_forward_handles = await _allow_docker_bridge_forward(
            ssh, host_payload, runtime=runtime, nft=nft, sudo=sudo, bridge=bridge,
        )
        yield network
    finally:
        failed_before_cleanup = sys.exc_info()[0] is not None
        if docker_forward_handles is not None:
            for handle in docker_forward_handles:
                try:
                    _, stderr, exit_code = await _remote(
                        ssh,
                        host_payload,
                        f"{qsudo} -n {qnft} delete rule ip filter DOCKER-USER handle {handle}",
                        what="Docker forward rule cleanup",
                    )
                    if exit_code != 0:
                        cleanup_errors.append(f"Docker forward rule cleanup: {stderr.strip()[:200]}")
                except SandboxExecutionError as exc:
                    cleanup_errors.append(str(exc))
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
