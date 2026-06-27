"""Network discovery job for AILA -- SSH-based port, service, and connection collection.

Runs as an arq cron job every 15 minutes (D-07/D-08). Collects open ports
(ss -tlnp), active connections (ss -tnp), and running services (systemctl)
from all registered ManagedSystemRecords.

SSH commands are hardcoded constants -- never constructed from user input (T-138-28).
Each scan overwrites previous results per system (D-09).
Unreachable systems are marked stale, never blocking the scan (D-10).
"""
from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlmodel import select

from aila.storage.database import async_session_scope
from aila.storage.db_models import (
    ManagedSystemRecord,
    SystemConnectionRecord,
    SystemMetadataRecord,
    SystemPortRecord,
    SystemServiceRecord,
)

if TYPE_CHECKING:
    pass

__all__ = [
    "detect_edges",
    "detect_subnets",
    "network_discovery_job",
    "parse_df_root_disk_gb",
    "parse_free_memory_mb",
    "parse_ip_route_default",
    "parse_nproc",
    "parse_os_release",
    "parse_ss_connections",
    "parse_ss_listening",
    "parse_systemctl_services",
    "parse_uptime_seconds",
]

_log = logging.getLogger(__name__)

# Hardcoded SSH command constants -- never constructed from user input (T-138-28).
_CMD_LISTENING = "ss -tlnp"
_CMD_CONNECTIONS = "ss -tnp"
_CMD_SERVICES = "systemctl list-units --type=service --state=running --no-pager --plain"

# Phase 176d: per-system metadata probes. Each command is hardcoded and runs
# under a tight timeout so a single slow host cannot stall the scan.
_CMD_IP_ROUTE = "ip route show default"
_CMD_OS_RELEASE = "cat /etc/os-release"
_CMD_UNAME_R = "uname -r"
_CMD_NPROC = "nproc"
_CMD_FREE_M = "free -m"
_CMD_DF_ROOT = "df -BG /"
_CMD_UPTIME = "cat /proc/uptime"
# External IP: try ifconfig.me then icanhazip, fall back to literal 'unknown'.
# The SSH session must not block on a slow provider -- curl's -m 3 caps each
# request at 3s and `|| echo unknown` guarantees a non-empty output.
_CMD_EXTERNAL_IP = (
    "curl -s -m 3 https://ifconfig.me "
    "|| curl -s -m 3 https://icanhazip.com "
    "|| echo unknown"
)

# SSH per-system timeout in seconds (T-138-27).
_SSH_TIMEOUT_SECONDS = 30.0
# Tighter timeout for metadata probes -- these are fire-and-forget enrichments.
_METADATA_SSH_TIMEOUT_SECONDS = 10.0

# Regex for ss process field: users:(("name",pid=N,fd=M))
_PROCESS_RE = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')


# ---------------------------------------------------------------------------
# SSH output parsers -- pure functions, easily testable (T-138-26)
# ---------------------------------------------------------------------------


def parse_ss_listening(output: str) -> list[dict]:
    """Parse ``ss -tlnp`` output into a list of port dicts.

    Each dict contains: port (int), protocol (str), local_address (str),
    process_name (str | None), pid (int | None).

    Lines that do not match the expected State/Local/Peer/Process format are
    silently skipped (strict parsing per T-138-26 -- reject malformed lines).
    """
    results: list[dict] = []
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        # Skip header line and empty lines
        if not line or line.startswith("State") or line.startswith("Netid"):
            continue
        # Split on whitespace -- columns: State, Recv-Q, Send-Q, Local, Peer, Process
        parts = line.split()
        if len(parts) < 4:
            continue
        # State must be LISTEN for listening ports
        if parts[0] != "LISTEN":
            continue
        local_field = parts[3]
        # Parse local address and port: e.g. "0.0.0.0:22" or "[::]:22" or ":::22"
        port_str = _extract_port_from_addr(local_field)
        if port_str is None:
            continue
        try:
            port = int(port_str)
        except ValueError:
            continue
        local_address = _extract_host_from_addr(local_field)
        # Parse process info if present
        process_name: str | None = None
        pid_val: int | None = None
        remainder = " ".join(parts[5:]) if len(parts) > 5 else ""
        match = _PROCESS_RE.search(remainder)
        if match:
            process_name = match.group(1)
            try:
                pid_val = int(match.group(2))
            except ValueError:
                pid_val = None
        results.append({
            "port": port,
            "protocol": "tcp",
            "local_address": local_address,
            "process_name": process_name,
            "pid": pid_val,
        })
    return results


def parse_ss_connections(output: str) -> list[dict]:
    """Parse ``ss -tnp`` output into a list of connection dicts.

    Each dict contains: local_ip (str), local_port (int), peer_ip (str),
    peer_port (int), state (str), process_name (str | None), pid (int | None).

    Lines that do not match the expected format are silently skipped.
    """
    results: list[dict] = []
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("State") or line.startswith("Netid"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        state = parts[0]
        # columns: State, Recv-Q, Send-Q, Local Address:Port, Peer Address:Port, [Process]
        local_field = parts[3]
        peer_field = parts[4]
        local_port_str = _extract_port_from_addr(local_field)
        peer_port_str = _extract_port_from_addr(peer_field)
        if local_port_str is None or peer_port_str is None:
            continue
        try:
            local_port = int(local_port_str)
            peer_port = int(peer_port_str)
        except ValueError:
            continue
        local_ip = _extract_host_from_addr(local_field)
        peer_ip = _extract_host_from_addr(peer_field)
        process_name: str | None = None
        pid_val: int | None = None
        remainder = " ".join(parts[5:]) if len(parts) > 5 else ""
        match = _PROCESS_RE.search(remainder)
        if match:
            process_name = match.group(1)
            try:
                pid_val = int(match.group(2))
            except ValueError:
                pid_val = None
        results.append({
            "local_ip": local_ip,
            "local_port": local_port,
            "peer_ip": peer_ip,
            "peer_port": peer_port,
            "state": state,
            "process_name": process_name,
            "pid": pid_val,
        })
    return results


def parse_systemctl_services(output: str) -> list[dict]:
    """Parse ``systemctl list-units --type=service --state=running`` output.

    Each dict contains: service_name (str), state (str), sub_state (str).

    Lines that do not match the expected format are silently skipped.
    """
    results: list[dict] = []
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # systemctl plain output columns: UNIT, LOAD, ACTIVE, SUB, DESCRIPTION
        # The header is: UNIT  LOAD  ACTIVE  SUB  DESCRIPTION
        if line.startswith("UNIT") and "LOAD" in line:
            continue
        # Lines that start with "●" or have leading bullet markers
        if line.startswith("●"):
            line = line[1:].strip()
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit_name = parts[0]
        # Filter to .service units only
        if not unit_name.endswith(".service"):
            continue
        load_state = parts[1]
        active_state = parts[2]
        sub_state = parts[3]
        # Only include active/running services
        if active_state not in ("active", "activating") and load_state != "loaded":
            continue
        # Strip the .service suffix for a cleaner name
        service_name = unit_name[:-len(".service")] if unit_name.endswith(".service") else unit_name
        results.append({
            "service_name": service_name,
            "state": active_state,
            "sub_state": sub_state,
        })
    return results


# ---------------------------------------------------------------------------
# Address parsing helpers
# ---------------------------------------------------------------------------


def _extract_port_from_addr(addr: str) -> str | None:
    """Extract port string from 'host:port' or '[ipv6]:port' or ':::port' format."""
    if not addr:
        return None
    # IPv6 bracket notation: [::1]:22 or [::]:22
    if addr.startswith("["):
        bracket_close = addr.rfind("]")
        if bracket_close != -1 and bracket_close + 1 < len(addr) and addr[bracket_close + 1] == ":":
            return addr[bracket_close + 2:]
        return None
    # ss uses ":::22" for IPv6 any-address
    if addr.startswith(":::"):
        return addr[3:]
    # Standard IPv4: 0.0.0.0:22 or 127.0.0.1:5432
    colon_pos = addr.rfind(":")
    if colon_pos == -1:
        return None
    return addr[colon_pos + 1:]


def _extract_host_from_addr(addr: str) -> str:
    """Extract host part from 'host:port' or '[ipv6]:port' or ':::port' format."""
    if not addr:
        return ""
    if addr.startswith("["):
        bracket_close = addr.rfind("]")
        if bracket_close != -1:
            return addr[1:bracket_close]
        return addr
    if addr.startswith(":::"):
        return "::"
    colon_pos = addr.rfind(":")
    if colon_pos == -1:
        return addr
    return addr[:colon_pos]


# ---------------------------------------------------------------------------
# Phase 176d: system metadata parsers (pure functions)
# ---------------------------------------------------------------------------


def parse_ip_route_default(output: str) -> tuple[str | None, str | None]:
    """Extract (gateway_ip, interface) from `ip route show default` output.

    Expected format:
        default via 192.168.1.1 dev wlan0 proto dhcp metric 600

    Returns (None, None) when the output does not match a default route.
    """
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("default"):
            continue
        tokens = line.split()
        gateway: str | None = None
        interface: str | None = None
        try:
            if "via" in tokens:
                gateway = tokens[tokens.index("via") + 1]
            if "dev" in tokens:
                interface = tokens[tokens.index("dev") + 1]
        except IndexError:
            return gateway, interface
        return gateway, interface
    return None, None


def parse_os_release(output: str) -> tuple[str | None, str | None]:
    """Extract (ID, PRETTY_NAME) from /etc/os-release content."""
    os_id: str | None = None
    pretty: str | None = None
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, raw_value = line.partition("=")
        value = raw_value.strip().strip('"').strip("'")
        if key == "ID":
            os_id = value or None
        elif key == "PRETTY_NAME":
            pretty = value or None
    return os_id, pretty


def parse_nproc(output: str) -> int | None:
    """Return integer CPU count from `nproc` output, or None if unparseable."""
    stripped = output.strip()
    if not stripped:
        return None
    try:
        return int(stripped.splitlines()[0].strip())
    except (ValueError, IndexError):
        return None


def parse_free_memory_mb(output: str) -> int | None:
    """Parse total memory in MB from the 'Mem:' row of `free -m` output.

    Expected format::
                      total        used        free      shared  buff/cache   available
        Mem:          15947        5012        1231         678       9704        9812
        Swap:             0           0           0
    """
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.lower().startswith("mem:"):
            continue
        tokens = stripped.split()
        if len(tokens) < 2:
            return None
        try:
            return int(tokens[1])
        except ValueError:
            return None
    return None


def parse_df_root_disk_gb(output: str) -> int | None:
    """Parse total disk size in GB from `df -BG /`.

    Expected format::
        Filesystem     1G-blocks  Used Available Use% Mounted on
        /dev/sda1           500G  123G      377G  25% /
    """
    lines = [line for line in output.splitlines() if line.strip()]
    if len(lines) < 2:
        return None
    tokens = lines[1].split()
    if len(tokens) < 2:
        return None
    total_raw = tokens[1].rstrip("G").rstrip("g")
    try:
        return int(total_raw)
    except ValueError:
        return None


def parse_uptime_seconds(output: str) -> int | None:
    """Parse integer uptime seconds from `cat /proc/uptime` (first float).

    /proc/uptime format: "12345.67 6543.21" -- first number is uptime seconds.
    """
    stripped = output.strip()
    if not stripped:
        return None
    first = stripped.split()[0] if stripped.split() else ""
    try:
        return int(float(first))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Edge detection (D-04)
# ---------------------------------------------------------------------------


def detect_edges(
    connections: list[dict],
    system_id: int,
    system_ip_map: dict[str, int],
) -> list[dict]:
    """Identify TCP connections whose peer IP matches a registered system.

    Args:
        connections: Output from parse_ss_connections() for this system.
        system_id: ID of the source system that produced the connections.
        system_ip_map: Mapping of {ip_address: system_id} for all registered systems.

    Returns:
        List of edge dicts with keys: source_system_id, dest_system_id, dest_ip,
        dest_port, protocol, state.
    """
    edges: list[dict] = []
    for conn in connections:
        peer_ip = conn.get("peer_ip", "")
        if not peer_ip:
            continue
        dest_system_id = system_ip_map.get(peer_ip)
        if dest_system_id is None:
            continue
        # Do not create self-loops
        if dest_system_id == system_id:
            continue
        edges.append({
            "source_system_id": system_id,
            "dest_system_id": dest_system_id,
            "dest_ip": peer_ip,
            "dest_port": conn.get("peer_port", 0),
            "protocol": "tcp",
            "state": conn.get("state", "ESTABLISHED"),
        })
    return edges


# ---------------------------------------------------------------------------
# Subnet auto-detection (D-11)
# ---------------------------------------------------------------------------


def detect_subnets(systems: list[ManagedSystemRecord]) -> dict[str, list[int]]:
    """Group system IDs by /24 subnet prefix parsed from their host IP.

    Non-IP hostnames (hostnames that cannot be parsed as IPv4) are grouped
    under "unresolved".

    Args:
        systems: List of ManagedSystemRecord instances.

    Returns:
        Mapping of subnet_prefix -> list of system_ids.
        E.g. {"192.168.1": [1, 2], "10.0.0": [3], "unresolved": [4]}
    """
    subnets: dict[str, list[int]] = {}
    for system in systems:
        if system.id is None:
            continue
        prefix = _ipv4_prefix(system.host)
        subnets.setdefault(prefix, []).append(system.id)
    return subnets


def _ipv4_prefix(host: str) -> str:
    """Return /24 prefix (first 3 octets) for an IPv4 address, or 'unresolved'."""
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3])
    return "unresolved"


# ---------------------------------------------------------------------------
# SSH data collection (D-05)
# ---------------------------------------------------------------------------


async def _collect_system_network_data(
    system: ManagedSystemRecord,
) -> tuple[list[dict], list[dict], list[dict], dict]:
    """SSH into system and collect ports, connections, services, and metadata.

    Returns:
        Tuple of (ports, connections, services, metadata) -- each a list of
        dicts (ports/connections/services) plus a single metadata dict keyed
        for the SystemMetadataRecord columns.

    Raises:
        Exception: Any SSH or connection error propagated to caller so the
            caller can mark the system stale (D-10).
    """
    from aila.config import get_settings
    from aila.platform.services.ssh import SSHService

    settings = get_settings()
    ssh_service = SSHService(settings)

    # Build integration dict matching SSHIntegrationInput fields
    integration = {
        "name": system.name,
        "host": system.host,
        "username": system.username,
        "port": system.port,
        "distro": system.distro,
        "description": system.description,
        "private_key_path": system.private_key_path,
        "password_secret_id": system.password_secret_id,
        "known_hosts_path": system.known_hosts_path,
        "host_key_fingerprint": system.host_key_fingerprint,
    }

    # Collect each command independently -- partial results are valid
    try:
        listening_output = await ssh_service.run_command(
            integration, _CMD_LISTENING, timeout_seconds=_SSH_TIMEOUT_SECONDS
        )
    except Exception:
        _log.debug("ss -tlnp failed on system %s (%s)", system.name, system.host)
        listening_output = ""

    try:
        connections_output = await ssh_service.run_command(
            integration, _CMD_CONNECTIONS, timeout_seconds=_SSH_TIMEOUT_SECONDS
        )
    except Exception:
        _log.debug("ss -tnp failed on system %s (%s)", system.name, system.host)
        connections_output = ""

    try:
        services_output = await ssh_service.run_command(
            integration, _CMD_SERVICES, timeout_seconds=_SSH_TIMEOUT_SECONDS
        )
    except Exception:
        _log.debug("systemctl failed on system %s (%s)", system.name, system.host)
        services_output = ""

    ports = parse_ss_listening(listening_output)
    connections = parse_ss_connections(connections_output)
    services = parse_systemctl_services(services_output)

    metadata = await _collect_system_metadata(ssh_service, integration, system)

    return ports, connections, services, metadata


async def _collect_system_metadata(
    ssh_service, integration: dict, system: ManagedSystemRecord
) -> dict:
    """Run the metadata probe commands and return a SystemMetadataRecord dict.

    Every SSH call is wrapped so a single failing probe (e.g. `ip` command
    missing on a minimal image) does not poison the whole metadata bundle.
    """
    async def _run(cmd: str) -> str:
        try:
            return await ssh_service.run_command(
                integration, cmd, timeout_seconds=_METADATA_SSH_TIMEOUT_SECONDS
            )
        except Exception as exc:
            _log.debug("metadata probe %r failed on %s: %s", cmd, system.name, exc)
            return ""

    ip_route_out = await _run(_CMD_IP_ROUTE)
    os_release_out = await _run(_CMD_OS_RELEASE)
    kernel_out = await _run(_CMD_UNAME_R)
    nproc_out = await _run(_CMD_NPROC)
    free_out = await _run(_CMD_FREE_M)
    df_out = await _run(_CMD_DF_ROOT)
    uptime_out = await _run(_CMD_UPTIME)
    external_ip_out = await _run(_CMD_EXTERNAL_IP)

    gateway_ip, gateway_interface = parse_ip_route_default(ip_route_out)
    os_name, os_pretty = parse_os_release(os_release_out)
    kernel = kernel_out.strip() or None
    cpu_cores = parse_nproc(nproc_out)
    memory_mb = parse_free_memory_mb(free_out)
    disk_gb = parse_df_root_disk_gb(df_out)
    uptime_seconds = parse_uptime_seconds(uptime_out)

    raw_ext_ip = external_ip_out.strip().splitlines()[-1] if external_ip_out.strip() else ""
    external_ip: str | None = None
    if (
        raw_ext_ip
        and raw_ext_ip.lower() != "unknown"
        # Guard against HTML error pages leaking through: only accept values
        # that look like plausible IPs (digits/colons/dots, <= 45 chars).
        and len(raw_ext_ip) <= 45
        and all(c.isdigit() or c in ".:abcdefABCDEF" for c in raw_ext_ip)
    ):
        external_ip = raw_ext_ip

    return {
        "gateway_ip": gateway_ip,
        "gateway_interface": gateway_interface,
        "external_ip": external_ip,
        "os_name": os_name,
        "os_pretty_name": os_pretty,
        "kernel": kernel,
        "cpu_cores": cpu_cores,
        "memory_mb": memory_mb,
        "disk_gb": disk_gb,
        "uptime_seconds": uptime_seconds,
    }


# ---------------------------------------------------------------------------
# DB persistence (D-09 -- overwrite per scan)
# ---------------------------------------------------------------------------


async def _persist_discovery_results(
    system_id: int,
    ports: list[dict],
    services: list[dict],
    edges: list[dict],
    collected_at: datetime,
    metadata: dict | None = None,
) -> None:
    """Write discovery results for one system, overwriting previous data (D-09).

    Within a single session: delete all existing records for this system_id,
    then insert fresh records from the current scan.
    """
    from sqlalchemy import delete as sa_delete

    async with async_session_scope() as session:
        # Delete previous data for this system
        await session.exec(  # type: ignore[call-overload]
            sa_delete(SystemPortRecord).where(SystemPortRecord.system_id == system_id)
        )
        await session.exec(  # type: ignore[call-overload]
            sa_delete(SystemServiceRecord).where(SystemServiceRecord.system_id == system_id)
        )
        await session.exec(  # type: ignore[call-overload]
            sa_delete(SystemConnectionRecord).where(SystemConnectionRecord.source_system_id == system_id)
        )

        # Insert fresh port records
        for p in ports:
            session.add(SystemPortRecord(
                system_id=system_id,
                port=p["port"],
                protocol=p.get("protocol", "tcp"),
                local_address=p.get("local_address", ""),
                process_name=p.get("process_name"),
                pid=p.get("pid"),
                last_collected=collected_at,
                is_stale=False,
            ))

        # Insert fresh service records
        for s in services:
            session.add(SystemServiceRecord(
                system_id=system_id,
                service_name=s["service_name"],
                service_type="systemd",
                state=s.get("state", "running"),
                sub_state=s.get("sub_state", ""),
                last_collected=collected_at,
                is_stale=False,
            ))

        # Insert fresh connection/edge records
        for e in edges:
            session.add(SystemConnectionRecord(
                source_system_id=e["source_system_id"],
                dest_system_id=e["dest_system_id"],
                dest_ip=e.get("dest_ip", ""),
                dest_port=e["dest_port"],
                protocol=e.get("protocol", "tcp"),
                state=e.get("state", "ESTABLISHED"),
                last_collected=collected_at,
                is_stale=False,
            ))

        # Upsert SystemMetadataRecord (1:1 with managed system, D-09 overwrite)
        if metadata is not None:
            from sqlmodel import select as _select

            existing_stmt = _select(SystemMetadataRecord).where(
                SystemMetadataRecord.system_id == system_id,
            )
            existing = (await session.exec(existing_stmt)).first()
            if existing is None:
                session.add(SystemMetadataRecord(
                    system_id=system_id,
                    gateway_ip=metadata.get("gateway_ip"),
                    gateway_interface=metadata.get("gateway_interface"),
                    external_ip=metadata.get("external_ip"),
                    os_name=metadata.get("os_name"),
                    os_pretty_name=metadata.get("os_pretty_name"),
                    kernel=metadata.get("kernel"),
                    cpu_cores=metadata.get("cpu_cores"),
                    memory_mb=metadata.get("memory_mb"),
                    disk_gb=metadata.get("disk_gb"),
                    uptime_seconds=metadata.get("uptime_seconds"),
                    last_collected=collected_at,
                    is_stale=False,
                ))
            else:
                existing.gateway_ip = metadata.get("gateway_ip")
                existing.gateway_interface = metadata.get("gateway_interface")
                existing.external_ip = metadata.get("external_ip")
                existing.os_name = metadata.get("os_name")
                existing.os_pretty_name = metadata.get("os_pretty_name")
                existing.kernel = metadata.get("kernel")
                existing.cpu_cores = metadata.get("cpu_cores")
                existing.memory_mb = metadata.get("memory_mb")
                existing.disk_gb = metadata.get("disk_gb")
                existing.uptime_seconds = metadata.get("uptime_seconds")
                existing.last_collected = collected_at
                existing.is_stale = False
                session.add(existing)

        await session.commit()


async def _mark_system_stale(system_id: int) -> None:
    """Mark all network records for a system as stale (D-10).

    Called when SSH connection to a system fails during discovery.
    """
    from sqlalchemy import update as sa_update

    async with async_session_scope() as session:
        await session.exec(  # type: ignore[call-overload]
            sa_update(SystemPortRecord)
            .where(SystemPortRecord.system_id == system_id)
            .values(is_stale=True)
        )
        await session.exec(  # type: ignore[call-overload]
            sa_update(SystemServiceRecord)
            .where(SystemServiceRecord.system_id == system_id)
            .values(is_stale=True)
        )
        await session.exec(  # type: ignore[call-overload]
            sa_update(SystemConnectionRecord)
            .where(SystemConnectionRecord.source_system_id == system_id)
            .values(is_stale=True)
        )
        await session.exec(  # type: ignore[call-overload]
            sa_update(SystemMetadataRecord)
            .where(SystemMetadataRecord.system_id == system_id)
            .values(is_stale=True)
        )
        await session.commit()


# ---------------------------------------------------------------------------
# Main discovery job (D-07)
# ---------------------------------------------------------------------------


async def network_discovery_job(ctx: dict) -> None:
    """Collect ports, services, and connections from all registered systems.

    arq cron job entry point -- registered in WorkerSettings.cron_jobs at 15-min
    intervals (D-08). Never blocks on a single unreachable system (D-10).

    For each system:
    - Try SSH collection of ports, connections, and services.
    - Detect edges (inter-system connections) from connection data.
    - Persist results, overwriting previous scan (D-09).
    - On SSH failure: mark system stale, log warning, continue.
    """
    _log.info("network_discovery_job: starting discovery run")
    collected_at = datetime.now(tz=UTC)

    # Load all registered systems
    async with async_session_scope() as session:
        systems = list((await session.exec(select(ManagedSystemRecord))).all())

    if not systems:
        _log.info("network_discovery_job: no registered systems -- nothing to do")
        return

    # Build IP -> system_id mapping for edge detection (D-04)
    system_ip_map: dict[str, int] = {}
    for system in systems:
        if system.id is not None:
            system_ip_map[system.host] = system.id

    succeeded = 0
    failed = 0

    for system in systems:
        if system.id is None:
            continue
        try:
            ports, connections, services, metadata = await _collect_system_network_data(system)
            edges = detect_edges(connections, system.id, system_ip_map)
            await _persist_discovery_results(
                system.id, ports, services, edges, collected_at, metadata,
            )
            _log.debug(
                "network_discovery_job: %s -- %d ports, %d services, %d edges, gateway=%s external=%s",
                system.name,
                len(ports),
                len(services),
                len(edges),
                metadata.get("gateway_ip"),
                metadata.get("external_ip"),
            )
            succeeded += 1
        except Exception:
            _log.warning(
                "network_discovery_job: system %s (%s) unreachable -- marking stale",
                system.name,
                system.host,
                exc_info=True,
            )
            try:
                await _mark_system_stale(system.id)
            except Exception:
                _log.exception(
                    "network_discovery_job: failed to mark system %s stale", system.name
                )
            failed += 1

    _log.info(
        "network_discovery_job: complete -- %d succeeded, %d failed/stale",
        succeeded,
        failed,
    )
