"""Topology schemas for the AILA REST API -- network discovery aggregation.

Used by GET /topology and GET /topology/subnets (RADAR-05 / D-12).

TopologyNode represents a registered system with its collected network state.
TopologyEdge represents an active connection between two registered systems.
SubnetGroup represents a set of systems sharing a /24 prefix (D-11).
TopologyResponse is the full aggregated network graph.

Severity overlay (D-02): SeverityCounts is populated from the vulnerability
module's LatestFindingRecord when vulnerability data exists. When no scan has
run, severity_counts is None -- the endpoint still returns the network graph.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

__all__ = [
    "PortInfo",
    "ServiceInfo",
    "SeverityCounts",
    "SubnetGroup",
    "SystemMetadata",
    "TopologyEdge",
    "TopologyNode",
    "TopologyResponse",
]


class SystemMetadata(BaseModel):
    """Gateway + external IP + neofetch-like system info (Phase 176d).

    Populated by the network discovery job. Every field is nullable so that
    a host missing one probe (e.g. no `ip` command) still surfaces whatever
    data was collected.
    """

    gateway_ip: str | None = None
    gateway_interface: str | None = None
    external_ip: str | None = None
    os_name: str | None = None
    os_pretty_name: str | None = None
    kernel: str | None = None
    cpu_cores: int | None = None
    memory_mb: int | None = None
    disk_gb: int | None = None
    uptime_seconds: int | None = None
    last_collected: datetime | None = None
    is_stale: bool = False


class PortInfo(BaseModel):
    """Open listening port on a registered system."""

    port: int
    protocol: str
    local_address: str
    process_name: str | None = None


class ServiceInfo(BaseModel):
    """Running systemd service on a registered system."""

    service_name: str
    state: str
    sub_state: str


class SeverityCounts(BaseModel):
    """Vulnerability severity distribution for one system (D-02 overlay).

    Populated from LatestFindingRecord when vulnerability scans exist.
    None at the node level means no vulnerability data is available yet.
    """

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class TopologyNode(BaseModel):
    """A registered system node in the network topology graph.

    Aggregates network state (ports, services) with an optional vulnerability
    severity overlay. is_stale=True means the system was unreachable during
    the last discovery scan (D-10).
    """

    id: int
    name: str
    host: str
    distro: str
    subnet: str | None = None
    group_tags: list[str] = []
    ports: list[PortInfo] = []
    services: list[ServiceInfo] = []
    severity_counts: SeverityCounts | None = None
    last_collected: datetime | None = None
    is_stale: bool = False
    # Phase 176d: gateway, external IP, neofetch-like fields. None when the
    # discovery job has not yet probed this host.
    metadata: SystemMetadata | None = None


class TopologyEdge(BaseModel):
    """An active TCP connection between two registered systems (topology edge).

    source_system_id -> dest_system_id represents the direction of the
    connection observed on the source system via ss -tnp.
    """

    source_system_id: int
    dest_system_id: int
    dest_port: int
    protocol: str
    state: str
    is_stale: bool = False


class SubnetGroup(BaseModel):
    """A set of registered systems sharing a /24 subnet prefix (D-11)."""

    subnet_prefix: str
    system_ids: list[int]


class TopologyResponse(BaseModel):
    """Complete network topology graph aggregated from platform discovery data.

    nodes: all registered systems with network state and optional vuln overlay.
    edges: active connections between registered systems (D-04).
    subnets: systems grouped by /24 prefix (D-11).

    Per D-12: the response is valid even when no vulnerability data exists.
    severity_counts on each node will be None in that case.
    """

    nodes: list[TopologyNode]
    edges: list[TopologyEdge]
    subnets: list[SubnetGroup]
