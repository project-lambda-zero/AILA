"""Topology router for AILA REST API -- platform-owned network graph endpoint.

Provides:
- GET /topology      -- full network graph: nodes (systems + ports + services +
                       severity overlay) and edges (active inter-system connections)
- GET /topology/subnets -- subnet groupings for quick filtering

Per RADAR-05 / D-12: platform builds the graph from network discovery data;
vulnerability module decorates nodes with severity counts when data exists.
Topology works without vulnerability data (severity_counts=None on each node).

Per T-138-25: requires operator+ role; rate limited to prevent scraping.
Per D-01: topology is platform-owned, not vulnerability-module-specific.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_OPERATOR
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.api.schemas.topology import (
    PortInfo,
    ServiceInfo,
    SeverityCounts,
    SubnetGroup,
    SystemMetadata,
    TopologyEdge,
    TopologyNode,
    TopologyResponse,
)
from aila.platform.tasks.discovery import detect_subnets
from aila.storage.database import async_session_scope
from aila.storage.db_models import (
    ManagedSystemRecord,
    SystemConnectionRecord,
    SystemMetadataRecord,
    SystemPortRecord,
    SystemServiceRecord,
)

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/topology", tags=["topology"], dependencies=[Depends(require_user_or_api_key)])

_ROLE_LEVELS: dict[str, int] = {"reader": 0, "operator": 1, "admin": 2}


def _require_operator(auth: AuthContext = Depends(require_user_or_api_key)) -> AuthContext:
    """Enforce operator+ role (T-138-25: topology reveals internal network structure)."""
    if _ROLE_LEVELS.get(auth.role, -1) < _ROLE_LEVELS[ROLE_OPERATOR]:
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Topology requires '{ROLE_OPERATOR}' role or higher; current role: '{auth.role}'",
        )
    return auth


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


# ---------------------------------------------------------------------------
# Vulnerability severity overlay (D-02)
# ---------------------------------------------------------------------------


async def _load_severity_counts(system_ids: list[int], platform: object) -> dict[int, SeverityCounts]:
    """Load vulnerability severity counts per system through the module boundary."""
    if platform is None or not system_ids:
        return {}
    try:
        module = platform.runtime.module_registry.require("vulnerability")  # type: ignore[attr-defined]
        labels = await module.fleet_severity_summary(system_ids, None)
    except Exception:
        _log.debug("severity overlay unavailable", exc_info=True)
        return {}
    counts: dict[int, SeverityCounts] = {}
    for sid, severity in labels.items():
        counts.setdefault(sid, SeverityCounts())
        if severity == "critical":
            counts[sid].critical += 1
        elif severity == "high":
            counts[sid].high += 1
        elif severity == "medium":
            counts[sid].medium += 1
        elif severity == "low":
            counts[sid].low += 1
    return counts


# ---------------------------------------------------------------------------
# Topology endpoint (RADAR-05 / D-12 / T-138-25)
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=DataEnvelope[TopologyResponse],
    summary="Network topology graph with severity overlay",
)
@limiter.limit("30/minute")
async def get_topology(
    request: Request,
    auth: AuthContext = Depends(_require_operator),
) -> DataEnvelope[TopologyResponse]:
    """Return the complete network topology graph.

    Aggregates:
    1. All registered ManagedSystemRecords as nodes.
    2. SystemPortRecord and SystemServiceRecord per system.
    3. SystemConnectionRecord as edges (active inter-system connections).
    4. Subnet groupings via detect_subnets() (D-11).
    5. Group tags from AssetTagRecord (key="group") per system.
    6. Vulnerability severity counts from LatestFindingRecord as overlay (D-02).

    Per D-12: topology is valid even when no vulnerability scans have run.
    severity_counts will be None on nodes with no vulnerability data.

    Per T-138-25: operator+ role enforced; 30/minute rate limit.
    Per T-138-31: response limited to registered systems only (bounded set).

    Team-scoped (#36): a team-scoped caller sees only its team's systems and
    the ports, services, edges, and subnet groupings derived from them. The
    child records (SystemPortRecord, SystemServiceRecord, SystemConnectionRecord,
    SystemMetadataRecord) are not team-scoped themselves; filtering at the
    ManagedSystemRecord parent is sufficient because each child is only
    reachable through the already-filtered system_ids set. A god-tier admin
    (team_id=None, TEAM-06) sees all teams' systems.
    """
    async with async_session_scope() as session:
        stmt = select(ManagedSystemRecord)
        if auth.team_id is not None:
            stmt = stmt.where(ManagedSystemRecord.team_id == auth.team_id)
        systems = list((await session.exec(stmt)).all())

    if not systems:
        return DataEnvelope(
            data=TopologyResponse(nodes=[], edges=[], subnets=[]),
            meta={"system_count": 0},
        )

    system_ids = [s.id for s in systems if s.id is not None]

    # Load all network data in parallel-ish queries (sequential but efficient)
    async with async_session_scope() as session:
        port_rows = list((await session.exec(
            select(SystemPortRecord).where(SystemPortRecord.system_id.in_(system_ids))  # type: ignore[attr-defined]
        )).all())

        service_rows = list((await session.exec(
            select(SystemServiceRecord).where(SystemServiceRecord.system_id.in_(system_ids))  # type: ignore[attr-defined]
        )).all())

        edge_rows = list((await session.exec(
            select(SystemConnectionRecord).where(
                SystemConnectionRecord.source_system_id.in_(system_ids)  # type: ignore[attr-defined]
            )
        )).all())

        metadata_rows = list((await session.exec(
            select(SystemMetadataRecord).where(
                SystemMetadataRecord.system_id.in_(system_ids)  # type: ignore[attr-defined]
            )
        )).all())

    # Phase 176d: build system_id -> SystemMetadata lookup
    metadata_by_system: dict[int, SystemMetadata] = {}
    for row in metadata_rows:
        metadata_by_system[row.system_id] = SystemMetadata(
            gateway_ip=row.gateway_ip,
            gateway_interface=row.gateway_interface,
            external_ip=row.external_ip,
            os_name=row.os_name,
            os_pretty_name=row.os_pretty_name,
            kernel=row.kernel,
            cpu_cores=row.cpu_cores,
            memory_mb=row.memory_mb,
            disk_gb=row.disk_gb,
            uptime_seconds=row.uptime_seconds,
            last_collected=row.last_collected,
            is_stale=row.is_stale,
        )

    system_group_tags: dict[int, list[str]] = defaultdict(list)
    platform = getattr(request.app.state, "platform", None)
    if platform is not None:
        try:
            module = platform.runtime.module_registry.require("vulnerability")
            tag_map = await module.system_tags_map(system_ids, None)
            for sid, tags in tag_map.items():
                for tag in tags:
                    if tag.get("tag_key") == "group":
                        system_group_tags[sid].append(str(tag.get("tag_value") or ""))
        except Exception:
            _log.debug("group tags unavailable", exc_info=True)

    severity_map = await _load_severity_counts(system_ids, platform)

    # Group ports and services by system_id for O(1) lookup
    ports_by_system: dict[int, list[SystemPortRecord]] = defaultdict(list)
    for row in port_rows:
        ports_by_system[row.system_id].append(row)

    services_by_system: dict[int, list[SystemServiceRecord]] = defaultdict(list)
    for row in service_rows:
        services_by_system[row.system_id].append(row)

    # Auto-detect subnets (D-11)
    subnet_map = detect_subnets(systems)

    # Build system_id -> subnet_prefix lookup for node decoration
    system_subnet: dict[int, str] = {}
    for prefix, sids in subnet_map.items():
        for sid in sids:
            system_subnet[sid] = prefix

    # Build topology nodes
    nodes: list[TopologyNode] = []
    for system in systems:
        if system.id is None:
            continue
        sid = system.id

        # Determine last_collected and is_stale from port records
        port_records = ports_by_system[sid]
        service_records = services_by_system[sid]
        last_collected: datetime | None = None
        is_stale = False
        if port_records:
            last_collected = port_records[0].last_collected
            is_stale = any(r.is_stale for r in port_records)
        elif service_records:
            last_collected = service_records[0].last_collected
            is_stale = any(r.is_stale for r in service_records)

        ports = [
            PortInfo(
                port=r.port,
                protocol=r.protocol,
                local_address=r.local_address,
                process_name=r.process_name,
            )
            for r in port_records
        ]

        services = [
            ServiceInfo(
                service_name=r.service_name,
                state=r.state,
                sub_state=r.sub_state,
            )
            for r in service_records
        ]

        nodes.append(TopologyNode(
            id=sid,
            name=system.name,
            host=system.host,
            distro=system.distro,
            subnet=system_subnet.get(sid),
            group_tags=system_group_tags.get(sid, []),
            ports=ports,
            services=services,
            severity_counts=severity_map.get(sid),
            last_collected=last_collected,
            is_stale=is_stale,
            metadata=metadata_by_system.get(sid),
        ))

    # Build topology edges
    edges: list[TopologyEdge] = [
        TopologyEdge(
            source_system_id=row.source_system_id,
            dest_system_id=row.dest_system_id,
            dest_port=row.dest_port,
            protocol=row.protocol,
            state=row.state,
            is_stale=row.is_stale,
        )
        for row in edge_rows
    ]

    # Build subnet groups
    subnets: list[SubnetGroup] = [
        SubnetGroup(subnet_prefix=prefix, system_ids=sids)
        for prefix, sids in sorted(subnet_map.items())
    ]

    return DataEnvelope(
        data=TopologyResponse(nodes=nodes, edges=edges, subnets=subnets),
        meta={
            "system_count": len(nodes),
            "edge_count": len(edges),
            "subnet_count": len(subnets),
        },
    )


@router.get(
    "/subnets",
    response_model=DataEnvelope[list[SubnetGroup]],
    summary="Network subnet groupings",
)
@limiter.limit("60/minute")
async def get_topology_subnets(
    request: Request,
    auth: AuthContext = Depends(_require_operator),
) -> DataEnvelope[list[SubnetGroup]]:
    """Return subnet groupings of registered systems by /24 prefix (D-11).

    Lightweight alternative to GET /topology for subnet-based filtering.
    Per T-138-25: operator+ role required.

    Team-scoped (#36): a team-scoped caller sees only its team's systems in
    the subnet groupings; a god-tier admin (team_id=None, TEAM-06) sees all.
    """
    async with async_session_scope() as session:
        stmt = select(ManagedSystemRecord)
        if auth.team_id is not None:
            stmt = stmt.where(ManagedSystemRecord.team_id == auth.team_id)
        systems = list((await session.exec(stmt)).all())

    subnet_map = detect_subnets(systems)
    subnets = [
        SubnetGroup(subnet_prefix=prefix, system_ids=sids)
        for prefix, sids in sorted(subnet_map.items())
    ]

    return DataEnvelope(
        data=subnets,
        meta={"subnet_count": len(subnets)},
    )
