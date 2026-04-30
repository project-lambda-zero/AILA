"""Systems API response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from .common import APIModel, PaginatedResponse

__all__ = [
    "ConnectivityStatusResponse",
    "ScanHistoryResponse",
    "SystemCreateRequest",
    "SystemCSVImportRequest",
    "SystemCSVImportResponse",
    "SystemDetailResponse",
    "SystemEnrichedResponse",
    "SystemListResponse",
    "SystemResponse",
    "SystemUpdateRequest",
]


class SystemResponse(APIModel):
    """A registered managed system (SSH target).

    Mirrors the ManagedSystemRecord shape. Returned in list and detail views.
    """

    id: int = Field(description="Database primary key")
    name: str = Field(description="Unique system name")
    host: str = Field(description="SSH hostname or IP address")
    username: str = Field(description="SSH login username")
    port: int = Field(default=22, description="SSH port")
    distro: str = Field(default="unknown", description="Linux distribution identifier")
    description: str = Field(default="", description="Human-readable system description")
    created_at: datetime | None = Field(default=None, description="When this system was registered")
    updated_at: datetime | None = Field(default=None, description="When this system was last updated")


class SystemEnrichedResponse(SystemResponse):
    """System response extended with fleet-level enrichment fields.

    Used in the list endpoint (GET /systems) to provide connectivity status,
    tag assignments, last scan timestamp, and top severity per system without
    requiring N+1 per-system requests from the client.

    Fields are nullable: absent data (e.g. no scan history, no port records)
    returns None rather than fabricating a value.
    """

    connectivity_status: str | None = Field(
        default=None,
        description="SSH reachability from last network discovery: reachable|unreachable|unknown",
    )
    tags: list[dict[str, str]] = Field(
        default_factory=list,
        description="Tags assigned to this system (each: {tag_key, tag_value})",
    )
    last_scan_at: datetime | None = Field(
        default=None,
        description="Completed_at timestamp of the most recent workflow run for this system",
    )
    last_scan_status: str | None = Field(
        default=None,
        description="Status of the most recent workflow run: completed|failed|running",
    )
    top_severity: str | None = Field(
        default=None,
        description="Highest active finding severity for this system: critical|high|medium|low",
    )


SystemListResponse = PaginatedResponse[SystemEnrichedResponse]
SystemListResponse.__doc__ = "Paginated list of registered systems with enrichment data."


class SystemDetailResponse(SystemResponse):
    """Detailed view of a single system including module-contributed dashboard data.

    Extends SystemResponse with module summaries (vulnerability counts,
    compliance status, etc.) and scan history count.
    """

    module_summaries: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Per-module dashboard data keyed by module_id",
    )
    scan_count: int = Field(default=0, description="Total number of scans run against this system")


class SystemCreateRequest(APIModel):
    """Request body for POST /systems (D-06, D-08, API-06)."""

    name: str = Field(..., min_length=1, max_length=128, description="Unique system name")
    host: str = Field(..., min_length=1, description="SSH hostname or IP address")
    username: str = Field(default="root", description="SSH username")
    port: int = Field(default=22, ge=1, le=65535, description="SSH port")
    distro: str = Field(default="unknown", description="Linux distribution")
    description: str = Field(default="", description="Optional free-text description")
    private_key: str | None = Field(
        default=None,
        description="SSH private key content (PEM format, will be encrypted and stored via SecretRecord)",
    )
    password: str | None = Field(
        default=None,
        description="SSH password (will be encrypted and stored via SecretRecord)",
    )
    private_key_passphrase: str | None = Field(
        default=None,
        description="Passphrase for the SSH private key (will be encrypted)",
    )


class SystemUpdateRequest(APIModel):
    """Request body for PUT /systems/{id} (D-06, API-06). All fields optional."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    host: str | None = Field(default=None, min_length=1)
    username: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    distro: str | None = None
    description: str | None = None
    private_key: str | None = Field(
        default=None,
        description="New SSH private key content (PEM format; will be encrypted; send null to clear)",
    )
    password: str | None = Field(
        default=None,
        description="New SSH password (will be encrypted; send null to clear)",
    )
    private_key_passphrase: str | None = Field(
        default=None,
        description="New passphrase for the SSH private key (will be encrypted; send null to clear)",
    )


class SystemCSVImportRequest(APIModel):
    """Request body for POST /systems/import-csv (D-09, T-142-01, T-142-02).

    Accepts up to 500 system definitions in a single request. Each item is
    validated against SystemCreateRequest (Pydantic enforces field constraints
    before any DB writes). Partial success: valid rows are created, invalid
    rows are reported in the errors array. Rate limited at 60/minute.
    """

    systems: list[SystemCreateRequest] = Field(
        ...,
        max_length=500,
        description="Array of system definitions to import (max 500 per request)",
    )


class SystemCSVImportResponse(APIModel):
    """Response for POST /systems/import-csv (D-09).

    Partial success semantics: some rows may succeed while others fail.
    Always returns HTTP 200 (partial success is valid for batch operations).
    """

    created: list[SystemResponse] = Field(
        default_factory=list,
        description="Successfully created system records",
    )
    errors: list[dict[str, object]] = Field(
        default_factory=list,
        description="Rows that failed ({row_index: int, name: str, reason: str})",
    )


class ConnectivityStatusResponse(APIModel):
    """SSH connectivity status for a system (D-03).

    Derived from the most recent network discovery port probe records.
    """

    status: str = Field(description="Connectivity state: reachable|unreachable|unknown")
    last_checked: datetime | None = Field(
        default=None,
        description="MAX(last_collected) across all port records for this system",
    )


class ScanHistoryResponse(APIModel):
    """Paginated scan history for a system.

    Contains workflow run summaries linked to the system.
    """

    total: int = Field(ge=0, description="Total number of matching scans")
    page: int = Field(ge=1, description="Current page number")
    page_size: int = Field(ge=1, le=250, description="Items per page")
    pages: int = Field(ge=0, description="Total number of pages")
    items: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Scan run summaries for the current page",
    )
