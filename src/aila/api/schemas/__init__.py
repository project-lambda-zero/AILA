"""API-level Pydantic response/request models for AILA.

These models form the public API contract -- they deliberately do NOT
re-export internal platform contracts. Changing internal types does not
break the API schema (per RESEARCH anti-pattern 3: do not expose
PlatformResponse directly).
"""
from __future__ import annotations

from . import audit, config, findings, reports, systems, tools
from .audit import AuditEventResponse, AuditListResponse
from .common import APIModel, PaginatedResponse
from .config import ConfigEntryResponse, ConfigListResponse, ConfigUpdateRequest
from .errors import ErrorResponse
from .findings import FacetsResponse, FindingResponse, FindingsListResponse
from .reports import ReportCountResponse, ReportSummaryResponse
from .systems import SystemDetailResponse, SystemListResponse, SystemResponse
from .tools import ToolDetailResponse, ToolInvokeRequest, ToolInvokeResponse, ToolSummaryResponse

__all__: list[str] = [
    # submodules (for `from aila.api.schemas import findings` pattern)
    "audit",
    "config",
    "findings",
    "reports",
    "systems",
    "tools",
    # common
    "APIModel",
    "PaginatedResponse",
    # errors
    "ErrorResponse",
    # findings
    "FacetsResponse",
    "FindingResponse",
    "FindingsListResponse",
    # reports
    "ReportCountResponse",
    "ReportSummaryResponse",
    # systems
    "SystemDetailResponse",
    "SystemListResponse",
    "SystemResponse",
    # audit
    "AuditEventResponse",
    "AuditListResponse",
    # config
    "ConfigEntryResponse",
    "ConfigListResponse",
    "ConfigUpdateRequest",
    # tools
    "ToolDetailResponse",
    "ToolInvokeRequest",
    "ToolInvokeResponse",
    "ToolSummaryResponse",
]
