"""Status enums for forensics domain records.

Replaces the scatter of magic strings (`"pending"`, `"running"`, `"failed"`, ...)
across intake / freeflow / investigator / api_router with typed values so a
typo is a compile-time failure, not a silent runtime bug.

StrEnum inheritance means existing DB rows with legacy string values continue
to compare equal (`ProjectStatus.READY == "ready"`), so this is a drop-in
replacement with no schema migration.
"""
from __future__ import annotations

from enum import StrEnum

__all__ = ["ProjectStatus", "InvestigationStatus"]


class ProjectStatus(StrEnum):
    """Lifecycle of a ForensicsProjectRecord."""

    CREATED = "created"
    READY = "ready"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class InvestigationStatus(StrEnum):
    """Lifecycle of an InvestigationRunRecord."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    EXHAUSTED = "exhausted"
    FAILED = "failed"
    CANCELLED = "cancelled"
