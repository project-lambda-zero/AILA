"""Platform-owned audit constants shared by API routers and modules."""
from __future__ import annotations

__all__ = ["AUDIT_STAGE_SCAN", "AUDIT_STATUS_COMPLETED"]

AUDIT_STAGE_SCAN: str = "scan"
AUDIT_STATUS_COMPLETED: str = "completed"
