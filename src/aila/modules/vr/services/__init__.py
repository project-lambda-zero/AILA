"""VR module domain services.

Barrel re-export. Service implementations live in submodules and are
constructed via the workflow services factory (or the API router's
local construction sites) per the platform DI rules.
"""
from __future__ import annotations

from aila.modules.vr.services.pattern_store import (
    PatternRetrievalResult,
    PatternStore,
    PatternStoreError,
)
from aila.modules.vr.services.target_ingestion import TargetIngestionService

__all__ = [
    "PatternRetrievalResult",
    "PatternStore",
    "PatternStoreError",
    "TargetIngestionService",
]
