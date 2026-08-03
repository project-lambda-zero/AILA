"""Forensics binding of the platform pattern-catalog storage service."""
from __future__ import annotations

from typing import ClassVar

from aila.modules.forensics.contracts.pattern import ForensicsPatternSummary
from aila.modules.forensics.db_models.pattern import ForensicsPatternRecord
from aila.platform.services.pattern_store import (
    PatternRetrievalResult,
    PatternStoreBase,
    PatternStoreError,
)

__all__ = [
    "PatternRetrievalResult",
    "PatternStore",
    "PatternStoreError",
]


class PatternStore(PatternStoreBase):
    """Pair-write storage: forensics_patterns + KnowledgeEntryRecord mirror."""

    _record_model: ClassVar[type] = ForensicsPatternRecord
    _summary_cls: ClassVar[type] = ForensicsPatternSummary
    _namespace_prefix: ClassVar[str] = "forensics.pattern"
