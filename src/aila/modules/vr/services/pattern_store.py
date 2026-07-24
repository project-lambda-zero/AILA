"""VR binding of the platform pattern-catalog storage service."""
from __future__ import annotations

from typing import ClassVar

from aila.modules.vr.contracts.pattern import VRPatternSummary
from aila.modules.vr.db_models import VRPatternRecord
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
    """Pair-write storage: vr_patterns + KnowledgeEntryRecord mirror."""

    _record_model: ClassVar[type] = VRPatternRecord
    _summary_cls: ClassVar[type] = VRPatternSummary
    _namespace_prefix: ClassVar[str] = "vr.pattern"
