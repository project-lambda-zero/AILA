"""Template pattern-catalog storage binding.

Mirrors :mod:`aila.modules.vr.services.pattern_store`: thin subclass of
:class:`PatternStoreBase` that pair-writes the module pattern row and
its :class:`KnowledgeEntryRecord` mirror. The base owns every method;
the subclass only binds the record model, summary contract, and
KnowledgeEntryRecord namespace prefix.
"""
from __future__ import annotations

from typing import ClassVar

from aila.modules._template.contracts.pattern import TemplatePatternSummary
from aila.modules._template.db_models import TemplatePatternRecord
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
    """Pair-write storage: template_patterns + KnowledgeEntryRecord mirror."""

    _record_model: ClassVar[type] = TemplatePatternRecord
    _summary_cls: ClassVar[type] = TemplatePatternSummary
    _namespace_prefix: ClassVar[str] = "template.pattern"
