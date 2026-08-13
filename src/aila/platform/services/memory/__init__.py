"""Long-term memory services -- consolidation of episodic traces (RFC #150).

This package hosts platform-general memory pipelines. Today it owns the
semantic-tier consolidator (:mod:`.consolidator`), which distills recent
resolved-investigation traces from the shared investigation ledger into
de-contextualized factual statements and writes them to the existing
pgvector knowledge store under each module's live-read semantic namespace.
"""

from __future__ import annotations

from .consolidator import (
    ConsolidationReport,
    SemanticConsolidationError,
    consolidate_recent_investigations,
    run_semantic_consolidation_sweep,
)

__all__ = [
    "ConsolidationReport",
    "SemanticConsolidationError",
    "consolidate_recent_investigations",
    "run_semantic_consolidation_sweep",
]
