"""Long-term memory services -- consolidation of episodic traces (RFC #150).

This package hosts platform-general memory pipelines:

* :mod:`.consolidator` -- the semantic tier. Distills recent
  resolved-investigation ledger traces from the shared investigation
  ledger into de-contextualized factual statements and writes them to
  each module's live-read semantic namespace.
* :mod:`.skills` -- the procedural / skill-library tier. Extracts one
  ``(problem_shape -> approach)`` skill per confirmed-outcome
  investigation and writes it to a team-scoped skill namespace so a
  future investigation with the same problem shape retrieves the
  winning approach at setup time.
"""

from __future__ import annotations

from .consolidator import (
    ConsolidationReport,
    SemanticConsolidationError,
    consolidate_recent_investigations,
    run_semantic_consolidation_sweep,
)
from .skills import (
    SKILL_DEDUP_PREFIX,
    SKILL_GLOBAL_NAMESPACE,
    SKILL_NAMESPACE_KIND,
    SkillLibraryError,
    SkillLibraryReport,
    extract_recent_skills,
    run_skill_library_sweep,
    skill_namespace,
)

__all__ = [
    "ConsolidationReport",
    "SKILL_DEDUP_PREFIX",
    "SKILL_GLOBAL_NAMESPACE",
    "SKILL_NAMESPACE_KIND",
    "SemanticConsolidationError",
    "SkillLibraryError",
    "SkillLibraryReport",
    "consolidate_recent_investigations",
    "extract_recent_skills",
    "run_semantic_consolidation_sweep",
    "run_skill_library_sweep",
    "skill_namespace",
]
