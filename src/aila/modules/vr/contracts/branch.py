"""Investigation branch contracts (M3.R-1).

Branches let one investigation explore multiple hypothesis lines in
parallel (D-41). Each branch runs its own HonestVulnResearcher instance
with isolated state. Branches can fork, merge, promote, or abandon
(D-41 operations).

Personas (D-39 — halvar/maddie/yuki/renzo/noor/wei) are voice modifiers
applied at branch level: each persona-voiced branch uses a different
prompt prefix when calling the LLM.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

__all__ = [
    "BranchOperation",
    "BranchStatus",
    "PersonaVoice",
    "VRBranchSummary",
]


class BranchStatus(StrEnum):
    """Lifecycle states for one branch within an investigation."""

    ACTIVE = "active"
    PAUSED = "paused"
    MERGED = "merged"
    PROMOTED = "promoted"
    ABANDONED = "abandoned"


class PersonaVoice(StrEnum):
    """Per-D-39 persona voice modifiers. Each is a prompt-prefix.

    Voices are not separate agents — they're stylistic prompt prefixes
    that bias the reasoning toward a particular kind of skepticism /
    aggression / pattern-matching. The same model produces all of them.
    """

    HALVAR = "halvar"
    MADDIE = "maddie"
    YUKI = "yuki"
    RENZO = "renzo"
    NOOR = "noor"
    WEI = "wei"


class BranchOperation(StrEnum):
    """Branch lifecycle operations (D-41).

    Recorded on every transition for audit trail. Triggered by engine
    (when confidence + evidence justify) OR operator (manual override
    via API). The branch_manager service (M3.R-5) emits an
    AgentStepRecord for each operation.
    """

    FORK = "fork"
    MERGE = "merge"
    PROMOTE = "promote"
    ABANDON = "abandon"
    PAUSE = "pause"
    RESUME = "resume"


class VRBranchSummary(BaseModel):
    """Read-only projection of one branch within an investigation."""

    model_config = ConfigDict(extra="forbid")

    id: str
    investigation_id: str
    parent_branch_id: str | None = None
    status: BranchStatus
    persona_voice: PersonaVoice | None = None
    fork_reason: str = ""
    fork_at_turn: int | None = None
    turn_count: int = 0
    branch_cost_usd: float = 0.0
    closed_reason: str = ""
    merged_into_branch_id: str | None = None
    promoted: bool = False
    closed_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
