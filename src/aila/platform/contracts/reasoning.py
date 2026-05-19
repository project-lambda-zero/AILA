from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

__all__ = [
    "ReasoningAction",
    "ReasoningCaseState",
    "ReasoningConfidence",
    "ReasoningContract",
    "ReasoningDomainProfile",
    "ReasoningEvidenceGraph",
    "ReasoningGraphDiff",
    "ReasoningGraphEdge",
    "ReasoningGraphEdgeKind",
    "ReasoningGraphNode",
    "ReasoningGraphNodeKind",
    "ReasoningOperatorSteering",
    "ReasoningPromptContext",
    "ReasoningStrategyFamily",
    "ReasoningTurnDecision",
    "EvidenceProvenance",
    "Hypothesis",
    "RejectedHypothesis",
]

ReasoningAction = Literal["script_execute", "tool_run", "reasoning", "submit"]
ReasoningConfidence = Literal["exact", "strong", "medium", "caveated", "unknown"]
ReasoningStrategyFamily = Literal[
    "filesystem_triage",
    "persistence_hunt",
    "memory_forensics",
    "network_forensics",
    "malware_static",
    "vulnerability_research",
    "web_pentest",
    "mobile_reverse",
    "generic",
]
ReasoningGraphNodeKind = Literal[
    "contract",
    "hypothesis",
    "rejected_hypothesis",
    "observable",
    "evidence",
    "answer",
]
ReasoningGraphEdgeKind = Literal[
    "depends_on",
    "supports",
    "refutes",
    "corroborates",
    "answered_by",
]


class ReasoningContract(BaseModel):
    """Answer contract derived by the engine for the active question."""

    answer_type: str = ""
    answer_format: str = ""
    evidence_domain: str = ""
    depends_on: list[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    """One live explanatory hypothesis the engine is evaluating."""

    id: str
    claim: str
    why_plausible: str = ""
    kill_criterion: str = ""


class RejectedHypothesis(BaseModel):
    """One disproved or discarded hypothesis with rationale."""

    id: str
    claim: str
    reason: str = ""


class EvidenceProvenance(BaseModel):
    """Primary and supporting evidence attached to an answer candidate."""

    primary_artifact: str = ""
    corroboration: list[str] = Field(default_factory=list)
    rejected_alternatives: list[str] = Field(default_factory=list)

class ReasoningGraphNode(BaseModel):
    """One node in the engine's evidence graph snapshot."""

    id: str
    kind: ReasoningGraphNodeKind
    label: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class ReasoningGraphEdge(BaseModel):
    """One edge in the engine's evidence graph snapshot."""

    source: str
    target: str
    kind: ReasoningGraphEdgeKind
    attributes: dict[str, Any] = Field(default_factory=dict)


class ReasoningEvidenceGraph(BaseModel):
    """Graph snapshot of the current reasoning state and evidence relations."""

    nodes: list[ReasoningGraphNode] = Field(default_factory=list)
    edges: list[ReasoningGraphEdge] = Field(default_factory=list)


class ReasoningGraphDiff(BaseModel):
    """Delta between two graph snapshots."""

    from_step: int
    to_step: int
    added_nodes: list[ReasoningGraphNode] = Field(default_factory=list)
    removed_nodes: list[ReasoningGraphNode] = Field(default_factory=list)
    added_edges: list[ReasoningGraphEdge] = Field(default_factory=list)
    removed_edges: list[ReasoningGraphEdge] = Field(default_factory=list)

class ReasoningCaseState(BaseModel):
    """Normalized reasoning state carried across investigation turns."""

    contract: ReasoningContract = Field(default_factory=ReasoningContract)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    rejected: list[RejectedHypothesis] = Field(default_factory=list)
    observables: dict[str, Any] = Field(default_factory=dict)


class ReasoningOperatorSteering(BaseModel):
    """Operator-provided steering constraints for one reasoning session."""

    confirmed_facts: list[str] = Field(default_factory=list)
    disproved_hypotheses: list[str] = Field(default_factory=list)
    guidance: list[str] = Field(default_factory=list)
    pinned_strategy_family: ReasoningStrategyFamily | None = None
    required_artifacts: list[str] = Field(default_factory=list)


class ReasoningDomainProfile(BaseModel):
    """Reusable cross-domain adapter metadata for one reasoning domain."""

    domain_id: str
    task_type: str
    description: str = ""
    allowed_strategies: list[ReasoningStrategyFamily] = Field(default_factory=list)
    default_strategy: ReasoningStrategyFamily = "generic"


class ReasoningPromptContext(BaseModel):
    """Normalized prompt inputs for one reasoning turn."""

    turn: int
    max_turns: int
    question: str
    evidence_dir: str = ""
    evidence_listing: str = ""
    project_kind: str = ""
    case_model: str = ""
    artifacts: str = ""
    previous: str = ""
    domain_profile: str = "generic"
    operator_steering: ReasoningOperatorSteering = Field(default_factory=ReasoningOperatorSteering)
    strategy_family: ReasoningStrategyFamily = "generic"


class ReasoningTurnDecision(BaseModel):
    """Single-turn decision emitted by the reasoning engine."""

    reasoning: str
    action: ReasoningAction = "reasoning"
    expected_observation: str = ""
    contract: ReasoningContract | None = None
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    rejected: list[RejectedHypothesis] = Field(default_factory=list)
    observables: dict[str, Any] = Field(default_factory=dict)
    script_content: str | None = None
    command: str | None = None
    answer: str | None = None
    confidence: ReasoningConfidence | None = None
    provenance: EvidenceProvenance = Field(default_factory=EvidenceProvenance)
    # Structured submit-payload for terminal outcomes. The system prompt
    # for vuln-research investigations places affected_components,
    # variant_hunt_orders, crash_type, poc_code, etc. under a `payload`
    # key on the submit action. Without this field on the schema,
    # Pydantic silently dropped everything inside `payload` — the agent
    # emitted the right structure but the dispatcher saw empty lists
    # everywhere. Stored as a free-form dict so the schema doesn't have
    # to enumerate every submit-payload variant per module.
    payload: dict[str, Any] = Field(default_factory=dict)
