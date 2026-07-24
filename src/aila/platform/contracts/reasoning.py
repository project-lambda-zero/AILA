from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    field_validator,
    model_validator,
)

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
    "ReasoningStrategyDeclaration",
    "ReasoningStrategyFamily",
    "ReasoningTurnDecision",
    "EvidenceProvenance",
    "Hypothesis",
    "ObservablesDict",
    "RejectedHypothesis",
]

ReasoningAction = Literal[
    "script_execute",
    "tool_run",
    "reasoning",
    "recall",
    "submit",
    "submit_outcome_review",
    "edit_outcome",
]
ReasoningConfidence = Literal["exact", "strong", "medium", "caveated", "unknown"]
# Strategy families are runtime-validated by the platform StrategyRegistry
# (populated from each module's reasoning_strategies() at load), not a
# closed Literal -- the platform no longer names module-domain strategies.
# ``"generic"`` is the one family the platform itself owns.
ReasoningStrategyFamily = str
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
    # Turn number at which this hypothesis became live. Used by
    # ``render_case_model`` to surface aging so the agent feels
    # pressure to close hypotheses that have been live for many turns
    # without resolution. Defaults to 0 for backward compat with rows
    # serialized before this field existed; ``absorb`` stamps new
    # hypotheses with the current turn number when given one.
    opened_at_turn: int = 0


class RejectedHypothesis(BaseModel):
    """One disproved or discarded hypothesis with rationale."""

    id: str
    claim: str
    reason: str = ""


class ResolvedHypothesis(BaseModel):
    """One hypothesis closed automatically when a branch submitted a
    terminal outcome without explicitly classifying it as either
    confirmed or rejected.

    Distinct from ``RejectedHypothesis`` because we DON'T know whether
    the claim was disproved or supported by the terminal -- it may have
    been the basis of the finding (confirmed) or an unaddressed
    competing explanation (effectively rejected) or simply abandoned
    as the agent ran out of turns. The frontend renders ``resolved``
    with a neutral badge so readers know to consult the terminal
    outcome for the actual classification.
    """

    id: str
    claim: str
    resolved_at_turn: int = 0
    terminal_outcome_kind: str = ""
    note: str = ""

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

def _require_json_serializable(value: dict[str, Any]) -> dict[str, Any]:
    """Reject an observables dict that cannot round-trip through json.dumps.

    observables is persisted to the DB and passed as task kwargs, both of which
    json-encode it. A datetime, bytes, set, or custom object passes Pydantic's
    ``dict[str, Any]`` check but crashes later at serialization time (issue
    #61). Fail fast at construction with the offending detail instead.
    """
    try:
        json.dumps(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"observables must be JSON-serializable (DB + task-kwarg persistence): {exc}"
        ) from exc
    return value


def _validate_json_serializable(v: dict[str, Any]) -> dict[str, Any]:
    """Reject non-JSON observables at construction time (#61-2).

    Observables are persisted as ``case_state_json`` and forwarded as
    task kwargs, both of which require JSON encoding; a ``datetime`` /
    ``bytes`` / ``set`` slipping in passes Pydantic construction, survives
    every in-process mutation, and only crashes later at ``model_dump
    (mode='json')`` / ``task_queue.submit`` -- far from the code that
    introduced it. One ``json.dumps`` here proves every key and value has
    a JSON encoding and surfaces the offender at the source.
    """
    try:
        json.dumps(v, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"observables must be JSON-serializable: {exc}",
        ) from exc
    return v


ObservablesDict = Annotated[
    dict[str, Any],
    AfterValidator(_validate_json_serializable),
]


class ReasoningCaseState(BaseModel):
    """Normalized reasoning state carried across investigation turns."""

    contract: ReasoningContract = Field(default_factory=ReasoningContract)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    rejected: list[RejectedHypothesis] = Field(default_factory=list)
    resolved: list[ResolvedHypothesis] = Field(default_factory=list)
    observables: ObservablesDict = Field(default_factory=dict)
    # Most recent turn number this state was absorbed at. Used by
    # ``render_case_model`` to compute hypothesis age (current_turn -
    # hypothesis.opened_at_turn). 0 means "never absorbed with a turn
    # number" (legacy rows). Filled in by ``absorb(turn_number=N)``.
    current_turn: int = 0

    @field_validator("observables")
    @classmethod
    def _observables_serializable(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _require_json_serializable(v)


class ReasoningOperatorSteering(BaseModel):
    """Operator-provided steering constraints for one reasoning session."""

    confirmed_facts: list[str] = Field(default_factory=list)
    disproved_hypotheses: list[str] = Field(default_factory=list)
    guidance: list[str] = Field(default_factory=list)
    pinned_strategy_family: ReasoningStrategyFamily | None = None
    required_artifacts: list[str] = Field(default_factory=list)


class ReasoningStrategyDeclaration(BaseModel):
    """A reasoning strategy family published by a module.

    Modules declare their strategy families through
    ``ModuleProtocol.reasoning_strategies()``; the platform collects them
    into the StrategyRegistry at load. The platform itself owns only the
    ``generic`` family.
    """

    family: str
    task_type: str
    description: str = ""


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
    observables: ObservablesDict = Field(default_factory=dict)
    script_content: str | None = None
    command: str | None = None
    # Names observable keys the engine MUST pull into the next turn's
    # prompt with their full uncapped body. Populated only when
    # ``action == "recall"``. Copy keys verbatim from the tool-readings
    # INDEX rendered in the prior turn's case_model.
    recall_keys: list[str] = Field(default_factory=list)
    answer: str | None = None
    confidence: ReasoningConfidence | None = None
    provenance: EvidenceProvenance = Field(default_factory=EvidenceProvenance)
    # Structured submit-payload for terminal outcomes. The system prompt
    # for vuln-research investigations places affected_components,
    # variant_hunt_orders, crash_type, poc_code, etc. under a `payload`
    # key on the submit action. Without this field on the schema,
    # Pydantic silently dropped everything inside `payload` -- the agent
    # emitted the right structure but the dispatcher saw empty lists
    # everywhere. Stored as a free-form dict so the schema doesn't have
    # to enumerate every submit-payload variant per module.
    # Sibling-corroborated draft outcome review (vr draft workflow).
    # When ``action == "submit_outcome_review"`` the agent MUST set
    # ``review_outcome_id`` (the draft being reviewed) and ``review_vote``
    # (approve | reject | request_edit | abstain). ``review_comment``
    # carries the rationale that the operator sees on the outcome
    # detail card; if absent, ``reasoning`` is used as a fallback.
    # Suggested payload edits ride on the existing ``payload`` dict
    # so the schema doesn't grow another free-form field.
    review_outcome_id: str | None = None
    review_vote: Literal[
        "approve", "reject", "request_edit", "abstain",
    ] | None = None
    review_comment: str | None = None
    # ``edit_outcome`` action: directly merge ``edit_patches`` into a
    # draft outcome's payload (counterpart to the deferred
    # ``request_edit`` vote -- that path stores suggested edits on the
    # review row and waits for the next synthesis pass; this path is
    # the IMMEDIATE merge). ``edit_outcome_id`` names the target,
    # ``edit_patches`` is a top-level merge dict (protected keys --
    # ``panel_contributions``, ``panel_summary``, ``verifier_report``,
    # ``applied_by_synthesis`` -- are dropped server-side). The merge
    # only fires on ``state == 'draft'`` outcomes; the service layer
    # refuses on approved / rejected / dispatched rows and reports the
    # reason so the agent can steer accordingly.
    edit_outcome_id: str | None = None
    edit_patches: dict[str, Any] = Field(default_factory=dict)
    edit_comment: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observables")
    @classmethod
    def _observables_serializable(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _require_json_serializable(v)

    @model_validator(mode="after")
    def _validate_tool_run_command(self) -> ReasoningTurnDecision:
        """When ``action='tool_run'``, ``command`` MUST parse as JSON with
        a ``tool`` (string) and ``args`` (dict).

        Why this lives on the schema instead of the executor:

        Without this validator, a malformed ``command`` field (the most
        common failure mode is truncation when the model's
        ``max_tokens`` budget is exhausted by extended-thinking) surfaces
        only at ``tool_executor._parse_command`` as a generic "Malformed
        tool_run command" text message persisted to the investigation
        thread. The agent's NEXT turn then re-tries the same broken
        emission with no signal that the original failure was caused by
        truncation. Worse, the LLM client's existing
        ``_check_truncation`` (client.py:980) ONLY fires when the OUTER
        wrapper JSON fails to parse; it does NOT validate inner string
        fields like ``command``, so truncation of the inner JSON-as-
        string slips through silently.

        Promoting the check to a Pydantic validator makes the LLM
        client's structured-response decoder fail validation BEFORE the
        response is returned to the caller. That triggers
        ``chat_structured``'s built-in retry-with-correction prompt
        (client.py:360-446) so the agent gets one shot to fix the
        emission on the same LLM round trip -- much cheaper than burning
        a full investigation turn on a parse failure.

        Validation rules (lenient on purpose -- we want to catch broken
        emissions, not gatekeep the schema):

          * ``action='tool_run'`` AND ``command`` is None/empty/blank
            → fail with a message identifying the empty-command shape.
          * ``action='tool_run'`` AND ``command`` doesn't parse as JSON
            → fail with the parse error position and a hint about
            max_tokens truncation, which is the dominant cause.
          * ``action='tool_run'`` AND parsed value is not a dict
            → fail naming the actual type seen.
          * ``action='tool_run'`` AND ``tool`` key missing or
            ``args`` key missing/wrong-type → fail naming the
            specific missing field.
          * Any other action (``reasoning``, ``submit``,
            ``script_execute``) → no check on ``command`` (those
            actions don't use it).
        """
        import json as _json

        if self.action != "tool_run":
            return self

        raw = self.command
        if raw is None or not raw.strip():
            raise ValueError(
                "action='tool_run' requires a non-empty `command` "
                "containing JSON with 'tool' (str) and 'args' (dict). "
                f"Got: {raw!r}. Common cause: max_tokens truncation "
                "cut the emission before the command JSON was written."
            )

        try:
            parsed = _json.loads(raw)
        except _json.JSONDecodeError as exc:
            raise ValueError(
                f"action='tool_run' command must be valid JSON. Parse "
                f"failed at line {exc.lineno} col {exc.colno}: "
                f"{exc.msg}. Common cause: max_tokens truncation cut "
                f"the emission mid-string. Command starts with: "
                f"{raw[:60]!r} ends with: {raw[-60:]!r} (length="
                f"{len(raw)})."
            ) from exc

        if not isinstance(parsed, dict):
            raise ValueError(
                f"action='tool_run' command JSON must decode to an "
                f"object/dict. Got: {type(parsed).__name__}."
            )

        tool = parsed.get("tool")
        if not isinstance(tool, str) or not tool:
            raise ValueError(
                "action='tool_run' command must include 'tool' as a "
                "non-empty string of shape '<server>.<tool_name>' "
                "(e.g. 'audit_mcp.semantic_search'). Got: "
                f"tool={tool!r}."
            )

        args = parsed.get("args")
        if not isinstance(args, dict):
            raise ValueError(
                "action='tool_run' command must include 'args' as a "
                f"JSON object/dict. Got: args type={type(args).__name__}."
            )

        return self

    @model_validator(mode="after")
    def _validate_submit_outcome_review(self) -> ReasoningTurnDecision:
        """When ``action='submit_outcome_review'``, ``review_outcome_id``
        and ``review_vote`` MUST both be set.

        Without this check the dispatcher receives a no-op review that
        the agent thinks counted; the draft outcome stays in DRAFT
        state forever because the upsert was rejected at the service
        layer with a generic ValueError, and the agent burns turns
        re-emitting the same broken vote shape.
        """
        if self.action != "submit_outcome_review":
            return self
        if not self.review_outcome_id:
            raise ValueError(
                "action='submit_outcome_review' requires "
                "`review_outcome_id` (the uuid of the draft outcome "
                "you are voting on). Copy it verbatim from the "
                "'Outcome id:' line of the *** DRAFT OUTCOME UP FOR "
                "REVIEW *** operator message."
            )
        if not self.review_vote:
            raise ValueError(
                "action='submit_outcome_review' requires `review_vote` "
                "in {approve, reject, request_edit, abstain}. Got: "
                f"{self.review_vote!r}."
            )
        return self

    @model_validator(mode="after")
    def _validate_recall(self) -> ReasoningTurnDecision:
        """When ``action='recall'``, ``recall_keys`` MUST be a non-empty
        list of non-empty strings naming observable keys the engine will
        pin into the next prompt with their full uncapped body.

        Without this check the agent burns a turn on a no-op recall:
        the engine records the empty recall_keys, ``_recall.pinned`` is
        unchanged, and the next turn renders the same INDEX with none
        of the desired bodies pulled through. Catch the malformed
        emission at the Pydantic boundary so the LLM client's
        correction retry fires before a full investigation turn is
        burned.
        """
        if self.action != "recall":
            return self
        if not isinstance(self.recall_keys, list) or not self.recall_keys:
            raise ValueError(
                "action='recall' requires `recall_keys` to be a "
                "non-empty list of observable keys to pin into the "
                "next turn's prompt with their full uncapped body. "
                "Copy each key verbatim from the tool-readings INDEX "
                "in your current case_model (e.g. "
                "'audit_mcp:read_function.source.foo'). Got: "
                f"{self.recall_keys!r}."
            )
        for idx, key in enumerate(self.recall_keys):
            if not isinstance(key, str) or not key.strip():
                raise ValueError(
                    "action='recall' requires every entry in "
                    "`recall_keys` to be a non-empty string naming "
                    "an observable key from the tool-readings INDEX. "
                    f"recall_keys[{idx}]={key!r} is invalid."
                )
        return self

    @model_validator(mode="after")
    def _validate_edit_outcome(self) -> ReasoningTurnDecision:
        """When ``action='edit_outcome'``, ``edit_outcome_id`` and a
        non-empty ``edit_patches`` dict MUST both be set.

        Without this check the engine dispatches a no-op edit that the
        agent thinks landed; the draft outcome stays unchanged and the
        operator sees nothing. Catch the malformed emission at the
        Pydantic boundary so the LLM client's correction retry fires
        before a full investigation turn is burned.
        """
        if self.action != "edit_outcome":
            return self
        if not self.edit_outcome_id:
            raise ValueError(
                "action='edit_outcome' requires `edit_outcome_id` "
                "(the uuid of the draft outcome you are editing). "
                "Copy it from the 'Outcome id:' line of the "
                "*** DRAFT OUTCOME UP FOR REVIEW *** operator message "
                "or from a prior outcome reference in your prompt."
            )
        if not self.edit_patches:
            raise ValueError(
                "action='edit_outcome' requires a non-empty "
                "`edit_patches` dict mapping top-level outcome "
                "payload keys (e.g. iocs, capabilities, "
                "family_attribution, summary, answer) to their new "
                "values. An empty patch is a no-op -- use "
                "action='submit_outcome_review' with vote='approve' "
                "if you have no changes to make."
            )
        return self
