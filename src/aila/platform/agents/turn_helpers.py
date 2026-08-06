"""Shared turn-runner helpers (RFC-03).

Pure functions lifted verbatim from the vr and malware turn runners,
which held byte-identical copies: the case-state JSON codec, terminal
live-hypothesis auto-resolution, and outcome-confidence coercion. These
depend only on platform contract types (ReasoningCaseState,
ResolvedHypothesis, ReasoningTurnDecision, OutcomeConfidence). No DB, no
side effects beyond the documented in-place case_state mutation.
"""
from __future__ import annotations

import json

from aila.platform.contracts.enums import OutcomeConfidence
from aila.platform.contracts.reasoning import (
    ReasoningCaseState,
    ReasoningTurnDecision,
    ResolvedHypothesis,
)

__all__ = [
    "auto_resolve_live_on_terminal",
    "decode_case_state",
    "encode_case_state",
    "to_outcome_confidence",
]


def decode_case_state(raw_json: str | None) -> ReasoningCaseState:
    if not raw_json:
        return ReasoningCaseState()
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return ReasoningCaseState()
    try:
        return ReasoningCaseState.model_validate(data)
    except (ValueError, TypeError):
        return ReasoningCaseState()


def encode_case_state(state: ReasoningCaseState) -> str:
    return json.dumps(state.model_dump(mode="json"))


def auto_resolve_live_on_terminal(
    state: ReasoningCaseState,
    *,
    turn: int,
    outcome_kind: str,
) -> None:
    """Move every still-live hypothesis to ``state.resolved`` in place.

    Called from ``run_turn`` immediately before the case_state is
    serialised for a terminal submission. A hypothesis sitting in
    ``state.hypotheses`` at submit time can be in three states the
    agent never explicitly labels:
      - CONFIRMED: agent relied on it as the basis of the finding
      - REJECTED: agent ran out of turns / refuted but forgot to move
      - SUPERSEDED: subsumed by a finer hypothesis but never killed

    Without auto-bucketing, these hypotheses stay "live" in the rail
    forever even though the investigation has concluded. The previous
    implementation moved them to ``state.rejected`` -- but that's
    actively misleading for confirmed claims (e.g. the agent's
    'predicate symmetry holds' claim that grounds a 'VARIANT DEAD'
    finding shouldn't be labeled 'rejected' in red).

    New behavior: move to ``state.resolved`` with a neutral note that
    points the reader at the terminal outcome for the actual
    classification. The frontend renders ``resolved`` with a yellow
    badge -- neither red (rejected) nor green (confirmed) -- so readers
    know to consult the canonical outcome.
    """
    if not state.hypotheses:
        return
    note = (
        f"auto-resolved at turn {turn}: branch submitted terminal "
        f"{outcome_kind} -- see canonical outcome for whether this "
        f"claim was confirmed (basis of finding) or refuted "
        f"(unaddressed alternative)"
    )
    seen_resolved = {r.id for r in state.resolved}
    seen_rejected = {r.id for r in state.rejected}
    for h in state.hypotheses:
        if h.id in seen_resolved or h.id in seen_rejected:
            continue
        state.resolved.append(
            ResolvedHypothesis(
                id=h.id,
                claim=h.claim,
                resolved_at_turn=turn,
                terminal_outcome_kind=outcome_kind,
                note=note,
            ),
        )
    state.hypotheses = []


def to_outcome_confidence(decision: ReasoningTurnDecision) -> OutcomeConfidence:
    if decision.confidence:
        return OutcomeConfidence(decision.confidence)
    return OutcomeConfidence.UNKNOWN
