"""Sibling-consensus rejection injector (RFC-03 Phase 2).

Pure function extracted verbatim from the vr and malware turn runners
(byte-identical copies). When 2+ sibling branches have rejected a
hypothesis this branch still holds live, it writes the
``_directive.sibling_consensus_rejection`` observable so the next turn's
prompt confronts the agent with the sibling consensus. No DB, no side
effects beyond mutating ``case_state.observables``.
"""
from __future__ import annotations

from typing import Any

__all__ = ["inject_sibling_consensus"]


def inject_sibling_consensus(
    case_state: Any, sibling_context: list[dict], my_live_ids: set[str],
) -> Any:
    """Return *case_state* with the sibling-consensus directive set when
    2+ siblings rejected any id in *my_live_ids*.

    ``my_live_ids`` is computed by the caller from its own hypothesis
    shape; the injector only reads *sibling_context* and writes the
    directive observable. A no-op when either input is empty or no id
    reaches the 2-sibling threshold.
    """
    if not (my_live_ids and sibling_context):
        return case_state
    sibling_rejection_count: dict[str, int] = {}
    sibling_rejection_claims: dict[str, list[str]] = {}
    for sib in sibling_context:
        for rej in sib.get("rejected", []):
            rid = rej.get("id")
            if not rid or rid not in my_live_ids:
                continue
            sibling_rejection_count[rid] = sibling_rejection_count.get(rid, 0) + 1
            sibling_rejection_claims.setdefault(rid, []).append(
                f"{sib.get('persona_voice','?')}: {rej.get('claim','')[:120]}"
            )
    consensus_rejections = {
        rid: claims for rid, claims in sibling_rejection_claims.items()
        if sibling_rejection_count.get(rid, 0) >= 2
    }
    if consensus_rejections:
        directive_lines = [
            "*** SIBLING CONSENSUS REJECTION ***",
            f"You have {len(consensus_rejections)} hypothesis(es) still LIVE that ",
            "2+ sibling branches have already REJECTED with source-citing evidence:",
            "",
        ]
        for rid, claims in consensus_rejections.items():
            directive_lines.append(f"  hypothesis id={rid}")
            for c in claims:
                directive_lines.append(f"    - {c}")
        directive_lines.append("")
        directive_lines.append(
            "This turn you MUST either: (a) include these ids in your "
            "decision.rejected[] with your own short concurring claim, "
            "OR (b) explain in reasoning why you disagree AND cite the "
            "verbatim source contradicting the siblings' refutation. "
            "Passive 'keep alive without comment' is a deliberation "
            "integrity failure."
        )
        # fix §103 -- directive lives ONLY in the in-memory
        # case_state.observables; the absorb()→branch_row write
        # at the end of this turn persists it as part of the
        # ONE consolidated case_state write per turn (was three
        # writes: directive injection here, normal write at
        # message-write site, terminal overwrite). The prompt
        # builder below reads from `case_state` (line ~295) so
        # this turn already sees the directive; absorb()
        # preserves observables into new_case_state, which
        # encodes to branch_row.case_state_json at end-of-turn.
        # fix §89 -- eliminates the pre-LLM directive UoW
        # (one of the three commits this method used to run
        # per turn). On a crash before the end-of-turn UoW
        # the directive recomputes deterministically from
        # sibling_context on retry, so no audit loss.
        case_state.observables["_directive.sibling_consensus_rejection"] = "\n".join(directive_lines)
    return case_state
