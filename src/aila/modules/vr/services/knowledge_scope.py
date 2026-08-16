"""Knowledge-base retrieval scope for the VR module (RFC-12).

Single source of truth for the workspace-scoped knowledge namespaces the VR
module retrieves from, shared by the Phase 1 setup resolver (which seeds the
RETRIEVED prompt tier) and the agentic knowledge bridge (which the agent
calls on demand). Keeping the list here means the setup path and the agent
path can never drift on what a VR investigation is allowed to recall.

The outcome dispatcher writes each knowledge kind under
``vr.<kind>.workspace.<id>`` (workspace scope), plus team- and global-scoped
audit memos. The agent never supplies the workspace, so no cross-workspace
recall is possible.

Issue #150 procedural tier: the platform skill-library sweep
(:mod:`aila.platform.services.memory.skills`) writes reusable
``(problem_shape -> approach)`` skills to a team-scoped
``skill.team.<team_id>`` namespace (or ``skill.global`` on
single-tenant installs). Including that namespace here is what makes
those skills visible at investigation setup time so the agent
compounds on prior wins across every workspace in the same team.
"""
from __future__ import annotations

from aila.platform.services.memory.skills import skill_namespace

__all__ = ["VR_KNOWLEDGE_KINDS", "vr_knowledge_namespaces"]

# VR knowledge kinds the outcome dispatcher writes, workspace-scoped; see
# aila.modules.vr.agents.outcome_dispatcher.
VR_KNOWLEDGE_KINDS: tuple[str, ...] = (
    "finding",
    "audit_memo",
    "strategy_descriptor",
    "crash_triage",
    "config_delta",
    "profile_spec",
    # RFC-12: evicted observations burned by the VR ToolExecutor's
    # _on_observables_evicted hook, so working-memory eviction does not
    # lose the underlying tool reading -- it just moves off the hot path.
    "observation",
    # Issue #150: semantic-tier facts written by the platform consolidator
    # (:mod:`aila.platform.services.memory.consolidator`) after distilling
    # a resolved investigation's ledger traces. Reading the semantic
    # namespace on every retrieval is what makes those facts visible to
    # the agent -- the writer relies on this list being the single
    # source of truth on which buckets are live.
    "semantic",
    # Operator-authored notes ingested from the console
    # (POST /platform/knowledge/ingest). A distinct kind so operator
    # context is filterable apart from agent-written memos, while still
    # being retrieved on every turn in the workspace.
    "operator_note",
)


def vr_knowledge_namespaces(
    workspace_id: str, team_id: str | None = None,
) -> list[str]:
    """Return the workspace-scoped knowledge namespaces to retrieve from."""
    namespaces = [
        f"vr.{kind}.workspace.{workspace_id}" for kind in VR_KNOWLEDGE_KINDS
    ]
    if team_id:
        namespaces.append(f"vr.audit_memo.team.{team_id}")
        namespaces.append(f"vr.operator_note.team.{team_id}")
    namespaces.append("vr.audit_memo.global")
    namespaces.append("vr.operator_note.global")
    # Issue #150 procedural tier: team-scoped skill library (or the
    # global fallback on single-tenant installs). Cross-module by
    # design so a VR investigation can retrieve a winning approach a
    # sibling module previously recorded under the same problem shape.
    namespaces.append(skill_namespace(team_id))
    return namespaces
