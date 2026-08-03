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
"""
from __future__ import annotations

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
    namespaces.append("vr.audit_memo.global")
    return namespaces
