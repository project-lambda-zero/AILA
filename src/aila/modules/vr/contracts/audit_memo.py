"""Audit memo contract (M3.R-1).

Audit memos are NEGATIVE findings (D-38): 'I audited this region, no
bug exists.' They prevent dead-end re-exploration in future
investigations.

Persistence per the platform rule: audit memos ride on the existing
``KnowledgeEntryRecord`` (pgvector 384-dim + HNSW + tsvector FTS,
``src/aila/storage/db_models.py:520``) via namespace
``vr.audit_memo.<scope>``. We do NOT create a separate
``vr_audit_memos`` table — the platform already provides the vector
store and FTS index.

Scope conventions:
  - ``vr.audit_memo.local.<investigation_id>``       — investigation-only
  - ``vr.audit_memo.workspace.<workspace_id>``       — workspace-scoped
  - ``vr.audit_memo.team.<team_id>``                 — team-scoped
  - ``vr.audit_memo.global``                         — promoted globally
                                                       (platform_admin only)

The 90-day expiry from D-38 is enforced by an eviction worker
(M3.R-4 milestone) that walks the KnowledgeEntryRecord namespace and
deletes entries past their ``expires_at`` unless ``promoted=true``.
``expires_at`` + ``promoted`` are stored in the entry's
``entry_metadata`` JSON since KnowledgeEntryRecord is generic.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from aila.modules.vr.contracts.outcome import OutcomeConfidence

__all__ = [
    "AuditMemoCreate",
    "AuditMemoScope",
    "AuditMemoSummary",
]


class AuditMemoScope(StrEnum):
    """Promotion ladder for audit memos. Matches D-43 GA-41 pattern scopes."""

    LOCAL = "local"
    WORKSPACE = "workspace"
    TEAM = "team"
    GLOBAL = "global"


class AuditMemoCreate(BaseModel):
    """Input payload for creating an audit memo.

    Typically emitted as a VROutcome (kind=audit_memo) by the engine
    rather than directly via API, but the same shape is reused for
    manual operator-created memos.
    """

    model_config = ConfigDict(extra="forbid")

    investigation_id: str = Field(min_length=1, max_length=64)
    target_signature: str = Field(
        min_length=1, max_length=128,
        description="SHA256(target_id + region_descriptor). Used as cache key + dedup.",
    )
    region_descriptor: str = Field(
        min_length=1,
        description="Human-readable region label, e.g. 'function v8::FastAPI::serialize at api-natives.cc:1024'.",
    )
    claim: str = Field(
        min_length=1,
        description="The audit claim — 'audited for X, no bug exists because Y'.",
    )
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: OutcomeConfidence = OutcomeConfidence.MEDIUM
    pivot_history: list[str] = Field(
        default_factory=list,
        description="Pivots tried before reaching this verdict (D-35 novelty_evidence pattern).",
    )
    scope: AuditMemoScope = AuditMemoScope.LOCAL


class AuditMemoSummary(BaseModel):
    """Read-only projection of one audit memo.

    Hydrated from a KnowledgeEntryRecord row: the ``content`` field
    becomes ``claim`` + ``region_descriptor``; ``entry_metadata`` JSON
    carries everything else (investigation_id, target_signature,
    evidence_refs, confidence, scope, expires_at, promoted).
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    investigation_id: str
    workspace_id: str | None = None
    target_signature: str
    region_descriptor: str
    claim: str
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: OutcomeConfidence
    pivot_history: list[str] = Field(default_factory=list)
    scope: AuditMemoScope
    expires_at: datetime | None = None
    promoted: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None
