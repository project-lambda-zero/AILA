"""Schemas for the admin RAG knowledge-store router.

Exposes the ``KnowledgeEntryRecord`` corpus + ``KnowledgeEntryEdge`` graph
over HTTP so an operator can inspect what the platform has ingested,
paginate/filter entries, and run an ad-hoc retrieval against the same
routed retrieval path the agent tools use.

Kept intentionally thin: shapes mirror what the console console needs
(see AILA cross-task contract). ``entry_metadata`` is surfaced as a
parsed ``dict`` (the DB stores it as a JSON-encoded ``Text`` column;
parsing at the router boundary keeps callers from re-parsing).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "KnowledgeStatsBucket",
    "KnowledgeStats",
    "KnowledgeEntryView",
    "KnowledgeEntriesPage",
    "KnowledgeHit",
    "KnowledgeIngestRequest",
    "KnowledgeIngestResult",
]


class KnowledgeStatsBucket(BaseModel):
    """One row of a ``GROUP BY`` breakdown -- ``{key, count}``.

    ``key`` may be ``None`` when the underlying column allows NULL
    (``model_id`` and ``source_type`` are nullable on
    ``KnowledgeEntryRecord``) so the operator can see that a share of
    entries were written by a code path that never stamped the field.
    """

    model_config = ConfigDict(extra="forbid")

    key: str | None
    count: int


class KnowledgeStats(BaseModel):
    """Aggregate view of the knowledge store used by the console overview.

    ``total_entries`` is the full ``KnowledgeEntryRecord`` row count and
    ``edge_count`` the full ``KnowledgeEntryEdge`` row count -- both are
    honest, not sampled. The three breakdowns are ordered by ``count``
    desc and capped server-side (top ~50) so a corpus with thousands of
    distinct namespaces does not stream every bucket over the wire.
    """

    model_config = ConfigDict(extra="forbid")

    total_entries: int
    edge_count: int
    by_namespace: list[KnowledgeStatsBucket] = Field(default_factory=list)
    by_source_type: list[KnowledgeStatsBucket] = Field(default_factory=list)
    by_model: list[KnowledgeStatsBucket] = Field(default_factory=list)


class KnowledgeEntryView(BaseModel):
    """One ``KnowledgeEntryRecord`` row projected for admin browsing.

    Excludes ``embedding`` (a 1024-dim pgvector column is never useful
    to a UI) and ``search_vector`` (a generated tsvector, likewise). The
    ``entry_metadata`` JSON blob is parsed to a dict so the caller does
    not need to re-parse it.
    """

    model_config = ConfigDict(extra="forbid")

    id: int
    namespace: str
    content: str
    source_type: str | None = None
    model_id: str | None = None
    created_at: datetime
    entry_metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeEntriesPage(BaseModel):
    """Paged ``KnowledgeEntryView`` list with a filtered-total counter."""

    model_config = ConfigDict(extra="forbid")

    items: list[KnowledgeEntryView]
    total: int


class KnowledgeHit(BaseModel):
    """One retrieval hit as returned by ``KnowledgeService.retrieve_routed``.

    ``score`` is the merged ``0.6*vec + 0.4*fts`` cosine-scale score for
    the simple/stable-core paths and stationary PPR mass for the graph
    route -- the two are not directly comparable but both are ranked
    high-to-low so ordering is meaningful within a single response.
    ``source_type`` / ``model_id`` are lifted from the gate's
    ``provenance`` sub-dict.
    """

    model_config = ConfigDict(extra="forbid")

    id: int
    namespace: str
    content: str
    score: float
    source_type: str | None = None
    model_id: str | None = None


class KnowledgeIngestRequest(BaseModel):
    """Operator-authored note written into the retrieval corpus.

    The note lands under a distinct ``operator_note`` kind so it is
    filterable apart from agent-written memos, while still being on the
    retrieval path (VR + malware retrieve ``<module>.operator_note.*``
    on every turn -- see each module's ``knowledge_scope``).

    ``scope`` selects the reach:

    * ``workspace`` -- ``<module>.operator_note.workspace.<scope_id>``;
      only agents running in that workspace recall it.
    * ``team`` -- ``<module>.operator_note.team.<scope_id>``; every
      workspace on that team recalls it.
    * ``global`` -- ``<module>.operator_note.global``; every workspace
      in that module recalls it. ``scope_id`` is ignored.
    * ``agent`` -- ``agent:<scope_id>``; the platform per-agent
      namespace used by the generic knowledge tool. ``module`` is
      ignored.

    ``scope_id`` is required for every scope except ``global``.
    """

    model_config = ConfigDict(extra="forbid")

    module: str = Field(
        default="vr",
        description="Module whose retrieval path consumes the note (vr | malware). "
        "Ignored for the agent scope.",
    )
    scope: str = Field(description="workspace | team | global | agent")
    scope_id: str | None = Field(
        default=None,
        description="Workspace id, team id, or agent name. Required unless scope is global.",
    )
    title: str | None = Field(default=None, max_length=200)
    content: str = Field(min_length=1)
    metadata: dict[str, Any] | None = None


class KnowledgeIngestResult(BaseModel):
    """Outcome of a :class:`KnowledgeIngestRequest` write."""

    model_config = ConfigDict(extra="forbid")

    entry_id: int | None
    namespace: str
    operation: str
