"""Platform observation-memory primitive (RFC #137).

Central writer + typed contract for turning tool-dispatch outcomes into
workspace-scoped, kind/polarity-tagged, supersedable rows in the
existing pgvector knowledge store. A newer observation about the same
``(module, workspace, subject, kind)`` upserts the prior row through the
knowledge store's ``(namespace, dedup_key)`` uniqueness -- that is the
supersession mechanism. No new DB table, no migration.

The namespace shape is
``{module}.observation.workspace.{workspace_id}``, matching the
``vr.observation.workspace.{id}`` bucket VR's
:func:`aila.modules.vr.services.knowledge_scope.vr_knowledge_namespaces`
already retrieves from. Every module that binds the primitive gets
cross-investigation observation memory: a sibling branch, a later turn,
or a fresh investigation on the same workspace sees the row through the
standard knowledge-retrieval path.

Design notes
------------
* Polarity is first-class: a NEGATIVE observation ("we looked for X in
  this workspace and it wasn't there") is exactly the "we already
  looked" memory the older malware-only :class:`MalwareObservationRecord`
  gave malware. VR's tool executor binds this hook to gain the same
  benefit without inventing another table.
* Supersession is idempotent by design: the ``dedup_key`` is a stable
  hash of ``(module, workspace, subject, kind)``, so re-recording an
  observation about the same subject with a new body simply upserts.
  The knowledge store owns the upsert; there is no ``supersedes_id``
  chain here (the row's ``updated_at`` is the current version stamp,
  the audit trail lives in the store's retrieval journal).
* Writer contract: :func:`record_observation` NEVER raises. A store
  failure logs at WARNING and returns ``None`` so the caller's
  tool-dispatch path is never broken by an observation write. The
  main platform executor calls this from :meth:`_on_tool_success` /
  :meth:`_on_tool_failure` hooks that are already best-effort by
  contract.

SEAM: malware still writes to :class:`MalwareObservationRecord` from
its own tool executor. A later pass should route that writer through
this platform contract (mapping malware's rich kind/polarity/source
onto :class:`PlatformObservation`) and drop the module-only table.
The two paths coexist until that migration lands.
"""
from __future__ import annotations

import hashlib
import logging
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError

from aila.platform.services.knowledge import KnowledgeService

__all__ = [
    "ObservationKind",
    "ObservationPolarity",
    "PlatformObservation",
    "observation_dedup_key",
    "observation_namespace",
    "record_observation",
]

_log = logging.getLogger(__name__)


class ObservationPolarity(StrEnum):
    """Directional tag on an observation.

    ``NEGATIVE`` is first-class: it encodes "we looked for X in this
    workspace and it isn't there" so a later turn / sibling branch /
    future investigation stops re-deriving the same absent fact.
    ``NEUTRAL`` covers observations that carry information without a
    directional claim (a summary, a survey, a rendered body).
    """

    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"


class ObservationKind(StrEnum):
    """Generic tool-outcome kinds shared by every module.

    Modules MAY pass a bare string ``kind`` when they need a
    domain-specific label (malware's twenty-four atomic-fact kinds
    stay in :class:`aila.modules.malware.contracts.observation.ObservationKind`
    until the malware writer migrates onto this contract). The values
    here name the kinds the platform hooks themselves emit.
    """

    # A tool executed cleanly and produced a non-empty result body.
    TOOL_SUCCESS = "tool_success"
    # A tool executed cleanly but produced zero results -- a search /
    # lookup that came back empty. First-class NEGATIVE material.
    TOOL_EMPTY_RESULT = "tool_empty_result"
    # A tool returned an error envelope (semantic failure, not
    # infrastructure). Also first-class NEGATIVE material for
    # dead-end classes like "resource not indexed" / "not found".
    TOOL_FAILURE = "tool_failure"
    # A read tool returned an actual source/body -- a confirming
    # read. POSITIVE material: the subject exists and here is its
    # shape.
    READ_HIT = "read_hit"
    # A lookup by identifier confirmed the resource is absent from
    # the target. NEGATIVE by contract.
    DEAD_END = "dead_end"


class PlatformObservation(BaseModel):
    """Typed observation record persisted to the knowledge store.

    Not a DB row: this contract shapes the ``metadata`` blob and the
    dedup identity written to
    ``{module}.observation.workspace.{workspace_id}``. The knowledge
    store owns the underlying persistence; this model is the platform's
    single writer-side type.
    """

    model_config = ConfigDict(extra="forbid")

    # Owning module id -- matches ``_bridge_module_id`` on the tool
    # executor (``vr``, ``malware``, ...). Written into the namespace
    # prefix so retrieval scope binds by module.
    module: str = Field(min_length=1, max_length=32)
    # Workspace scope this observation belongs to. Same value the
    # module's retrieval path resolves off the investigation ->
    # target -> workspace chain.
    workspace_id: str = Field(min_length=1, max_length=64)
    # The thing the observation is ABOUT (a symbol name, a file path,
    # a search pattern, a CVE id, ...). Combined with ``kind`` to
    # derive the dedup identity so re-recording about the same
    # subject supersedes.
    subject: str = Field(min_length=1, max_length=256)
    # Categorical label. Prefer an :class:`ObservationKind` value;
    # bare strings accepted so modules can extend without touching
    # the platform enum.
    kind: str = Field(min_length=1, max_length=64)
    polarity: ObservationPolarity = ObservationPolarity.NEUTRAL
    # Human-readable body. Also what the knowledge store embeds for
    # semantic recall, so callers should write a self-contained
    # sentence rather than a raw dump.
    content: str = Field(min_length=1)
    # Provenance -- optional so an observation written outside a
    # branch (e.g. an operator-driven ingest) still validates.
    investigation_id: str | None = Field(default=None, max_length=64)
    branch_id: str | None = Field(default=None, max_length=64)
    turn_number: int | None = None
    # Message / entry ids that back this observation, mirroring
    # malware's ``evidence_refs`` column.
    evidence_refs: list[str] = Field(default_factory=list)
    # Escape hatch for module-specific fields (a malware family name,
    # a VR audit_mcp index id, ...). Merged into the persisted
    # metadata blob so retrieval can filter on them.
    extra: dict[str, Any] = Field(default_factory=dict)


def observation_namespace(module: str, workspace_id: str) -> str:
    """Return the workspace-scoped knowledge namespace observations land in.

    Single source of truth so writers and readers cannot drift on the
    naming. Matches the ``vr.observation.workspace.{id}`` bucket the
    VR retrieval scope already enumerates.
    """
    return f"{module}.observation.workspace.{workspace_id}"


def observation_dedup_key(
    module: str, workspace_id: str, subject: str, kind: str,
) -> str:
    """Stable per-(module, workspace, subject, kind) dedup identity.

    Feeds :meth:`KnowledgeService.store`'s ``(namespace, dedup_key)``
    upsert so re-recording about the same subject supersedes the
    prior row. Content-derived hash keeps the key bounded regardless
    of subject length; the ``obs:`` prefix names the identity kind
    for grep-ability against the shared knowledge table.
    """
    digest = hashlib.sha256(
        f"{module}|{workspace_id}|{subject}|{kind}".encode(),
    ).hexdigest()
    return f"obs:{digest[:32]}"


async def record_observation(
    observation: PlatformObservation,
    *,
    writer: KnowledgeService | None = None,
    extract_entities: bool = True,
    link_neighbors: bool = True,
) -> str | None:
    """Persist ``observation`` to the knowledge store, best-effort.

    Returns the store's ``entry_id`` (as a string) on success or
    ``None`` on any failure. NEVER raises: a store failure logs at
    WARNING and returns ``None`` so the caller's main path -- typically
    a tool-dispatch hook fired after the tool result has already
    committed -- is not broken by an observation write.

    ``extract_entities`` and ``link_neighbors`` default True to match
    the shape of VR's existing evicted-observation burn: security
    identifiers found in ``content`` (CVE / CWE / ATT&CK ids) get
    stamped for entity-scoped retrieval, and the row is joined by
    ``related`` edges to its semantic neighbours in the same
    namespace so the graph retrieval route can hop across
    observations.
    """
    metadata: dict[str, Any] = {
        "kind": observation.kind,
        "polarity": observation.polarity.value,
        "subject": observation.subject,
        "module": observation.module,
        "workspace_id": observation.workspace_id,
        "source": "platform_observation",
    }
    if observation.investigation_id is not None:
        metadata["investigation_id"] = observation.investigation_id
    if observation.branch_id is not None:
        metadata["branch_id"] = observation.branch_id
    if observation.turn_number is not None:
        metadata["turn_number"] = observation.turn_number
    if observation.evidence_refs:
        metadata["evidence_refs"] = list(observation.evidence_refs)
    if observation.extra:
        # Do not let ``extra`` clobber the platform-owned keys above:
        # a module cannot silently rewrite ``polarity`` or ``subject``
        # by naming them in ``extra``.
        for key, value in observation.extra.items():
            metadata.setdefault(key, value)

    service = writer if writer is not None else KnowledgeService()
    try:
        result = await service.store(
            namespace=observation_namespace(
                observation.module, observation.workspace_id,
            ),
            content=observation.content,
            metadata=metadata,
            dedup_key=observation_dedup_key(
                observation.module, observation.workspace_id,
                observation.subject, observation.kind,
            ),
            extract_entities=extract_entities,
            link_neighbors=link_neighbors,
        )
    except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
        _log.warning(
            "record_observation failed module=%s workspace=%s subject=%r "
            "kind=%s: %s",
            observation.module, observation.workspace_id,
            observation.subject, observation.kind, exc, exc_info=True,
        )
        return None
    entry_id = result.get("entry_id") if isinstance(result, dict) else None
    return str(entry_id) if entry_id is not None else None
