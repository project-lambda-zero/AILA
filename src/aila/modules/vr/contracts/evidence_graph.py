"""Evidence graph contract (08_FRONTEND_UX.md §1.9).

Server-side layout authoritative for ``GET /vr/investigations/{id}/evidence-graph``.
The frontend EvidenceGraph component prefers these coords when present
(stable across reloads + across operators), falling back to its own
concentric layout when the endpoint returns no coords (e.g. for
ephemeral cards).
"""
from __future__ import annotations

from aila.platform.contracts.evidence_graph import (
    EvidenceGraphEdge,
    EvidenceGraphNode,
    EvidenceGraphSnapshot,
)

__all__ = [
    "EvidenceGraphEdge",
    "EvidenceGraphNode",
    "EvidenceGraphSnapshot",
]
