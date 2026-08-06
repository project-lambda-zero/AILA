"""Retrieval sanitize/classify + provenance gate -- RFC-12 criterion 6.

Every knowledge hit returned to a caller passes through :func:`apply_gate`,
which does three things without touching the underlying entry row:

* Runs the content through :func:`sanitize_input` (the same untrusted-input
  scrubber the LLM pipeline uses) and stamps ``sanitized_content`` +
  ``content_sanitized`` on the hit. The original ``content`` is kept
  verbatim so a caller that wants the raw bytes can still see them; a
  caller emitting into a prompt reads ``sanitized_content``.
* Classifies the content via :func:`classify_messages` and adds
  ``classification`` (``"public"`` / ``"internal"`` / ``"restricted"``).
  RESTRICTED hits are annotated with the pattern types that fired so the
  caller can decide whether to redact them further before use.
* Copies the provenance columns (``model_id``, ``content_hash``,
  ``source_type``, ``updated_at``, ``created_at``, ``namespace``) into a
  nested ``provenance`` dict on the hit. RFC-12 criterion 6 requires every
  retrieved item to carry provenance; centralising the extraction here
  avoids each caller redoing the column reads or forgetting a field.

The gate is pure (no I/O, no globals mutated) so it composes cleanly with
the different retrieval paths and stays trivially unit-testable. It also
does not mutate its input dict; a new dict comes back so callers who
retained a reference to the raw hit see the pre-gate shape.
"""

from __future__ import annotations

from typing import Any

from ..llm.classify import ClassificationLevel, classify_messages
from ..llm.sanitize import sanitize_input

__all__ = [
    "GATE_FIELD_KEYS",
    "PROVENANCE_KEYS",
    "apply_gate",
    "apply_gate_many",
]

# The keys :func:`apply_gate` adds to every hit dict. Exported so a test
# can assert coverage without duplicating the string list.
GATE_FIELD_KEYS: tuple[str, ...] = (
    "sanitized_content",
    "content_sanitized",
    "classification",
    "classification_matches",
    "provenance",
)

# The provenance sub-fields the gate lifts out of the entry row (or the
# caller-supplied ``entry_row`` mapping). Kept as a module constant so
# both the extractor and the tests share one canonical list.
PROVENANCE_KEYS: tuple[str, ...] = (
    "model_id",
    "content_hash",
    "source_type",
    "created_at",
    "updated_at",
    "namespace",
)


def _extract_provenance(hit: dict[str, Any], entry_row: Any | None) -> dict[str, Any]:
    """Build the ``provenance`` sub-dict for a single hit.

    Two lookup layers so both call sites work: hits produced by
    :meth:`KnowledgeService.retrieve` carry ``namespace`` inline and get
    the rest of their provenance from the caller-supplied ``entry_row``
    row; graph/stable-core hits already carry every column and pass
    ``entry_row=None`` because the hit dict is itself the row. Missing
    columns are stamped as ``None`` so the caller can inspect the key
    set uniformly.
    """
    prov: dict[str, Any] = {}
    for key in PROVENANCE_KEYS:
        value: Any = None
        if key in hit and hit.get(key) is not None:
            value = hit.get(key)
        elif entry_row is not None:
            value = _row_attr(entry_row, key)
        prov[key] = value
    return prov


def _row_attr(entry_row: Any, key: str) -> Any:
    """Return ``entry_row[key]`` or ``getattr(entry_row, key)``, else None.

    Handles both mapping-shaped and ORM-shaped inputs so the gate works
    unchanged whether the caller passes a SQLModel row, a mock, or a
    plain dict that already collated the provenance columns.
    """
    if isinstance(entry_row, dict):
        return entry_row.get(key)
    return getattr(entry_row, key, None)


def apply_gate(
    hit: dict[str, Any],
    entry_row: Any | None = None,
) -> dict[str, Any]:
    """Return a gated copy of ``hit`` with sanitize/classify/provenance stamps.

    The returned dict is a shallow copy of ``hit`` with the
    :data:`GATE_FIELD_KEYS` added and a nested ``provenance`` mapping
    built from :data:`PROVENANCE_KEYS`. ``hit`` itself is not mutated so
    callers holding a reference to the pre-gate hit see the original
    shape.

    ``entry_row`` is an optional companion payload (SQLModel row / dict)
    used to hydrate provenance keys the hit does not already carry --
    exactly the shape :meth:`KnowledgeService.retrieve` returns, where
    ``namespace`` is on the hit but the provenance columns still live
    on the entry row.
    """
    gated: dict[str, Any] = dict(hit)
    raw_content = str(hit.get("content") or "")
    sanitized = sanitize_input(raw_content)
    gated["sanitized_content"] = sanitized
    gated["content_sanitized"] = sanitized != raw_content

    result = classify_messages([{"content": raw_content}])
    gated["classification"] = result.level.name.lower()
    if result.level >= ClassificationLevel.RESTRICTED:
        gated["classification_matches"] = list(result.pattern_types)
    else:
        gated["classification_matches"] = []

    gated["provenance"] = _extract_provenance(hit, entry_row)
    return gated


def apply_gate_many(
    hits: list[dict[str, Any]],
    entry_rows: dict[int, Any] | None = None,
) -> list[dict[str, Any]]:
    """Apply :func:`apply_gate` to every hit, using ``entry_rows`` for provenance.

    ``entry_rows`` is an ``id -> row`` map; the gate looks up each hit's
    provenance row by ``hit["id"]``. Missing ids fall back to
    ``entry_row=None`` (the gate stamps ``None`` provenance rather than
    raising) so a stale row that was deleted between the retrieve and
    the gate does not blow up the whole call.
    """
    rows = entry_rows or {}
    return [apply_gate(hit, rows.get(int(hit.get("id") or -1))) for hit in hits]
