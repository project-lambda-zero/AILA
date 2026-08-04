"""RFC-12 Phase 5: classify/sanitize gate on ingest.

Locks the pure ``_ingest_gate_metadata`` helper that every ``store`` call runs
before persisting: it tags the classification tier and an injection flag while
leaving the stored content untouched (the operator's no-trim rule). The
store -> DB integration is exercised live via the backfill CLI; here we lock
the tagging contract without a DB.
"""
from __future__ import annotations

from aila.platform.services.knowledge import _ingest_gate_metadata


def test_public_content_tagged_public_without_matches() -> None:
    meta = _ingest_gate_metadata("No container escape vulnerability found in the sandbox.")
    assert meta["ingest_classification"] == "public"
    assert "ingest_classification_matches" not in meta
    assert meta["ingest_content_flagged"] is False


def test_restricted_content_tagged_with_matches() -> None:
    # A credential pattern trips the RESTRICTED tier (classify.py).
    meta = _ingest_gate_metadata("service account password=hunter2 stored in the config")
    assert meta["ingest_classification"] == "restricted"
    assert meta.get("ingest_classification_matches")  # non-empty list


def test_gate_is_metadata_only_and_never_raises() -> None:
    # Empty / degenerate input must return a dict, never raise, and never
    # carry the content itself (raw content stays in the row, not the tag).
    meta = _ingest_gate_metadata("")
    assert isinstance(meta, dict)
    assert "content" not in meta
    assert meta.get("ingest_classification") in {"public", "internal", "restricted"}
