"""Forensics pattern catalog table (RFC-12 Phase 4).

A pattern is a reusable forensics technique extracted from a completed
investigation (or entered manually). The structured fields live here; the
body + embedding live in the mirrored ``KnowledgeEntryRecord`` under
namespace ``forensics.pattern.<scope>.<id>``. ``PatternStore`` writes both
rows in one transaction so they stay consistent and joins back via
``knowledge_entry_id``.

The shared columns live on the platform ``PatternRecordBase`` (RFC-01);
this module only sets the concrete table + foreign-key target names.
Forensics has no workspace table -- the project is the forensics
workspace, so ``__workspace_tablename__`` points at ``forensics_projects``
and callers pass ``investigation.project_id`` as the ``workspace_id``.
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.contracts.pattern_base import PatternRecordBase

__all__ = ["ForensicsPatternRecord"]


class ForensicsPatternRecord(PatternRecordBase, table=True):
    """Catalog entry for one reusable forensics pattern."""

    __tablename__ = "forensics_patterns"
    __workspace_tablename__: ClassVar[str] = "forensics_projects"
    __investigation_tablename__: ClassVar[str] = "forensics_investigations"
