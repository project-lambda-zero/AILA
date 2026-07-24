"""Pattern catalog table (Knowledge Transfer plan GA-41).

A pattern is a reusable technique extracted from a successful
investigation (or entered manually by the operator). The structured
fields below are queryable; the body + embedding live in a mirrored
``KnowledgeEntryRecord`` under namespace ``vr.pattern.<scope>.<id>``.

PatternStore writes both rows in one transaction so they stay
consistent. Search uses the KnowledgeService (pgvector + FTS) and joins
back to ``vr_patterns`` via the stored ``knowledge_entry_id``.

The shared columns live on the platform ``PatternRecordBase`` (RFC-01);
this module only sets the concrete table + foreign-key target names.
VR carries no pattern residue.
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.contracts.pattern_base import PatternRecordBase

__all__ = ["VRPatternRecord"]


class VRPatternRecord(PatternRecordBase, table=True):
    """Catalog entry for one reusable pattern."""

    __tablename__ = "vr_patterns"
    __workspace_tablename__: ClassVar[str] = "vr_workspaces"
    __investigation_tablename__: ClassVar[str] = "vr_investigations"
