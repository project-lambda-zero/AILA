"""Target table scaffold demonstrating the RFC-01 base-subclass pattern.

Shared columns live on ``aila.platform.contracts.target_base``; the
concretes below set ``__tablename__`` and the FK tablename ClassVars
their base docstrings require (``__workspace_tablename__`` on both,
plus ``__target_tablename__`` on the tag-index).

Module-specific residue is added by the concrete subclass -- see the
commented ``parent_target_id`` / ``sha256`` example below, mirrored on
the malware target for unpack lineage and sample identity. Kept
commented so this scaffold stays minimal.
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.contracts.target_base import TargetRecordBase, TargetTagIndexBase

__all__ = ["TemplateTargetRecord", "TemplateTargetTagIndexRecord"]


class TemplateTargetRecord(TargetRecordBase, table=True):
    """Scaffold: a persistent target identity owned by a workspace."""

    __tablename__ = "template_targets"
    __workspace_tablename__: ClassVar[str] = "template_workspaces"

    # A module that needs extra columns declares them after the inherited
    # base columns. The malware target, as a live example, keeps two extra
    # columns -- an unpack-lineage pointer (nullable, indexed, and a
    # self-referential foreign key back to its own targets table) plus a
    # sample-identity hash (nullable, indexed, 64-char hex). See the
    # malware module db_models target for the concrete shape.


class TemplateTargetTagIndexRecord(TargetTagIndexBase, table=True):
    """Scaffold: denormalized tag-to-target index for fast filter queries."""

    __tablename__ = "template_target_tag_index"
    __target_tablename__: ClassVar[str] = "template_targets"
    __workspace_tablename__: ClassVar[str] = "template_workspaces"
