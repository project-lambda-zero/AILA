"""Project table scaffold demonstrating the RFC-01 base-subclass pattern.

Shared columns live on ``aila.platform.contracts.project_base``; the
concrete below sets ``__tablename__`` + ``__target_tablename__``. The
FK from ``target_id`` to the module's targets table is derived by
``TableDerivedConstraintsMixin`` from ``__target_tablename__``.

Scaffold kept minimal (no residue). A module that needs extra fields
declares them here on the subclass -- see the commented ``cve_id``
example below, mirrored on the vr project for CVE-tagged research
sessions.
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.contracts.project_base import ProjectRecordBase

__all__ = ["TemplateProjectRecord"]


class TemplateProjectRecord(ProjectRecordBase, table=True):
    """Scaffold: a project bound to one target."""

    __tablename__ = "template_projects"
    __target_tablename__: ClassVar[str] = "template_targets"

    # A module that needs extra columns declares them after the inherited
    # base columns. The vulnerability research project, as a live example,
    # keeps a nullable indexed CVE identifier plus links to a patched
    # target and a proof-of-concept system. See the vr module db_models
    # project for the concrete shape.
