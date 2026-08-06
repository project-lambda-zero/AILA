"""Project table definition for the vulnerability research module.

Per D-53: target identity moved to VRTargetRecord (M3.T-1). VRProjectRecord
now holds only project-scoped fields. The shared columns (id, name,
target_id, analysis_system_id, context_notes, status, created_by,
budget_json, obligations_json, created_at, updated_at) live on the
platform ``ProjectRecordBase`` (RFC-01). This concrete keeps VR-only
residue: ``cve_id``, ``patched_target_id`` (differential analysis FK to
vr_targets), and ``poc_system_id`` (PoC machine assignment).

All target metadata (target_class, target_path, binary_id, mitigations,
ingestion descriptor) lives on VRTargetRecord and is read via the
target_id FK at workflow execution time.

Written by: POST /api/vr/projects (after the api_router creates the
underlying vr_targets row first).
Consumed by: workflow states, agent, advisory builder.
"""
from __future__ import annotations

from typing import ClassVar

from sqlalchemy import Column, ForeignKey
from sqlmodel import Field

from aila.platform.contracts.project_base import ProjectRecordBase

__all__ = ["VRProjectRecord"]


class VRProjectRecord(ProjectRecordBase, table=True):
    """A vulnerability research project bound to one or two targets.

    The project is the unit of workflow execution + budget + obligation
    tracking. Target identity (binary_id, paths, mitigations, language)
    lives on the linked ``VRTargetRecord``.
    """

    __tablename__ = "vr_projects"
    __target_tablename__: ClassVar[str] = "vr_targets"

    cve_id: str | None = Field(default=None, index=True, max_length=32)

    # Optional second target for differential (patched-vs-vulnerable)
    # analysis. FK to the same vr_targets table.
    patched_target_id: str | None = Field(
        default=None,
        sa_column=Column(
            "patched_target_id",
            ForeignKey("vr_targets.id"),
            nullable=True,
            index=True,
        ),
    )

    # Machine assignment for PoC development (separate from the shared
    # ``analysis_system_id`` used for the primary investigation VM).
    poc_system_id: int | None = Field(default=None)
