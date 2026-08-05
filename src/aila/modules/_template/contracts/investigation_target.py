"""Multi-target investigation contracts (scaffold).

Mirrors :mod:`aila.modules.vr.contracts.investigation_target`. Backs the
template :class:`MultiTargetService` binding: the platform generic needs
a role enum and a summary contract to project attachment rows through.

A copier prunes the role enum to the values its module actually supports
(e.g. malware ships only PRIMARY / COMPARISON / PARENT_LIBRARY) and adds
module-specific attach / detach payload models if needed.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "InvestigationTargetRole",
    "TemplateInvestigationTargetAttach",
    "TemplateInvestigationTargetDetach",
    "TemplateInvestigationTargetSummary",
]


class InvestigationTargetRole(StrEnum):
    """Why a secondary target is attached to an investigation."""

    PRIMARY = "primary"
    COMPARISON = "comparison"
    PARALLEL_CODEBASE = "parallel_codebase"
    PARENT_LIBRARY = "parent_library"
    DERIVED_FORK = "derived_fork"


class TemplateInvestigationTargetAttach(BaseModel):
    """Operator-attaches a secondary target to an existing investigation."""

    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(min_length=1, max_length=64)
    role: InvestigationTargetRole = InvestigationTargetRole.COMPARISON
    rationale: str = Field(
        default="",
        max_length=2048,
        description="Why this target is relevant to the investigation.",
    )


class TemplateInvestigationTargetDetach(BaseModel):
    """Detach a previously-attached secondary target."""

    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(min_length=1, max_length=64)


class TemplateInvestigationTargetSummary(BaseModel):
    """Read projection of one (investigation, target, role) tuple."""

    model_config = ConfigDict(extra="forbid")

    id: str
    investigation_id: str
    target_id: str
    role: InvestigationTargetRole
    rationale: str = ""
    attached_at: datetime | None = None
