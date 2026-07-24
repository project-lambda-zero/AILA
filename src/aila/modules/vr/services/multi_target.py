"""VR binding of the platform multi-target investigation service.

Binds the platform MultiTargetServiceBase to the VR record models, role enum,
and summary contract. The platform base owns the attach / list / detach logic.
"""
from __future__ import annotations

from typing import ClassVar

from aila.modules.vr.contracts.investigation_target import (
    InvestigationTargetRole,
    VRInvestigationTargetSummary,
)
from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRInvestigationTargetRecord,
    VRTargetRecord,
)
from aila.platform.services.multi_target import (
    MultiTargetServiceBase,
    MultiTargetServiceError,
)

__all__ = ["MultiTargetService", "MultiTargetServiceError"]


class MultiTargetService(MultiTargetServiceBase):
    """Attach + list + detach secondary targets on a VR investigation."""

    _investigation_model: ClassVar[type] = VRInvestigationRecord
    _target_model: ClassVar[type] = VRTargetRecord
    _attachment_model: ClassVar[type] = VRInvestigationTargetRecord
    _role_enum = InvestigationTargetRole
    _summary_cls: ClassVar[type] = VRInvestigationTargetSummary
