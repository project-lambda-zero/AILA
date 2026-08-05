"""Template binding of the platform multi-target investigation service.

Mirrors :mod:`aila.modules.vr.services.multi_target`. Binds the platform
:class:`MultiTargetServiceBase` to the template record models, role
enum, and summary contract. The platform base owns the attach / list /
detach logic.
"""
from __future__ import annotations

from typing import ClassVar

from aila.modules._template.contracts.investigation_target import (
    InvestigationTargetRole,
    TemplateInvestigationTargetSummary,
)
from aila.modules._template.db_models import (
    TemplateInvestigationRecord,
    TemplateInvestigationTargetRecord,
    TemplateTargetRecord,
)
from aila.platform.services.multi_target import (
    MultiTargetServiceBase,
    MultiTargetServiceError,
)

__all__ = ["MultiTargetService", "MultiTargetServiceError"]


class MultiTargetService(MultiTargetServiceBase):
    """Attach + list + detach secondary targets on a template investigation."""

    _investigation_model: ClassVar[type] = TemplateInvestigationRecord
    _target_model: ClassVar[type] = TemplateTargetRecord
    _attachment_model: ClassVar[type] = TemplateInvestigationTargetRecord
    _role_enum = InvestigationTargetRole
    _summary_cls: ClassVar[type] = TemplateInvestigationTargetSummary
