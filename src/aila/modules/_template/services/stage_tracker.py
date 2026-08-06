"""Template binding of the platform per-target stage tracker service.

Mirrors :mod:`aila.modules.vr.services.stage_tracker`. Binds the platform
generic :class:`StageTracker` and its module-level helpers to
:class:`TemplateTargetRecord`. The model-coupled functions are wrapped as
module-level ``functools.partial`` so the registered periodic-sweep
callable (``reap_stuck_stages``) is a stable object across re-imports --
the sweep registry keys re-registration on callable identity, and an
inline partial at the registration site would break the re-registration
no-op.
"""
from __future__ import annotations

from functools import partial
from typing import ClassVar

from aila.modules._template.db_models import TemplateTargetRecord
from aila.platform.services.stage_tracker import (
    StageAlreadyDoneError,
    StageInFlightError,
    StageTrackerError,
    parse_stages,
)
from aila.platform.services.stage_tracker import (
    StageTracker as _PlatformStageTracker,
)
from aila.platform.services.stage_tracker import (
    load_target_stages as _platform_load_target_stages,
)
from aila.platform.services.stage_tracker import (
    reap_stuck_stages as _platform_reap_stuck_stages,
)
from aila.platform.services.stage_tracker import (
    save_target_stages as _platform_save_target_stages,
)

__all__ = [
    "StageAlreadyDoneError",
    "StageInFlightError",
    "StageTracker",
    "StageTrackerError",
    "load_target_stages",
    "parse_stages",
    "reap_stuck_stages",
    "save_target_stages",
]


class StageTracker(_PlatformStageTracker):
    """Template binding of the platform per-target stage tracker."""

    _target_model: ClassVar[type] = TemplateTargetRecord


load_target_stages = partial(
    _platform_load_target_stages, target_model=TemplateTargetRecord,
)
save_target_stages = partial(
    _platform_save_target_stages, target_model=TemplateTargetRecord,
)
reap_stuck_stages = partial(
    _platform_reap_stuck_stages, target_model=TemplateTargetRecord,
)
