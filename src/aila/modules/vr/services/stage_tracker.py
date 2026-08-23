"""VR binding of the platform per-target stage tracker service.

Binds the platform generic :class:`StageTracker` and its module-level helpers
to the VR :class:`VRTargetRecord`. The model-coupled read/write helpers are
wrapped as module-level ``functools.partial`` so their identity is stable
across re-imports; the periodic-sweep registry keys re-registration on
callable identity, and an inline partial at the registration site would break
the re-registration no-op.

``reap_stuck_stages`` is NOT a bare partial because it also overlays
operator-tunable per-stage timeouts sourced from ConfigRegistry (the
``stage_capability_profile_timeout_s`` / ``stage_function_ranking_timeout_s``
keys in ``vr/config_schema.py``). The wrapper resolves the config on every
sweep tick so a ``PUT /config/vr/*`` lands without a worker restart; the
periodic-sweep registry keys re-registration on identity, so the wrapper is
defined once at module scope and re-registered as a no-op on hot import.
"""
from __future__ import annotations

from functools import partial
from typing import ClassVar

from aila.modules.vr.db_models import VRTargetRecord
from aila.platform.config_base import ModuleConfigReader
from aila.platform.contracts.enums import StageName
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
    "resolve_stage_timeout_s",
    "save_target_stages",
]


class StageTracker(_PlatformStageTracker):
    """VR binding of the platform per-target stage tracker."""

    _target_model: ClassVar[type] = VRTargetRecord


load_target_stages = partial(_platform_load_target_stages, target_model=VRTargetRecord)
save_target_stages = partial(_platform_save_target_stages, target_model=VRTargetRecord)


# ConfigRegistry-backed per-stage timeout resolution. Consulted by the
# reaper wrapper on every sweep tick and by the enrichment service call
# sites (profile_builder / function_ranker) before entering StageTracker.
# Keys not listed here fall through to the platform default so the VR
# binding never has to enumerate ingestion / android / ipa stages just
# to keep them at their existing defaults.
_STAGE_TIMEOUT_CONFIG_KEYS: dict[StageName, str] = {
    StageName.CAPABILITY_PROFILE: "stage_capability_profile_timeout_s",
    StageName.FUNCTION_RANKING: "stage_function_ranking_timeout_s",
}

_cfg = ModuleConfigReader("vr")


async def resolve_stage_timeout_s(stage: StageName) -> float | None:
    """Resolve the operator-tunable per-stage timeout for the VR module.

    Returns the config-backed timeout in seconds when ``stage`` has a
    registered override key, else ``None`` so the caller can fall back
    to the platform default in ``_DEFAULT_TIMEOUTS``. Reads via
    ConfigRegistry (env AILA_VR_<KEY> -> DB -> schema default) so a
    ``PUT /config/vr/<key>`` picks up on the next call without a worker
    restart.
    """
    key = _STAGE_TIMEOUT_CONFIG_KEYS.get(stage)
    if key is None:
        return None
    return await _cfg.get_float(key)


async def _resolve_stage_timeouts_overlay() -> dict[StageName, float]:
    """Build the per-sweep overlay dict passed into the platform reaper."""
    overlay: dict[StageName, float] = {}
    for stage in _STAGE_TIMEOUT_CONFIG_KEYS:
        value = await resolve_stage_timeout_s(stage)
        if value is not None:
            overlay[stage] = value
    return overlay


async def reap_stuck_stages() -> int:
    """VR-bound reaper. Resolves the operator-tunable per-stage timeouts
    from ConfigRegistry on every tick and delegates to the platform
    :func:`reap_stuck_stages`.
    """
    overlay = await _resolve_stage_timeouts_overlay()
    return await _platform_reap_stuck_stages(
        target_model=VRTargetRecord,
        stage_timeouts=overlay,
    )
