"""VR binding of the platform investigation cap-exceeded reaper.

Binds the platform generic reaper functions to the VR record models,
ARQ track name, and a namespaced :class:`ConfigRegistry`-backed
``cap_resolver`` via module-level ``functools.partial``. Callers use
the public names unchanged (``evaluate_cap_for_investigation`` +
``sweep_cap_exceeded_investigations``); the emit path and the ARQ
cron both address these bound partials directly.

Adopts the platform generic to close a live bug: the prior VR reaper
read caps from raw ``os.environ`` at every call and ignored operator
overrides written via ``PUT /config``. This binding routes through
``ConfigRegistry`` in the ``vr`` namespace so a DB override -- or an
``AILA_VR_INVESTIGATION_TURN_CAP`` env var -- lands on the next tick
without a worker restart. The prior ``VR_INVESTIGATION_TURN_CAP`` /
``VR_INVESTIGATION_MESSAGE_CAP`` / ``VR_INVESTIGATION_WALL_CLOCK_HOURS``
/ ``VR_WALL_CLOCK_IDLE_GRACE_S`` env-var names are no longer read;
the operator-visible surface is the standard ``AILA_VR_<KEY>`` form.
"""
from __future__ import annotations

from functools import partial

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationRecord,
)
from aila.platform.services.investigation_reaper import (
    CapConfig,
)
from aila.platform.services.investigation_reaper import (
    evaluate_cap_for_investigation as _platform_evaluate,
)
from aila.platform.services.investigation_reaper import (
    sweep_cap_exceeded_investigations as _platform_sweep,
)
from aila.storage.registry import ConfigRegistry

__all__ = [
    "evaluate_cap_for_investigation",
    "sweep_cap_exceeded_investigations",
]

_NAMESPACE = "vr"

# Bootstrapping safety fallback: if the VR config schema has not yet
# been registered with the running :class:`ConfigRegistry` instance
# (e.g. a reaper tick lands during a partial worker cold-start),
# ``ConfigRegistry.get`` returns ``None`` for a schema-driven key.
# Falling back to the module defaults keeps the reaper honest until
# the schema is wired; once wired, the schema defaults + operator DB
# overrides take over.
_CAP_DEFAULTS: dict[str, int | float] = {
    "investigation_turn_cap": 300,
    "investigation_message_cap": 1000,
    "investigation_wall_clock_hours": 6.0,
    "wall_clock_idle_grace_s": 900.0,
}

_registry: ConfigRegistry | None = None


def _get_registry() -> ConfigRegistry:
    """Lazy singleton -- one registry instance per worker process.

    Mirrors ``aila.modules.malware.services.config_helpers._get_registry``
    so the reaper pays the registry construction cost only on first
    cap read, not on module import.
    """
    global _registry
    if _registry is None:
        _registry = ConfigRegistry()
    return _registry


async def _resolve_caps() -> CapConfig:
    """Async cap resolver bound into the platform reaper via partial.

    Reads each of the four caps via ``ConfigRegistry`` in the ``vr``
    namespace. The registry's layered lookup is
    ``AILA_VR_<KEY>`` env -> DB -> schema default; the ``None``
    fallback below covers the pre-schema-registration bootstrap
    window.
    """
    reg = _get_registry()
    raw_turn = await reg.get(_NAMESPACE, "investigation_turn_cap")
    raw_msg = await reg.get(_NAMESPACE, "investigation_message_cap")
    raw_wall = await reg.get(_NAMESPACE, "investigation_wall_clock_hours")
    raw_idle = await reg.get(_NAMESPACE, "wall_clock_idle_grace_s")
    return CapConfig(
        turn_cap=int(
            raw_turn if raw_turn is not None else _CAP_DEFAULTS["investigation_turn_cap"],
        ),
        message_cap=int(
            raw_msg if raw_msg is not None else _CAP_DEFAULTS["investigation_message_cap"],
        ),
        wallclock_hours=float(
            raw_wall if raw_wall is not None else _CAP_DEFAULTS["investigation_wall_clock_hours"],
        ),
        idle_grace_s=float(
            raw_idle if raw_idle is not None else _CAP_DEFAULTS["wall_clock_idle_grace_s"],
        ),
    )


evaluate_cap_for_investigation = partial(
    _platform_evaluate,
    investigation_model=VRInvestigationRecord,
    branch_model=VRInvestigationBranchRecord,
    message_model=VRInvestigationMessageRecord,
    track="vr",
    cap_resolver=_resolve_caps,
)

sweep_cap_exceeded_investigations = partial(
    _platform_sweep,
    investigation_model=VRInvestigationRecord,
    branch_model=VRInvestigationBranchRecord,
    message_model=VRInvestigationMessageRecord,
    track="vr",
    cap_resolver=_resolve_caps,
)
