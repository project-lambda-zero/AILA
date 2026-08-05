"""Template binding of the platform investigation cap-exceeded reaper.

Mirrors :mod:`aila.modules.vr.services.investigation_reaper`. Binds the
platform generic reaper functions to the template record models, ARQ
track name, and a namespaced :class:`ConfigRegistry`-backed
``cap_resolver`` via module-level ``functools.partial``. Callers use
the public names unchanged (``evaluate_cap_for_investigation`` +
``sweep_cap_exceeded_investigations``); the emit path and the ARQ cron
both address these bound partials directly.

Cap values are read from the ``template`` namespace at every tick, so
operator overrides written via ``PUT /config`` land on the next tick
without a worker restart. The ``_CAP_DEFAULTS`` map is a placeholder
bootstrapping fallback used only during the pre-schema-registration
window; once :class:`TemplateConfigSchema` is registered, the
schema defaults + operator DB overrides take over.
"""
from __future__ import annotations

from functools import partial

from aila.modules._template.db_models import (
    TemplateInvestigationBranchRecord,
    TemplateInvestigationMessageRecord,
    TemplateInvestigationRecord,
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

_NAMESPACE = "template"

# Placeholder bootstrapping fallback: values are only consulted when
# ``ConfigRegistry.get`` returns ``None`` for a schema-driven key (i.e.
# during the partial-cold-start window before the template schema is
# registered). A copier tunes these once the module has real cap
# characteristics, and can drop the fallback entirely once schema
# registration is guaranteed to precede reaper ticks.
_CAP_DEFAULTS: dict[str, int | float] = {
    "investigation_turn_cap": 1000,
    "investigation_message_cap": 5000,
    "investigation_wall_clock_hours": 48.0,
    "wall_clock_idle_grace_s": 900.0,
}

_registry: ConfigRegistry | None = None


def _get_registry() -> ConfigRegistry:
    """Lazy singleton -- one registry instance per worker process."""
    global _registry
    if _registry is None:
        _registry = ConfigRegistry()
    return _registry


async def _resolve_caps() -> CapConfig:
    """Async cap resolver bound into the platform reaper via partial.

    Reads each of the four caps via :class:`ConfigRegistry` in the
    ``template`` namespace. The registry's layered lookup is
    ``AILA_TEMPLATE_<KEY>`` env -> DB -> schema default; the ``None``
    fallback below covers the pre-schema-registration bootstrap window.
    """
    reg = _get_registry()
    raw_turn = await reg.get(_NAMESPACE, "investigation_turn_cap")
    raw_msg = await reg.get(_NAMESPACE, "investigation_message_cap")
    raw_wall = await reg.get(_NAMESPACE, "investigation_wall_clock_hours")
    raw_idle = await reg.get(_NAMESPACE, "wall_clock_idle_grace_s")
    return CapConfig(
        turn_cap=int(
            raw_turn if raw_turn is not None
            else _CAP_DEFAULTS["investigation_turn_cap"],
        ),
        message_cap=int(
            raw_msg if raw_msg is not None
            else _CAP_DEFAULTS["investigation_message_cap"],
        ),
        wallclock_hours=float(
            raw_wall if raw_wall is not None
            else _CAP_DEFAULTS["investigation_wall_clock_hours"],
        ),
        idle_grace_s=float(
            raw_idle if raw_idle is not None
            else _CAP_DEFAULTS["wall_clock_idle_grace_s"],
        ),
    )


evaluate_cap_for_investigation = partial(
    _platform_evaluate,
    investigation_model=TemplateInvestigationRecord,
    branch_model=TemplateInvestigationBranchRecord,
    message_model=TemplateInvestigationMessageRecord,
    track="template",
    cap_resolver=_resolve_caps,
)

sweep_cap_exceeded_investigations = partial(
    _platform_sweep,
    investigation_model=TemplateInvestigationRecord,
    branch_model=TemplateInvestigationBranchRecord,
    message_model=TemplateInvestigationMessageRecord,
    track="template",
    cap_resolver=_resolve_caps,
)
