"""Typed configuration schema for the template module.

Every module publishes its operator-tunable knobs through a Pydantic
model registered with the shared :class:`aila.storage.registry.ConfigRegistry`
under the module's own namespace. Subclassing
:class:`aila.platform.config_base.ModuleConfigBase` bakes in
``extra='forbid'`` so an undeclared or misspelled key fails closed at
construction instead of silently passing through -- the drift class of
failure RFC-04 closed for ``vulnerability`` and codified as honesty
audit rule 37 (``module_config_schema_base``).

Copiers replace the example fields below with the real knobs the new
module needs (rate limits, cache TTLs, external URLs, feature flags).
The registration wiring in :mod:`module.py` picks the schema up without
further platform edits.
"""
from __future__ import annotations

from pydantic import Field

from aila.platform.config_base import ModuleConfigBase

__all__ = ["TemplateConfigSchema"]


class TemplateConfigSchema(ModuleConfigBase):
    """Example config schema demonstrating the ModuleConfigBase pattern.

    Each annotated attribute becomes one typed key in the module's config
    namespace. ``extra='forbid'`` is inherited from
    :class:`ModuleConfigBase` so an operator ``PUT /config`` with an
    undeclared key raises at construction rather than silently succeeding.

    Replace both example fields when copying this module.
    """

    example_timeout_seconds: float = Field(
        default=30.0,
        ge=0.0,
        description="Placeholder timeout knob; replace with a real setting.",
    )
    example_max_retries: int = Field(
        default=3,
        ge=0,
        description="Placeholder retry ceiling; replace with a real setting.",
    )
