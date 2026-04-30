"""Public contract models for the template module.

For modules with more than 5 contract models, split into domain submodules
(analysis.py, reporting.py, matching.py, scoring.py) and make this file a
barrel re-export only.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["TemplateOptions", "TemplatePayload"]


class TemplatePayload(BaseModel):
    """Input payload for a template module action request.

    Validated from ModuleRequest.payload by TemplateRuntime.handle().
    Add module-specific required fields here.
    """

    model_config = ConfigDict(extra="forbid")

    target_names: list[str] = Field(default_factory=list)


class TemplateOptions(BaseModel):
    """Runtime options for a template module action request.

    Validated from ModuleRequest.options by TemplateRuntime.handle().
    """

    model_config = ConfigDict(extra="forbid")

    force_refresh: bool = False
