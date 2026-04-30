"""Public contract models for the hello_world module."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["HelloOptions", "HelloPayload"]


class HelloPayload(BaseModel):
    """Input payload for a hello_world module action request.

    Validated from ModuleRequest.payload by HelloWorldRuntime.handle().
    """

    model_config = ConfigDict(extra="forbid")

    target_names: list[str] = Field(default_factory=list)


class HelloOptions(BaseModel):
    """Runtime options for a hello_world module action request."""

    model_config = ConfigDict(extra="forbid")

    force_refresh: bool = False
