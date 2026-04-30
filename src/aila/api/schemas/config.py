"""Config API request/response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from .common import APIModel, PaginatedResponse

__all__ = ["ConfigEntryResponse", "ConfigListResponse", "ConfigUpdateRequest"]


class ConfigEntryResponse(APIModel):
    """A single module configuration entry.

    Mirrors ConfigEntryRecord. value is always returned as a string;
    clients use value_type to cast it (str, int, float, bool).
    """

    namespace: str = Field(min_length=1, description="Module namespace (e.g. 'vulnerability')")
    key: str = Field(min_length=1, description="Config key within the namespace")
    value: str = Field(description="Current value as a string")
    value_type: str = Field(default="str", description="Python type name for casting (str/int/float/bool)")
    updated_at: datetime | None = Field(default=None, description="When this value was last updated")


ConfigListResponse = PaginatedResponse[ConfigEntryResponse]
ConfigListResponse.__doc__ = "Paginated list of configuration entries."


class ConfigUpdateRequest(APIModel):
    """Request body for PUT /config/{namespace}/{key}."""

    value: str = Field(description="New value for this config key")
    value_type: Literal["str", "int", "float", "bool"] = Field(
        default="str", description="Python type name (str/int/float/bool)"
    )
