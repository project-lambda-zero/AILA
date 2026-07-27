"""Config API request/response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from .common import APIModel, PaginatedResponse

__all__ = ["ConfigEntryResponse", "ConfigListResponse", "ConfigUpdateRequest"]


class ConfigEntryResponse(APIModel):
    """A single module configuration entry.

    Mirrors ConfigEntryRecord. ``value`` is the stored DB row (a fallback);
    ``effective_value`` is what the runtime resolves to right now given the
    live env var override chain. Clients use ``value_type`` to cast either.
    """

    namespace: str = Field(min_length=1, description="Module namespace (e.g. 'vulnerability')")
    key: str = Field(min_length=1, description="Config key within the namespace")
    value: str = Field(description="Stored DB row value (fallback used only when the env var is unset)")
    value_type: str = Field(default="str", description="Python type name for casting (str/int/float/bool)")
    updated_at: datetime | None = Field(default=None, description="When this value was last updated")
    env_key: str = Field(
        default="",
        description="Env var that overrides this key: AILA_{NAMESPACE}_{KEY} uppercased",
    )
    env_value: str | None = Field(
        default=None,
        description="Raw env var value if set, else null (redacted for secret keys to non-admin)",
    )
    default_value: str | None = Field(
        default=None,
        description="Schema default as a string, or null when the key is unknown to the namespace schema",
    )
    effective_value: str = Field(
        default="",
        description="Value the system resolves to right now: env > db > default",
    )
    effective_source: Literal["env", "db", "default"] = Field(
        default="db",
        description="Which layer supplied effective_value (env, stored DB row, or schema default)",
    )
    overridden_by_env: bool = Field(
        default=False,
        description="True iff env_value is not null (the stored DB value is not live)",
    )


ConfigListResponse = PaginatedResponse[ConfigEntryResponse]
ConfigListResponse.__doc__ = "Paginated list of configuration entries."


class ConfigUpdateRequest(APIModel):
    """Request body for PUT /config/{namespace}/{key}."""

    value: str = Field(description="New value for this config key")
    value_type: Literal["str", "int", "float", "bool"] = Field(
        default="str", description="Python type name (str/int/float/bool)"
    )
