from __future__ import annotations

from collections.abc import Generator
from itertools import islice
from typing import Any

from ..contracts._common import utc_now as utc_now


class Tool:
    """Base class for platform tools.

    Provides the name/description/forward interface that ToolProtocol
    expects. Platform and module tools inherit from this.
    """

    name: str = ""
    description: str = ""

    def forward(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the tool's action and return the result."""
        raise NotImplementedError

__all__ = ["Tool", "chunked", "require_text", "optional_text", "normalize_int_arg", "normalize_offset", "normalize_limit"]


def chunked(items: list[Any], size: int) -> Generator[list[Any], None, None]:
    """Yield successive fixed-size chunks from items.

    Used to batch large lists into smaller groups for bulk DB operations or
    API calls that have per-request size limits.
    """
    iterator = iter(items)
    while batch := list(islice(iterator, size)):
        yield batch


def require_text(value: object, *, tool_name: str, field_name: str) -> str:
    """Validate that value is a non-empty string and return its stripped form.

    All platform tools use this guard at their forward() entry points to produce
    consistent, tool-identified error messages before any DB or network calls.
    Raises ValueError if value is not a string or is blank after stripping.
    """
    if not isinstance(value, str):
        raise ValueError(f"{tool_name} {field_name} must be a string.")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{tool_name} requires {field_name}.")
    return normalized


def optional_text(value: object | None, *, tool_name: str, field_name: str) -> str | None:
    """Validate and strip an optional string argument.

    Returns None for None input or for strings that are blank after stripping.
    Raises ValueError if value is present but is not a string type.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{tool_name} {field_name} must be a string.")
    normalized = value.strip()
    return normalized or None


def normalize_int_arg(value: str | int | float | None, *, name: str) -> int:
    """Reject booleans (bool is a subclass of int) and coerce to int."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer.")
    if value is None:
        raise ValueError(f"{name} must not be None.")
    return int(value)


def normalize_offset(value: int | None) -> int:
    """Coerce an optional offset to a non-negative integer, defaulting to 0."""
    if value is None:
        return 0
    normalized = normalize_int_arg(value, name="Offset")
    if normalized < 0:
        raise ValueError("Offset must be >= 0.")
    return normalized


def normalize_limit(value: int | None, *, default: int, maximum: int) -> int:
    """Coerce an optional limit to a validated integer within [1, maximum].

    Returns default when value is None. Raises ValueError if value is below 1
    or above maximum, keeping query result sizes within safe bounds.
    """
    if value is None:
        return default
    normalized = normalize_int_arg(value, name="Limit")
    if normalized < 1:
        raise ValueError("Limit must be >= 1.")
    if normalized > maximum:
        raise ValueError(f"Limit must be <= {maximum}.")
    return normalized
