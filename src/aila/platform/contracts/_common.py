from __future__ import annotations

from datetime import UTC, datetime
from typing import TypeAlias

JsonScalar: TypeAlias = str | int | float | bool | None
"""A JSON primitive value: string, number, boolean, or null."""

JsonValue: TypeAlias = object
"""Any JSON-compatible value including nested objects and arrays."""

JsonObject: TypeAlias = dict[str, JsonValue]
"""A JSON object -- the canonical dict type for cross-boundary payloads in AILA."""

ActionId: TypeAlias = str
"""Dot-separated module.action identifier (e.g. 'vulnerability.report_summary')."""


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime.

    This is the authoritative timestamp source for all DB writes and audit
    records -- always UTC, always timezone-aware, never reliant on local clock settings.
    """
    return datetime.now(UTC)
