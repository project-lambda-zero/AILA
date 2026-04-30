"""Response envelope schemas for the AILA REST API.

All non-streaming endpoints return responses wrapped in DataEnvelope per D-27.
This ensures a consistent response shape: {data, error, meta} across all endpoints.

PaginatedMeta is used by list endpoints that support offset/limit pagination per D-26.
"""
from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel

__all__ = ["DataEnvelope", "PaginatedMeta"]

T = TypeVar("T")


class DataEnvelope(BaseModel, Generic[T]):
    """Generic response wrapper used by all non-streaming endpoints.

    Per D-27: wrapped response envelope {data, error, meta}.
    data holds the payload (None on error).
    error holds the error message string (None on success).
    meta holds arbitrary key-value metadata (pagination info, etc).
    """

    data: T
    error: str | None = None
    meta: dict[str, object] = {}


class PaginatedMeta(BaseModel):
    """Pagination metadata for list endpoints.

    Per D-26: pagination via offset + limit with total count.
    Embedded in DataEnvelope.meta for list responses.
    """

    total: int
    offset: int
    limit: int
