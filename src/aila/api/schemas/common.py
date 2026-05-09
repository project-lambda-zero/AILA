"""Shared Pydantic base types used across all API response schemas."""
from __future__ import annotations

import math
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = ["APIModel", "PaginatedResponse"]

T = TypeVar("T")


class APIModel(BaseModel):
    """Base class for all AILA API request and response models.

    Forbids extra fields on input to prevent silent data loss.
    All API models inherit from this class.
    """

    model_config = ConfigDict(extra="forbid")


class PaginatedResponse(APIModel, Generic[T]):
    """Generic paginated response wrapper.

    Wraps any list of items with pagination metadata.
    pages is computed automatically from total and page_size when pages=0.

    Fields:
        total: Total number of matching records (across all pages).
        page: Current 1-indexed page number.
        page_size: Number of items per page (max 250).
        pages: Total number of pages (ceil(total / page_size)).
        items: Items on the current page.
    """

    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=250)
    pages: int = Field(ge=0)
    items: list[T]

    @model_validator(mode="after")
    def _compute_pages(self) -> PaginatedResponse[T]:
        """Recompute pages from total and page_size if pages=0 and total > 0."""
        if self.pages == 0 and self.total > 0:
            object.__setattr__(self, "pages", math.ceil(self.total / self.page_size))
        return self
