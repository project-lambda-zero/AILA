"""Tests for Phase 53 Plan 02 schema definitions.

Tests cover ErrorResponse extension and PaginatedResponse generic base.
Uses TDD: tests written before implementation.
"""
from __future__ import annotations

import math

import pytest
from pydantic import ValidationError


class TestErrorResponseExtension:
    """ErrorResponse extended with optional code and errors fields."""

    def test_backward_compatible_detail_only(self):
        """ErrorResponse(detail=...) still works without new fields."""
        from aila.api.schemas.errors import ErrorResponse

        e = ErrorResponse(detail="something went wrong")
        assert e.detail == "something went wrong"
        assert e.code is None
        assert e.errors is None

    def test_with_machine_readable_code(self):
        """ErrorResponse accepts optional machine-readable code."""
        from aila.api.schemas.errors import ErrorResponse

        e = ErrorResponse(detail="not found", code="KEY_NOT_FOUND")
        assert e.code == "KEY_NOT_FOUND"

    def test_with_validation_errors_list(self):
        """ErrorResponse accepts optional per-field errors list."""
        from aila.api.schemas.errors import ErrorResponse

        e = ErrorResponse(
            detail="bad input",
            errors=[{"field": "name", "msg": "required"}],
        )
        assert e.errors is not None
        assert e.errors[0]["field"] == "name"
        assert e.errors[0]["msg"] == "required"

    def test_with_all_fields(self):
        """ErrorResponse accepts all three fields simultaneously."""
        from aila.api.schemas.errors import ErrorResponse

        e = ErrorResponse(
            detail="validation failed",
            code="VALIDATION_ERROR",
            errors=[{"field": "id", "msg": "must be positive"}],
        )
        assert e.detail == "validation failed"
        assert e.code == "VALIDATION_ERROR"
        assert len(e.errors) == 1

    def test_code_must_be_string_or_none(self):
        """code field rejects non-string values."""
        from aila.api.schemas.errors import ErrorResponse

        with pytest.raises(ValidationError):
            ErrorResponse(detail="x", code=123)  # type: ignore[arg-type]

    def test_errors_must_be_list_of_dicts(self):
        """errors field rejects non-list values."""
        from aila.api.schemas.errors import ErrorResponse

        with pytest.raises(ValidationError):
            ErrorResponse(detail="x", errors="not a list")  # type: ignore[arg-type]

    def test_extra_fields_forbidden(self):
        """APIModel extra='forbid' still applies to ErrorResponse."""
        from aila.api.schemas.errors import ErrorResponse

        with pytest.raises(ValidationError):
            ErrorResponse(detail="x", unknown_field="y")  # type: ignore[call-arg]


class TestPaginatedResponseGeneric:
    """PaginatedResponse[T] generic base class."""

    def test_basic_paginated_response(self):
        """PaginatedResponse wraps items with pagination metadata."""
        from aila.api.schemas.common import PaginatedResponse

        p = PaginatedResponse[str](total=100, page=1, page_size=50, pages=2, items=["a", "b"])
        assert p.total == 100
        assert p.page == 1
        assert p.page_size == 50
        assert p.pages == 2
        assert p.items == ["a", "b"]

    def test_pages_auto_computed_when_zero(self):
        """pages is auto-computed from total/page_size when passed as 0."""
        from aila.api.schemas.common import PaginatedResponse

        p = PaginatedResponse[str](total=55, page=1, page_size=50, pages=0, items=["a"])
        assert p.pages == 2  # ceil(55/50)

    def test_pages_auto_computed_exact_division(self):
        """ceil(100/50) = 2 — exact division gives correct pages."""
        from aila.api.schemas.common import PaginatedResponse

        p = PaginatedResponse[str](total=100, page=1, page_size=50, pages=0, items=[])
        assert p.pages == 2

    def test_pages_auto_computed_single_item(self):
        """ceil(1/50) = 1 — single item has 1 page."""
        from aila.api.schemas.common import PaginatedResponse

        p = PaginatedResponse[str](total=1, page=1, page_size=50, pages=0, items=["x"])
        assert p.pages == 1

    def test_pages_zero_when_total_zero(self):
        """pages stays 0 when total=0 (no items)."""
        from aila.api.schemas.common import PaginatedResponse

        p = PaginatedResponse[str](total=0, page=1, page_size=50, pages=0, items=[])
        assert p.pages == 0

    def test_page_must_be_ge1(self):
        """page=0 is rejected (1-indexed)."""
        from aila.api.schemas.common import PaginatedResponse

        with pytest.raises(ValidationError):
            PaginatedResponse[str](total=10, page=0, page_size=50, pages=0, items=[])

    def test_page_size_must_be_le250(self):
        """page_size > 250 is rejected."""
        from aila.api.schemas.common import PaginatedResponse

        with pytest.raises(ValidationError):
            PaginatedResponse[str](total=10, page=1, page_size=251, pages=0, items=[])

    def test_total_must_be_ge0(self):
        """total < 0 is rejected."""
        from aila.api.schemas.common import PaginatedResponse

        with pytest.raises(ValidationError):
            PaginatedResponse[str](total=-1, page=1, page_size=50, pages=0, items=[])

    def test_items_can_be_complex_types(self):
        """items can hold any type, not just strings."""
        from aila.api.schemas.common import PaginatedResponse

        items = [{"id": 1, "name": "x"}, {"id": 2, "name": "y"}]
        p = PaginatedResponse[dict](total=2, page=1, page_size=50, pages=0, items=items)
        assert len(p.items) == 2
        assert p.pages == 1  # ceil(2/50) = 1

    def test_pages_computed_correctly_for_various_totals(self):
        """Verify ceil computation for a range of totals."""
        from aila.api.schemas.common import PaginatedResponse

        cases = [
            (1, 50, 1),
            (50, 50, 1),
            (51, 50, 2),
            (99, 50, 2),
            (100, 50, 2),
            (101, 50, 3),
        ]
        for total, page_size, expected_pages in cases:
            p = PaginatedResponse[str](total=total, page=1, page_size=page_size, pages=0, items=[])
            assert p.pages == expected_pages, f"total={total} page_size={page_size}: expected {expected_pages}, got {p.pages}"
