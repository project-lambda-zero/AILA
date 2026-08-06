"""Deep review tests for src/aila/api/schemas/common.py (FILE-14).

Proves APIModel base class enforces extra='forbid', PaginatedResponse computes
pages correctly for all edge cases (0 items, exact multiples, boundary crossings),
validation rejects invalid ranges, and every concrete PaginatedResponse[T] alias
instantiates correctly.

Complementary to test_schemas_p53_02.py -- focuses on deep review criteria.
"""
from __future__ import annotations

from datetime import UTC

import pytest
from pydantic import ValidationError

from aila.api.schemas import common
from aila.api.schemas.common import APIModel, PaginatedResponse


class TestAPIModelBase:
    """APIModel enforces extra='forbid' and subclasses inherit it."""

    def test_extra_forbid_config(self) -> None:
        """APIModel has extra='forbid' in model_config."""
        assert APIModel.model_config.get("extra") == "forbid"

    def test_subclass_inherits_extra_forbid(self) -> None:
        """A subclass of APIModel rejects unknown fields."""

        class Sub(APIModel):
            name: str

        # Valid construction works
        s = Sub(name="ok")
        assert s.name == "ok"

        # Unknown field raises ValidationError
        with pytest.raises(ValidationError):
            Sub(name="ok", bogus="x")  # type: ignore[call-arg]

    def test_subclass_accepts_declared_fields_only(self) -> None:
        """Subclass accepts exactly its declared fields."""

        class Sub(APIModel):
            x: int
            y: str

        s = Sub(x=1, y="a")
        assert s.x == 1
        assert s.y == "a"

    def test_apimodel_exports(self) -> None:
        """common.__all__ exports exactly APIModel and PaginatedResponse."""
        assert common.__all__ == ["APIModel", "PaginatedResponse"]


class TestPaginatedResponseComputation:
    """PaginatedResponse computes pages correctly for all edge cases."""

    def test_zero_items_pages_stays_zero(self) -> None:
        """total=0, pages=0 -> pages stays 0."""
        p = PaginatedResponse[int](total=0, page=1, page_size=10, pages=0, items=[])
        assert p.pages == 0

    def test_exact_multiple(self) -> None:
        """total=10, page_size=10, pages=0 -> pages=1."""
        p = PaginatedResponse[int](total=10, page=1, page_size=10, pages=0, items=[])
        assert p.pages == 1

    def test_one_over_boundary(self) -> None:
        """total=11, page_size=10, pages=0 -> pages=2."""
        p = PaginatedResponse[int](total=11, page=1, page_size=10, pages=0, items=[])
        assert p.pages == 2

    def test_single_item(self) -> None:
        """total=1, page_size=10, pages=0 -> pages=1."""
        p = PaginatedResponse[int](total=1, page=1, page_size=10, pages=0, items=[])
        assert p.pages == 1

    def test_min_page_size(self) -> None:
        """total=1, page_size=1, pages=0 -> pages=1."""
        p = PaginatedResponse[int](total=1, page=1, page_size=1, pages=0, items=[])
        assert p.pages == 1

    def test_max_page_size(self) -> None:
        """total=250, page_size=250, pages=0 -> pages=1."""
        p = PaginatedResponse[int](total=250, page=1, page_size=250, pages=0, items=[])
        assert p.pages == 1

    def test_large_total(self) -> None:
        """total=9999, page_size=50, pages=0 -> pages=200."""
        p = PaginatedResponse[int](total=9999, page=1, page_size=50, pages=0, items=[])
        assert p.pages == 200  # ceil(9999/50) = 200

    def test_explicit_pages_preserved(self) -> None:
        """Non-zero pages is preserved even when total/page_size would compute differently."""
        p = PaginatedResponse[int](total=100, page=1, page_size=10, pages=5, items=[])
        assert p.pages == 5  # validator only fires when pages==0 and total>0

    @pytest.mark.parametrize(
        "total,page_size,expected_pages",
        [
            (0, 1, 0),
            (0, 50, 0),
            (1, 1, 1),
            (1, 50, 1),
            (49, 50, 1),
            (50, 50, 1),
            (51, 50, 2),
            (100, 100, 1),
            (101, 100, 2),
            (249, 250, 1),
            (250, 250, 1),
            (251, 250, 2),
        ],
        ids=[
            "0/1=0",
            "0/50=0",
            "1/1=1",
            "1/50=1",
            "49/50=1",
            "50/50=1",
            "51/50=2",
            "100/100=1",
            "101/100=2",
            "249/250=1",
            "250/250=1",
            "251/250=2",
        ],
    )
    def test_parametrized_edge_cases(
        self, total: int, page_size: int, expected_pages: int
    ) -> None:
        """Exhaustive edge case matrix for pages computation."""
        p = PaginatedResponse[int](
            total=total, page=1, page_size=page_size, pages=0, items=[]
        )
        assert p.pages == expected_pages, (
            f"total={total}, page_size={page_size}: expected {expected_pages}, got {p.pages}"
        )


class TestPaginatedResponseValidation:
    """PaginatedResponse rejects invalid field values."""

    def test_page_size_zero_rejected(self) -> None:
        """page_size=0 raises ValidationError (Field ge=1)."""
        with pytest.raises(ValidationError):
            PaginatedResponse[int](total=10, page=1, page_size=0, pages=0, items=[])

    def test_page_size_251_rejected(self) -> None:
        """page_size=251 raises ValidationError (Field le=250)."""
        with pytest.raises(ValidationError):
            PaginatedResponse[int](total=10, page=1, page_size=251, pages=0, items=[])

    def test_page_zero_rejected(self) -> None:
        """page=0 raises ValidationError (Field ge=1)."""
        with pytest.raises(ValidationError):
            PaginatedResponse[int](total=10, page=0, page_size=10, pages=0, items=[])

    def test_total_negative_rejected(self) -> None:
        """total=-1 raises ValidationError (Field ge=0)."""
        with pytest.raises(ValidationError):
            PaginatedResponse[int](total=-1, page=1, page_size=10, pages=0, items=[])

    def test_pages_negative_rejected(self) -> None:
        """pages=-1 raises ValidationError (Field ge=0)."""
        with pytest.raises(ValidationError):
            PaginatedResponse[int](total=10, page=1, page_size=10, pages=-1, items=[])

    def test_extra_fields_rejected(self) -> None:
        """Extra fields rejected (inherits APIModel extra='forbid')."""
        with pytest.raises(ValidationError):
            PaginatedResponse[int](
                total=10, page=1, page_size=10, pages=0, items=[], bogus="x"  # type: ignore[call-arg]
            )


class TestPaginatedResponseConcreteAliases:
    """Every concrete PaginatedResponse[T] alias instantiates correctly."""

    def test_findings_list_response(self) -> None:
        """FindingsListResponse wraps FindingResponse items."""
        from aila.api.schemas.findings import FindingResponse, FindingsListResponse

        item = FindingResponse(run_id="run-1")
        p = FindingsListResponse(total=1, page=1, page_size=10, pages=0, items=[item])
        assert p.pages == 1
        assert len(p.items) == 1
        assert p.items[0].run_id == "run-1"

    def test_audit_list_response(self) -> None:
        """AuditListResponse wraps AuditEventResponse items."""
        from aila.api.schemas.audit import AuditEventResponse, AuditListResponse

        item = AuditEventResponse(run_id="run-1", stage="auth", action="login")
        p = AuditListResponse(total=1, page=1, page_size=10, pages=0, items=[item])
        assert p.pages == 1
        assert len(p.items) == 1
        assert p.items[0].run_id == "run-1"

    def test_session_messages_response(self) -> None:
        """SessionMessagesResponse wraps SessionMessageResponse items."""
        from datetime import datetime

        from aila.api.schemas.sessions import (
            SessionMessageResponse,
            SessionMessagesResponse,
        )

        item = SessionMessageResponse(
            message_id="msg-1",
            role="user",
            content="hello",
            created_at=datetime.now(tz=UTC),
        )
        p = SessionMessagesResponse(total=1, page=1, page_size=10, pages=0, items=[item])
        assert p.pages == 1
        assert len(p.items) == 1
        assert p.items[0].message_id == "msg-1"

    def test_config_list_response(self) -> None:
        """ConfigListResponse wraps ConfigEntryResponse items."""
        from aila.api.schemas.config import ConfigEntryResponse, ConfigListResponse

        item = ConfigEntryResponse(namespace="vuln", key="max_cves", value="100")
        p = ConfigListResponse(total=1, page=1, page_size=10, pages=0, items=[item])
        assert p.pages == 1
        assert len(p.items) == 1
        assert p.items[0].namespace == "vuln"

    def test_system_list_response(self) -> None:
        """SystemListResponse wraps SystemEnrichedResponse items.

        src/aila/api/schemas/systems.py:75 aliases
        SystemListResponse = PaginatedResponse[SystemEnrichedResponse], so items
        must be SystemEnrichedResponse instances (SystemResponse alone fails
        pydantic model_type validation).
        """
        from aila.api.schemas.systems import SystemEnrichedResponse, SystemListResponse

        item = SystemEnrichedResponse(id=1, name="web-1", host="10.0.0.1", username="root")
        p = SystemListResponse(total=1, page=1, page_size=10, pages=0, items=[item])
        assert p.pages == 1
        assert len(p.items) == 1
        assert p.items[0].name == "web-1"
