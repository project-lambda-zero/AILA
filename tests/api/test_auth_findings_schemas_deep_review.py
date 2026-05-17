"""Deep review tests for schemas/auth.py (FILE-15) and schemas/findings.py (FILE-16).

Proves extra='forbid' inherited by all schemas, required fields enforced,
role validates against allowed values, datetime serialization is ISO 8601,
FindingResponse fields map correctly to LatestFindingRecord columns, bulk
status validation works, and FacetsResponse is extensible.

Complementary to test_common_schemas_deep_review.py -- focuses on auth and findings.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aila.api.schemas import auth as auth_module
from aila.api.schemas import findings as findings_module
from aila.api.schemas.auth import (
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyListItem,
    ApiKeyListResponse,
    ApiKeyRevokeResponse,
    RefreshRequest,
    RefreshResponse,
    TokenRequest,
    TokenResponse,
)
from aila.api.schemas.findings import (
    BULK_ALLOWED_STATUSES,
    BulkStatusUpdateRequest,
    BulkUpdateResponse,
    FacetsResponse,
    FindingResponse,
    FindingsListResponse,
)

# ---------------------------------------------------------------------------
# Auth schemas -- extra="forbid"
# ---------------------------------------------------------------------------


class TestAuthSchemaExtraForbid:
    """All auth schemas reject unknown fields (inherited from APIModel)."""

    @pytest.mark.parametrize(
        "cls,kwargs",
        [
            (ApiKeyCreateRequest, {"role": "reader", "label": "x"}),
            (ApiKeyCreateResponse, {"key_id": "k", "raw_key": "r", "key_prefix": "p", "role": "admin", "label": "", "created_at": datetime.now(tz=UTC)}),
            (ApiKeyListItem, {"key_id": "k", "key_prefix": "p", "role": "reader", "label": "", "created_by": "cli", "created_at": datetime.now(tz=UTC)}),
            (ApiKeyListResponse, {"keys": []}),
            (TokenRequest, {"api_key": "secret"}),
            (TokenResponse, {"access_token": "a", "refresh_token": "r", "expires_in": 3600}),
            (RefreshRequest, {"refresh_token": "rt"}),
            (RefreshResponse, {"access_token": "a", "expires_in": 3600}),
            (ApiKeyRevokeResponse, {"key_id": "k"}),
        ],
        ids=[
            "ApiKeyCreateRequest",
            "ApiKeyCreateResponse",
            "ApiKeyListItem",
            "ApiKeyListResponse",
            "TokenRequest",
            "TokenResponse",
            "RefreshRequest",
            "RefreshResponse",
            "ApiKeyRevokeResponse",
        ],
    )
    def test_rejects_extra_field(self, cls: type, kwargs: dict) -> None:
        """Adding an unknown field raises ValidationError."""
        # Valid construction works
        obj = cls(**kwargs)
        assert obj is not None

        # Extra field rejected
        with pytest.raises(ValidationError, match="extra_forbidden"):
            cls(**kwargs, bogus="unexpected")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Auth schemas -- required fields
# ---------------------------------------------------------------------------


class TestAuthSchemaRequiredFields:
    """Required fields must be provided; defaults are correct."""

    def test_token_request_api_key_required(self) -> None:
        """TokenRequest.api_key is mandatory."""
        with pytest.raises(ValidationError):
            TokenRequest()  # type: ignore[call-arg]

    def test_token_request_api_key_present(self) -> None:
        """TokenRequest accepts api_key."""
        t = TokenRequest(api_key="my-secret-key")
        assert t.api_key == "my-secret-key"

    def test_refresh_request_refresh_token_required(self) -> None:
        """RefreshRequest.refresh_token is mandatory."""
        with pytest.raises(ValidationError):
            RefreshRequest()  # type: ignore[call-arg]

    def test_api_key_create_request_defaults(self) -> None:
        """ApiKeyCreateRequest has sensible defaults for role and label."""
        r = ApiKeyCreateRequest()
        assert r.role == "reader"
        assert r.label == ""

    def test_token_response_defaults(self) -> None:
        """TokenResponse.token_type defaults to 'bearer'."""
        t = TokenResponse(access_token="a", refresh_token="r", expires_in=3600)
        assert t.token_type == "bearer"

    def test_refresh_response_defaults(self) -> None:
        """RefreshResponse.token_type defaults to 'bearer'."""
        r = RefreshResponse(access_token="a", expires_in=3600)
        assert r.token_type == "bearer"

    def test_api_key_revoke_response_defaults(self) -> None:
        """ApiKeyRevokeResponse.revoked defaults to True."""
        r = ApiKeyRevokeResponse(key_id="k")
        assert r.revoked is True

    def test_api_key_list_item_revoked_at_optional(self) -> None:
        """ApiKeyListItem.revoked_at defaults to None."""
        item = ApiKeyListItem(
            key_id="k", key_prefix="p", role="reader",
            label="", created_by="cli", created_at=datetime.now(tz=UTC),
        )
        assert item.revoked_at is None

    def test_api_key_list_item_revoked_at_set(self) -> None:
        """ApiKeyListItem accepts a revoked_at datetime."""
        dt = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
        item = ApiKeyListItem(
            key_id="k", key_prefix="p", role="reader",
            label="", created_by="cli",
            created_at=datetime.now(tz=UTC),
            revoked_at=dt,
        )
        assert item.revoked_at == dt


# ---------------------------------------------------------------------------
# Auth schemas -- role validation
# ---------------------------------------------------------------------------


class TestAuthSchemaRoleValidation:
    """ApiKeyCreateRequest.role validates against allowed roles."""

    @pytest.mark.parametrize("role", ["admin", "operator", "reader"])
    def test_valid_roles_accepted(self, role: str) -> None:
        """Each valid role is accepted."""
        r = ApiKeyCreateRequest(role=role)
        assert r.role == role

    @pytest.mark.parametrize(
        "bad_role",
        ["superadmin", "ADMIN", "Admin", "root", "", "viewer", "write"],
        ids=["superadmin", "ADMIN-case", "Admin-case", "root", "empty", "viewer", "write"],
    )
    def test_invalid_roles_rejected(self, bad_role: str) -> None:
        """Invalid roles raise ValidationError."""
        with pytest.raises(ValidationError):
            ApiKeyCreateRequest(role=bad_role)


# ---------------------------------------------------------------------------
# Auth schemas -- datetime serialization
# ---------------------------------------------------------------------------


class TestAuthSchemaDatetimeSerialization:
    """Datetime fields serialize to ISO 8601 format."""

    def test_api_key_create_response_datetime_iso(self) -> None:
        """ApiKeyCreateResponse.created_at serializes to ISO 8601."""
        dt = datetime(2026, 3, 15, 14, 30, 0, tzinfo=UTC)
        r = ApiKeyCreateResponse(
            key_id="k", raw_key="r", key_prefix="p",
            role="admin", label="", created_at=dt,
        )
        dumped = r.model_dump(mode="json")
        assert dumped["created_at"] == "2026-03-15T14:30:00Z"

    def test_api_key_list_item_datetime_iso(self) -> None:
        """ApiKeyListItem.created_at and revoked_at serialize to ISO 8601."""
        created = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        revoked = datetime(2026, 6, 15, 23, 59, 59, tzinfo=UTC)
        item = ApiKeyListItem(
            key_id="k", key_prefix="p", role="reader",
            label="", created_by="cli",
            created_at=created, revoked_at=revoked,
        )
        dumped = item.model_dump(mode="json")
        assert dumped["created_at"] == "2026-01-01T00:00:00Z"
        assert dumped["revoked_at"] == "2026-06-15T23:59:59Z"

    def test_api_key_list_item_revoked_at_null(self) -> None:
        """ApiKeyListItem.revoked_at serializes to null when not set."""
        item = ApiKeyListItem(
            key_id="k", key_prefix="p", role="reader",
            label="", created_by="cli",
            created_at=datetime.now(tz=UTC),
        )
        dumped = item.model_dump(mode="json")
        assert dumped["revoked_at"] is None


# ---------------------------------------------------------------------------
# Findings schemas -- extra="forbid"
# ---------------------------------------------------------------------------


class TestFindingsSchemaExtraForbid:
    """All findings schemas reject unknown fields."""

    @pytest.mark.parametrize(
        "cls,kwargs",
        [
            (FindingResponse, {"run_id": "run-1"}),
            (FacetsResponse, {}),
            (BulkStatusUpdateRequest, {"finding_ids": [1], "status": "open"}),
            (BulkUpdateResponse, {"count": 5}),
        ],
        ids=["FindingResponse", "FacetsResponse", "BulkStatusUpdateRequest", "BulkUpdateResponse"],
    )
    def test_rejects_extra_field(self, cls: type, kwargs: dict) -> None:
        """Adding an unknown field raises ValidationError."""
        obj = cls(**kwargs)
        assert obj is not None

        with pytest.raises(ValidationError, match="extra_forbidden"):
            cls(**kwargs, bogus="unexpected")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# FindingResponse -- field mapping to LatestFindingRecord
# ---------------------------------------------------------------------------


class TestFindingResponseFieldMapping:
    """FindingResponse fields map correctly to LatestFindingRecord columns."""

    def test_all_fields_present(self) -> None:
        """FindingResponse declares the expected fields for the API surface."""
        field_names = set(FindingResponse.model_fields.keys())
        expected = {"id", "run_id", "cve_id", "package", "version", "host",
                     "severity", "kev", "score", "status", "created_at"}
        assert field_names == expected

    def test_minimal_construction(self) -> None:
        """Only run_id is required; all others have defaults."""
        f = FindingResponse(run_id="run-1")
        assert f.run_id == "run-1"
        assert f.id is None
        assert f.cve_id is None
        assert f.package is None
        assert f.version is None
        assert f.host is None
        assert f.severity is None
        assert f.kev is False
        assert f.score is None
        assert f.status is None
        assert f.created_at is None

    def test_full_construction(self) -> None:
        """All fields can be populated from LatestFindingRecord column values."""
        dt = datetime(2026, 2, 20, 8, 0, 0, tzinfo=UTC)
        f = FindingResponse(
            id=42,
            run_id="run-abc",
            cve_id="CVE-2025-12345",
            package="openssl",
            version="3.0.15",
            host="web-server-1",
            severity="CRITICAL",
            kev=True,
            score=0.95,
            status="open",
            created_at=dt,
        )
        assert f.id == 42
        assert f.run_id == "run-abc"
        assert f.cve_id == "CVE-2025-12345"
        assert f.package == "openssl"
        assert f.severity == "CRITICAL"
        assert f.kev is True
        assert f.score == 0.95
        assert f.status == "open"
        assert f.created_at == dt

    def test_finding_datetime_serialization(self) -> None:
        """FindingResponse.created_at serializes to ISO 8601."""
        dt = datetime(2026, 7, 4, 16, 45, 0, tzinfo=UTC)
        f = FindingResponse(run_id="r", created_at=dt)
        dumped = f.model_dump(mode="json")
        assert dumped["created_at"] == "2026-07-04T16:45:00Z"

    def test_finding_datetime_null_serialization(self) -> None:
        """FindingResponse.created_at serializes to null when not set."""
        f = FindingResponse(run_id="r")
        dumped = f.model_dump(mode="json")
        assert dumped["created_at"] is None

    def test_field_mapping_from_db_record(self) -> None:
        """API surface field names match documented DB-to-API mapping.

        LatestFindingRecord.criticality -> FindingResponse.severity
        LatestFindingRecord.package_name -> FindingResponse.package
        LatestFindingRecord.fixed_version -> FindingResponse.version
        LatestFindingRecord.system_id -> FindingResponse.run_id (proxied)
        """
        # Simulate the router mapping from LatestFindingRecord to FindingResponse
        db_row_values = {
            "id": 1,
            "system_id": 99,
            "cve_id": "CVE-2025-00001",
            "package_name": "curl",
            "fixed_version": "8.5.0",
            "host": "db-host",
            "criticality": "HIGH",
            "score": 0.72,
            "status": "open",
            "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        }
        # This is how the router maps it (from api_router.py)
        f = FindingResponse(
            id=db_row_values["id"],
            run_id=str(db_row_values["system_id"]),
            cve_id=db_row_values["cve_id"],
            package=db_row_values["package_name"],
            version=db_row_values["fixed_version"],
            host=db_row_values["host"],
            severity=db_row_values["criticality"],
            kev=False,
            score=db_row_values["score"],
            status=db_row_values["status"],
            created_at=db_row_values["created_at"],
        )
        assert f.run_id == "99"
        assert f.package == "curl"
        assert f.severity == "HIGH"
        assert f.version == "8.5.0"


# ---------------------------------------------------------------------------
# BulkStatusUpdateRequest -- validation
# ---------------------------------------------------------------------------


class TestBulkStatusValidation:
    """BulkStatusUpdateRequest validates status and finding_ids."""

    @pytest.mark.parametrize("valid_status", list(BULK_ALLOWED_STATUSES))
    def test_valid_statuses_accepted(self, valid_status: str) -> None:
        """Each allowed status is accepted."""
        r = BulkStatusUpdateRequest(finding_ids=[1], status=valid_status)
        assert r.status == valid_status

    @pytest.mark.parametrize(
        "bad_status",
        ["invalid", "OPEN", "closed", "fixed", ""],
        ids=["invalid", "OPEN-case", "closed", "fixed", "empty"],
    )
    def test_invalid_statuses_rejected(self, bad_status: str) -> None:
        """Invalid status raises ValidationError."""
        with pytest.raises(ValidationError):
            BulkStatusUpdateRequest(finding_ids=[1], status=bad_status)

    def test_empty_finding_ids_rejected(self) -> None:
        """Empty finding_ids list raises ValidationError (min_length=1)."""
        with pytest.raises(ValidationError):
            BulkStatusUpdateRequest(finding_ids=[], status="open")

    def test_finding_ids_required(self) -> None:
        """finding_ids field is required."""
        with pytest.raises(ValidationError):
            BulkStatusUpdateRequest(status="open")  # type: ignore[call-arg]

    def test_status_required(self) -> None:
        """status field is required."""
        with pytest.raises(ValidationError):
            BulkStatusUpdateRequest(finding_ids=[1])  # type: ignore[call-arg]

    def test_multiple_finding_ids(self) -> None:
        """Multiple finding IDs accepted."""
        r = BulkStatusUpdateRequest(finding_ids=[1, 2, 3, 100], status="remediated")
        assert r.finding_ids == [1, 2, 3, 100]
        assert r.status == "remediated"


# ---------------------------------------------------------------------------
# BulkUpdateResponse
# ---------------------------------------------------------------------------


class TestBulkUpdateResponse:
    """BulkUpdateResponse fields and defaults."""

    def test_defaults(self) -> None:
        """BulkUpdateResponse.status defaults to 'updated'."""
        r = BulkUpdateResponse(count=3)
        assert r.status == "updated"
        assert r.count == 3

    def test_count_required(self) -> None:
        """count field is required."""
        with pytest.raises(ValidationError):
            BulkUpdateResponse()  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# FacetsResponse -- extensibility
# ---------------------------------------------------------------------------


class TestFacetsResponseExtensibility:
    """FacetsResponse supports arbitrary facet groups."""

    def test_empty_facets(self) -> None:
        """FacetsResponse defaults to empty dict."""
        r = FacetsResponse()
        assert r.facets == {}

    def test_standard_groups(self) -> None:
        """Standard severity/host/package groups work."""
        r = FacetsResponse(facets={
            "severity": {"CRITICAL": 5, "HIGH": 12},
            "host": {"web-1": 3},
            "package": {"openssl": 2},
        })
        assert r.facets["severity"]["CRITICAL"] == 5
        assert r.facets["host"]["web-1"] == 3

    def test_custom_groups(self) -> None:
        """Arbitrary groups can be added without schema changes."""
        r = FacetsResponse(facets={
            "severity": {"HIGH": 1},
            "custom_module_group": {"value_a": 10, "value_b": 20},
        })
        assert "custom_module_group" in r.facets
        assert r.facets["custom_module_group"]["value_a"] == 10

    def test_kev_group(self) -> None:
        """kev facet group uses string keys for boolean values."""
        r = FacetsResponse(facets={"kev": {"true": 5, "false": 95}})
        assert r.facets["kev"]["true"] == 5


# ---------------------------------------------------------------------------
# FindingsListResponse alias
# ---------------------------------------------------------------------------


class TestFindingsListResponseAlias:
    """FindingsListResponse is PaginatedResponse[FindingResponse]."""

    def test_wraps_finding_response(self) -> None:
        """FindingsListResponse paginates FindingResponse items."""
        item = FindingResponse(run_id="run-1", cve_id="CVE-2025-00001")
        r = FindingsListResponse(
            total=1, page=1, page_size=50, pages=1, items=[item],
        )
        assert len(r.items) == 1
        assert r.items[0].cve_id == "CVE-2025-00001"
        assert r.total == 1

    def test_empty_response(self) -> None:
        """Empty findings list is valid."""
        r = FindingsListResponse(
            total=0, page=1, page_size=50, pages=0, items=[],
        )
        assert r.total == 0
        assert r.items == []
        assert r.pages == 0

    def test_pages_auto_computed(self) -> None:
        """Pages auto-computed when pages=0 and total>0."""
        r = FindingsListResponse(
            total=51, page=1, page_size=50, pages=0,
            items=[FindingResponse(run_id="r")],
        )
        assert r.pages == 2


# ---------------------------------------------------------------------------
# Module __all__ exports
# ---------------------------------------------------------------------------


class TestAuthExports:
    """auth module __all__ exports match defined classes."""

    def test_all_exports(self) -> None:
        """auth.__all__ contains exactly the defined schema classes."""
        expected = {
            "ApiKeyCreateRequest",
            "ApiKeyCreateResponse",
            "ApiKeyListItem",
            "ApiKeyListResponse",
            "ApiKeyRevokeResponse",
            "RefreshRequest",
            "RefreshResponse",
            "TokenRequest",
            "TokenResponse",
        }
        assert set(auth_module.__all__) == expected

    def test_no_extra_exports(self) -> None:
        """No public classes exist that are missing from __all__."""
        from pydantic import BaseModel

        public_classes = {
            name for name, obj in vars(auth_module).items()
            if isinstance(obj, type) and issubclass(obj, BaseModel)
            and not name.startswith("_") and obj.__module__ == auth_module.__name__
        }
        assert public_classes == set(auth_module.__all__)


class TestFindingsExports:
    """findings module __all__ exports match defined classes."""

    def test_all_exports(self) -> None:
        """findings.__all__ contains exactly the defined schema classes."""
        expected = {
            "BulkStatusUpdateRequest",
            "BulkUpdateResponse",
            "FacetsResponse",
            "FindingResponse",
            "FindingsListResponse",
        }
        assert set(findings_module.__all__) == expected
