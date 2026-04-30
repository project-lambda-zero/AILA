"""Phase 176a Task 4: OpenAPI schema shape for DataEnvelope[list[ReportSummary]] (gap-fix-01 #11)."""
from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_openapi_schema_datenvelope_list_reportsummary_is_correct(
    async_client: AsyncClient,
):
    resp = await async_client.get("/openapi.json")
    assert resp.status_code == 200
    spec = resp.json()

    # Route exists.
    path = "/vulnerability/reports/list"
    assert path in spec["paths"], f"missing path {path}"

    get_op = spec["paths"][path]["get"]
    ok_schema = get_op["responses"]["200"]["content"]["application/json"]["schema"]
    # Either an inline schema or a $ref to a generic DataEnvelope wrapper.
    assert isinstance(ok_schema, dict)
    # Resolve $ref if present.
    if "$ref" in ok_schema:
        ref = ok_schema["$ref"].rsplit("/", 1)[-1]
        resolved = spec["components"]["schemas"][ref]
    else:
        resolved = ok_schema
    # DataEnvelope shape: has 'data' property.
    props = resolved.get("properties", {})
    assert "data" in props, f"resolved schema missing 'data': {resolved}"
    data_schema = props["data"]
    # data is an array.
    assert data_schema.get("type") == "array", f"data schema not an array: {data_schema}"
    # items -> ReportSummary.
    items_schema = data_schema.get("items", {})
    if "$ref" in items_schema:
        item_ref = items_schema["$ref"].rsplit("/", 1)[-1]
        summary_schema = spec["components"]["schemas"][item_ref]
    else:
        summary_schema = items_schema
    summary_props = summary_schema.get("properties", {})
    # ReportSummary required fields are present.
    for field in ("id", "title", "target", "created_at", "status",
                  "severity_counts", "finding_count"):
        assert field in summary_props, f"ReportSummary missing field {field}"


@pytest.mark.asyncio
async def test_openapi_schema_datenvelope_reportdetail_is_correct(
    async_client: AsyncClient,
):
    resp = await async_client.get("/openapi.json")
    spec = resp.json()

    path = "/vulnerability/reports/detail/{report_id}"
    assert path in spec["paths"]
    get_op = spec["paths"][path]["get"]
    ok_schema = get_op["responses"]["200"]["content"]["application/json"]["schema"]
    if "$ref" in ok_schema:
        ref = ok_schema["$ref"].rsplit("/", 1)[-1]
        resolved = spec["components"]["schemas"][ref]
    else:
        resolved = ok_schema
    assert "data" in resolved.get("properties", {})
