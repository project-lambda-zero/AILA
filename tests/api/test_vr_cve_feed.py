"""End-to-end tests for CVE ingest + memo invalidation (v0.4 GA-51)."""
from __future__ import annotations

import pytest
from httpx import AsyncClient


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_ingest_cve_creates_record(
    async_client: AsyncClient, admin_token: str,
) -> None:
    resp = await async_client.post(
        "/vr/cves", headers=_auth(admin_token),
        json={
            "cve_id": "CVE-2026-9001",
            "source": "manual",
            "title": "Test CVE",
            "description": "A type confusion in V8 InferMaps optimisation",
            "cvss_score": 9.8,
            "cwe_ids": ["CWE-843"],
            "references": ["https://nvd.nist.gov/CVE-2026-9001"],
            "affected_components": ["v8"],
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()["data"]
    assert body["inserted"] is True
    assert body["cve"]["cve_id"] == "CVE-2026-9001"
    assert body["cve"]["cvss_score"] == 9.8
    assert body["cve"]["cwe_ids"] == ["CWE-843"]


@pytest.mark.asyncio
async def test_ingest_cve_is_idempotent_on_cve_id(
    async_client: AsyncClient, admin_token: str,
) -> None:
    payload = {
        "cve_id": "CVE-2026-9002",
        "source": "manual",
        "description": "first description",
    }
    r1 = await async_client.post(
        "/vr/cves", headers=_auth(admin_token), json=payload,
    )
    assert r1.status_code == 201
    assert r1.json()["data"]["inserted"] is True

    # Re-ingest with updated description — should update, not insert
    payload["description"] = "second description"
    payload["cvss_score"] = 7.5
    r2 = await async_client.post(
        "/vr/cves", headers=_auth(admin_token), json=payload,
    )
    assert r2.status_code == 201
    assert r2.json()["data"]["inserted"] is False
    assert r2.json()["data"]["cve"]["description"] == "second description"
    assert r2.json()["data"]["cve"]["cvss_score"] == 7.5


@pytest.mark.asyncio
async def test_get_cve_by_id(
    async_client: AsyncClient, admin_token: str,
) -> None:
    await async_client.post(
        "/vr/cves", headers=_auth(admin_token),
        json={
            "cve_id": "CVE-2026-9003",
            "source": "nvd",
            "title": "GetTest",
            "description": "Test description for retrieval.",
        },
    )
    got = await async_client.get(
        "/vr/cves/CVE-2026-9003", headers=_auth(admin_token),
    )
    assert got.status_code == 200
    assert got.json()["data"]["title"] == "GetTest"


@pytest.mark.asyncio
async def test_list_cves_filterable(
    async_client: AsyncClient, admin_token: str,
) -> None:
    await async_client.post(
        "/vr/cves", headers=_auth(admin_token),
        json={"cve_id": "CVE-2026-9010", "source": "nvd", "cvss_score": 9.0},
    )
    await async_client.post(
        "/vr/cves", headers=_auth(admin_token),
        json={"cve_id": "CVE-2026-9011", "source": "ghsa", "cvss_score": 4.5},
    )
    await async_client.post(
        "/vr/cves", headers=_auth(admin_token),
        json={"cve_id": "CVE-2026-9012", "source": "nvd", "cvss_score": 8.0},
    )

    # Filter by source
    nvd = await async_client.get(
        "/vr/cves", headers=_auth(admin_token),
        params={"source": "nvd"},
    )
    assert nvd.status_code == 200
    nvd_ids = {r["cve_id"] for r in nvd.json()["data"]}
    assert "CVE-2026-9010" in nvd_ids
    assert "CVE-2026-9012" in nvd_ids
    assert "CVE-2026-9011" not in nvd_ids

    # Filter by min_cvss
    high = await async_client.get(
        "/vr/cves", headers=_auth(admin_token),
        params={"min_cvss": 8.5},
    )
    assert high.status_code == 200
    high_ids = {r["cve_id"] for r in high.json()["data"]}
    assert "CVE-2026-9010" in high_ids
    assert "CVE-2026-9011" not in high_ids
    assert "CVE-2026-9012" not in high_ids


@pytest.mark.asyncio
async def test_404_on_unknown_cve(
    async_client: AsyncClient, admin_token: str,
) -> None:
    resp = await async_client.get(
        "/vr/cves/CVE-2099-99999", headers=_auth(admin_token),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_invalid_cve_id_format_rejected(
    async_client: AsyncClient, admin_token: str,
) -> None:
    resp = await async_client.post(
        "/vr/cves", headers=_auth(admin_token),
        json={
            "cve_id": "not-a-cve",
            "description": "x",
        },
    )
    assert resp.status_code == 422
