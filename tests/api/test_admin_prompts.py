"""API tests for the RFC-09 admin prompt-version router.

Covers the operator deploy loop: register an immutable version, list it,
flip the production alias (deploy/rollback), and the auth + not-found
guards.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from httpx import AsyncClient


def _key() -> str:
    return f"vr/audit-{uuid4().hex[:8]}/base"


@pytest.mark.asyncio
async def test_register_dedup_and_list(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    del test_db
    key = _key()
    hdr = {"Authorization": f"Bearer {admin_token}"}
    r1 = await async_client.post(
        "/admin/prompts/versions",
        json={"key": key, "body": "BODY ONE", "notes": "first"},
        headers=hdr,
    )
    assert r1.status_code == 201
    assert r1.json()["data"]["version"] == "1.0.0"

    # Identical body -> same version (content-hash dedup).
    r_dup = await async_client.post(
        "/admin/prompts/versions",
        json={"key": key, "body": "BODY ONE"},
        headers=hdr,
    )
    assert r_dup.json()["data"]["version"] == "1.0.0"

    r2 = await async_client.post(
        "/admin/prompts/versions",
        json={"key": key, "body": "BODY TWO"},
        headers=hdr,
    )
    assert r2.json()["data"]["version"] == "1.0.1"

    listing = await async_client.get(
        "/admin/prompts/versions", params={"key": key}, headers=hdr,
    )
    versions = [v["version"] for v in listing.json()["data"]]
    assert versions == ["1.0.0", "1.0.1"]


@pytest.mark.asyncio
async def test_set_alias_deploy_and_rollback(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    del test_db
    key = _key()
    hdr = {"Authorization": f"Bearer {admin_token}"}
    await async_client.post(
        "/admin/prompts/versions", json={"key": key, "body": "V1"}, headers=hdr,
    )
    await async_client.post(
        "/admin/prompts/versions", json={"key": key, "body": "V2"}, headers=hdr,
    )
    deploy = await async_client.put(
        "/admin/prompts/aliases",
        json={"key": key, "alias": "production", "version": "1.0.0", "reason": "deploy"},
        headers=hdr,
    )
    assert deploy.status_code == 200
    aliases = await async_client.get(
        "/admin/prompts/aliases", params={"key": key}, headers=hdr,
    )
    prod = {a["alias"]: a["version"] for a in aliases.json()["data"]}
    assert prod["production"] == "1.0.0"

    # Rollback / re-deploy flips the pointer.
    await async_client.put(
        "/admin/prompts/aliases",
        json={"key": key, "alias": "production", "version": "1.0.1", "reason": "rollforward"},
        headers=hdr,
    )
    aliases2 = await async_client.get(
        "/admin/prompts/aliases", params={"key": key}, headers=hdr,
    )
    prod2 = {a["alias"]: a["version"] for a in aliases2.json()["data"]}
    assert prod2["production"] == "1.0.1"


@pytest.mark.asyncio
async def test_set_alias_unknown_version_404(
    async_client: AsyncClient, admin_token: str, test_db,
) -> None:
    del test_db
    key = _key()
    hdr = {"Authorization": f"Bearer {admin_token}"}
    resp = await async_client.put(
        "/admin/prompts/aliases",
        json={"key": key, "alias": "production", "version": "9.9.9"},
        headers=hdr,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_requires_admin(
    async_client: AsyncClient, reader_token: str, test_db,
) -> None:
    del test_db
    resp = await async_client.post(
        "/admin/prompts/versions",
        json={"key": _key(), "body": "x"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403
