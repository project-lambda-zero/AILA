"""OIDC provider writes keep provider rows and client secrets in one transaction.

A failed secret stage must leave no committed provider row with an empty
client_secret_encrypted reference, and a failed update must not partially
apply the provider fields.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlmodel import select

from aila.api.routers import oidc as oidc_router
from aila.storage.database import async_session_scope
from aila.storage.db_models import OIDCProviderRecord


def _boom(*_args: object, **_kwargs: object) -> None:
    raise RuntimeError("simulated secret stage failure")


async def _provider_by_name(name: str) -> OIDCProviderRecord | None:
    async with async_session_scope() as session:
        return (await session.exec(
            select(OIDCProviderRecord).where(OIDCProviderRecord.provider_name == name)
        )).first()


@pytest.mark.asyncio
async def test_create_provider_secret_failure_leaves_no_provider(
    async_client: AsyncClient, admin_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(oidc_router.SecretStore, "stage_secret", _boom)

    try:
        resp = await async_client.post(
            "/auth/oidc/providers",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "provider_name": "atomic-create",
                "provider_type": "microsoft",
                "tenant_id": "tenant-atomic",
                "client_id": "client-atomic",
                "client_secret": "never-stored",
            },
        )
        assert resp.status_code >= 500
    except RuntimeError:
        # Unhandled exception surfaced through the ASGI transport.
        pass

    assert await _provider_by_name("atomic-create") is None


@pytest.mark.asyncio
async def test_update_provider_secret_failure_applies_no_field_changes(
    async_client: AsyncClient, admin_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    create = await async_client.post(
        "/auth/oidc/providers",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "provider_name": "atomic-update",
            "provider_type": "microsoft",
            "tenant_id": "tenant-u",
            "client_id": "client-u",
            "client_secret": "original-secret",
        },
    )
    assert create.status_code == 201, create.text
    provider_id = create.json()["data"]["id"]
    before = await _provider_by_name("atomic-update")
    assert before is not None
    original_ref = before.client_secret_encrypted

    monkeypatch.setattr(oidc_router.SecretStore, "stage_secret", _boom)
    try:
        resp = await async_client.put(
            f"/auth/oidc/providers/{provider_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"client_id": "client-changed", "client_secret": "rotated-secret"},
        )
        assert resp.status_code >= 500
    except RuntimeError:
        pass

    after = await _provider_by_name("atomic-update")
    assert after is not None
    assert after.client_id == "client-u"
    assert after.client_secret_encrypted == original_ref
