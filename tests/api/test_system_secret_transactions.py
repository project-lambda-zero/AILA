"""System writes never overwrite another system's secret on a failed row.

Secrets are keyed by system name. A duplicate-name write must fail its
unique-constraint flush and roll back its staged secret, so the existing
system's secret is left intact.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from aila.storage.database import async_session_scope
from aila.storage.secrets import SecretStore


async def _ssh_secret(system_name: str, suffix: str) -> str | None:
    async with async_session_scope() as session:
        return await SecretStore().get_secret_by_key(
            session, scope="ssh", secret_key=f"system.{system_name}.{suffix}",
        )


@pytest.mark.asyncio
async def test_duplicate_create_does_not_overwrite_existing_password(
    async_client: AsyncClient, operator_token: str
) -> None:
    headers = {"Authorization": f"Bearer {operator_token}"}
    created = await async_client.post(
        "/systems",
        json={"name": "sec-dup", "host": "10.0.1.1", "password": "first-pw"},
        headers=headers,
    )
    assert created.status_code == 201, created.text

    dup = await async_client.post(
        "/systems",
        json={"name": "sec-dup", "host": "10.0.1.2", "password": "hijack-pw"},
        headers=headers,
    )
    assert dup.status_code == 409

    assert await _ssh_secret("sec-dup", "password") == "first-pw"


@pytest.mark.asyncio
async def test_csv_duplicate_row_does_not_overwrite_existing_password(
    async_client: AsyncClient, operator_token: str
) -> None:
    headers = {"Authorization": f"Bearer {operator_token}"}
    created = await async_client.post(
        "/systems",
        json={"name": "csv-dup", "host": "10.0.2.1", "password": "orig-pw"},
        headers=headers,
    )
    assert created.status_code == 201, created.text

    resp = await async_client.post(
        "/systems/import-csv",
        json={"systems": [
            {"name": "csv-dup", "host": "10.0.2.2", "password": "hijack-pw"},
        ]},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["created"] == []
    assert len(body["errors"]) == 1

    assert await _ssh_secret("csv-dup", "password") == "orig-pw"


@pytest.mark.asyncio
async def test_duplicate_rename_update_leaves_both_secrets_unchanged(
    async_client: AsyncClient, operator_token: str
) -> None:
    headers = {"Authorization": f"Bearer {operator_token}"}
    a = await async_client.post(
        "/systems",
        json={"name": "upd-a", "host": "10.0.3.1", "password": "pw-a"},
        headers=headers,
    )
    assert a.status_code == 201, a.text
    b = await async_client.post(
        "/systems",
        json={"name": "upd-b", "host": "10.0.3.2", "password": "pw-b"},
        headers=headers,
    )
    assert b.status_code == 201, b.text

    resp = await async_client.put(
        f"/systems/{b.json()['id']}",
        json={"name": "upd-a", "password": "pw-new"},
        headers=headers,
    )
    assert resp.status_code == 409

    assert await _ssh_secret("upd-a", "password") == "pw-a"
    assert await _ssh_secret("upd-b", "password") == "pw-b"
