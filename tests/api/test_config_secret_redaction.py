"""Config secret-value redaction tests for #50 (C6).

The config router is readable by any authenticated user, so secret-classed
values (api_key/hmac_key/token/...) were returned verbatim to non-admins.
Secret values are now redacted for non-admin callers; admins still see them.
"""
from __future__ import annotations

from httpx import AsyncClient
from sqlmodel import select

from aila.storage.database import async_session_scope
from aila.storage.db_models import ConfigEntryRecord

_KEYS = ("probe_api_key", "log_level")


async def _seed_config() -> None:
    async with async_session_scope() as session:
        existing = (
            await session.exec(
                select(ConfigEntryRecord).where(
                    ConfigEntryRecord.namespace == "platform",
                    ConfigEntryRecord.key.in_(_KEYS),
                )
            )
        ).all()
        for row in existing:
            await session.delete(row)
        # SQLAlchemy orders INSERTs before DELETEs within one flush; force the
        # deletes out first so re-seeding does not trip the unique constraint.
        await session.flush()
        session.add(
            ConfigEntryRecord(namespace="platform", key="probe_api_key", value="s3cr3t-value")
        )
        session.add(
            ConfigEntryRecord(namespace="platform", key="log_level", value="info")
        )
        await session.commit()


async def test_reader_gets_redacted_secret(async_client: AsyncClient, reader_token: str) -> None:
    await _seed_config()
    resp = await async_client.get(
        "/config/platform/probe_api_key",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["value"] == "[REDACTED]"


async def test_admin_gets_plaintext_secret(async_client: AsyncClient, admin_token: str) -> None:
    await _seed_config()
    resp = await async_client.get(
        "/config/platform/probe_api_key",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["value"] == "s3cr3t-value"


async def test_reader_sees_nonsecret_plaintext(async_client: AsyncClient, reader_token: str) -> None:
    await _seed_config()
    resp = await async_client.get(
        "/config/platform/log_level",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["value"] == "info"


async def test_reader_list_redacts_secret_only(async_client: AsyncClient, reader_token: str) -> None:
    await _seed_config()
    resp = await async_client.get(
        "/config/platform",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 200
    by_key = {item["key"]: item["value"] for item in resp.json()["items"]}
    assert by_key["probe_api_key"] == "[REDACTED]"
    assert by_key["log_level"] == "info"
