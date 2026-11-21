"""SystemRegistryTool writes its password secret and system row in one transaction.

When the system row commit fails after the password is staged, the staged
secret must not persist.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy.exc import OperationalError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from aila.config import get_settings
from aila.platform.tools.registry import SystemRegistryTool
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord
from aila.storage.secrets import SecretStore


async def _password(name: str) -> str | None:
    async with async_session_scope() as session:
        return await SecretStore().get_secret_by_key(
            session, scope="system-password", secret_key=name,
        )


async def _system_exists(name: str) -> bool:
    async with async_session_scope() as session:
        return (await session.exec(
            select(ManagedSystemRecord).where(ManagedSystemRecord.name == name)
        )).first() is not None


@pytest.mark.usefixtures("test_db")
async def test_upsert_commit_failure_discards_staged_password(monkeypatch: pytest.MonkeyPatch) -> None:
    tool = SystemRegistryTool(get_settings())
    name = f"rollback-sys-{uuid4().hex[:6]}"

    async def _failing_commit(_self: AsyncSession) -> None:
        raise OperationalError("COMMIT", {}, Exception("simulated commit failure"))

    monkeypatch.setattr(AsyncSession, "commit", _failing_commit)
    with pytest.raises(OperationalError):
        await tool.forward(
            action="upsert",
            integration={"name": name, "host": "10.8.8.8", "username": "u", "password": "pw-rollback"},
        )

    assert await _password(name) is None
    assert not await _system_exists(name)
