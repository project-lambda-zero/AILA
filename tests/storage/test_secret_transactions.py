"""SecretStore staging contract: stage_* flushes without committing.

Multi-step writers stage secret changes inside their own transaction and
commit once. These tests pin the rollback behaviour and the commit semantics
that single-operation upsert_secret / delete_secret keep.
"""

from __future__ import annotations

import pytest
from sqlmodel import select

from aila.storage.database import async_session_scope
from aila.storage.db_models import SecretRecord
from aila.storage.secrets import SecretStore

_SCOPE = "stage-test"


async def _find(session, secret_key: str) -> SecretRecord | None:
    return (await session.exec(
        select(SecretRecord).where(
            SecretRecord.scope == _SCOPE,
            SecretRecord.secret_key == secret_key,
        )
    )).first()


@pytest.mark.usefixtures("test_db")
async def test_stage_secret_is_discarded_on_rollback() -> None:
    store = SecretStore()
    async with async_session_scope() as session:
        staged = await store.stage_secret(
            session, scope=_SCOPE, secret_key="rolled-back", plaintext="s3cret",
        )
        assert staged.id is not None
        await session.rollback()

    async with async_session_scope() as session:
        assert await _find(session, "rolled-back") is None


@pytest.mark.usefixtures("test_db")
async def test_stage_secret_persists_only_with_caller_commit() -> None:
    store = SecretStore()
    async with async_session_scope() as session:
        await store.stage_secret(
            session, scope=_SCOPE, secret_key="committed", plaintext="s3cret",
        )
        await session.commit()

    async with async_session_scope() as session:
        assert await store.get_secret_by_key(
            session, scope=_SCOPE, secret_key="committed",
        ) == "s3cret"


@pytest.mark.usefixtures("test_db")
async def test_stage_secret_if_absent_inserts_then_leaves_existing_row_untouched() -> None:
    store = SecretStore()
    async with async_session_scope() as session:
        assert await store.stage_secret_if_absent(
            session, scope=_SCOPE, secret_key="first-wins", plaintext="winner-key",
        ) is True
        await session.commit()

    async with async_session_scope() as session:
        before = await _find(session, "first-wins")
        assert before is not None
        snapshot = (before.id, before.ciphertext, before.nonce, before.hint, before.key_version)

    async with async_session_scope() as session:
        assert await store.stage_secret_if_absent(
            session, scope=_SCOPE, secret_key="first-wins", plaintext="loser-key",
        ) is False
        await session.commit()

    async with async_session_scope() as session:
        after = await _find(session, "first-wins")
        assert after is not None
        assert (after.id, after.ciphertext, after.nonce, after.hint, after.key_version) == snapshot
        assert await store.get_secret_by_key(
            session, scope=_SCOPE, secret_key="first-wins",
        ) == "winner-key"


@pytest.mark.usefixtures("test_db")
async def test_stage_secret_if_absent_is_discarded_on_rollback() -> None:
    store = SecretStore()
    async with async_session_scope() as session:
        assert await store.stage_secret_if_absent(
            session, scope=_SCOPE, secret_key="absent-rolled-back", plaintext="s3cret",
        ) is True
        await session.rollback()

    async with async_session_scope() as session:
        assert await _find(session, "absent-rolled-back") is None


@pytest.mark.usefixtures("test_db")
async def test_stage_secret_by_key_keeps_existing_row_id() -> None:
    store = SecretStore()
    async with async_session_scope() as session:
        first = await store.stage_secret(
            session, scope=_SCOPE, secret_key="same-key", plaintext="one",
        )
        await session.commit()
        first_id = first.id

    async with async_session_scope() as session:
        second = await store.stage_secret(
            session, scope=_SCOPE, secret_key="same-key", plaintext="two",
        )
        await session.commit()

    assert second.id == first_id
    async with async_session_scope() as session:
        assert await store.get_secret_by_key(
            session, scope=_SCOPE, secret_key="same-key",
        ) == "two"


@pytest.mark.usefixtures("test_db")
async def test_stage_delete_secret_returns_false_for_missing_row() -> None:
    store = SecretStore()
    async with async_session_scope() as session:
        deleted = await store.stage_delete_secret(
            session, scope=_SCOPE, secret_key="never-created",
        )
        await session.rollback()
    assert deleted is False


@pytest.mark.usefixtures("test_db")
async def test_stage_delete_secret_is_discarded_on_rollback() -> None:
    store = SecretStore()
    async with async_session_scope() as session:
        await store.stage_secret(
            session, scope=_SCOPE, secret_key="kept", plaintext="s3cret",
        )
        await session.commit()

    async with async_session_scope() as session:
        assert await store.stage_delete_secret(
            session, scope=_SCOPE, secret_key="kept",
        ) is True
        await session.rollback()

    async with async_session_scope() as session:
        assert await _find(session, "kept") is not None


@pytest.mark.usefixtures("test_db")
async def test_upsert_secret_still_commits() -> None:
    store = SecretStore()
    async with async_session_scope() as session:
        await store.upsert_secret(
            session, scope=_SCOPE, secret_key="single-op", plaintext="s3cret",
        )

    async with async_session_scope() as session:
        assert await store.get_secret_by_key(
            session, scope=_SCOPE, secret_key="single-op",
        ) == "s3cret"


@pytest.mark.usefixtures("test_db")
async def test_delete_secret_still_commits() -> None:
    store = SecretStore()
    async with async_session_scope() as session:
        await store.upsert_secret(
            session, scope=_SCOPE, secret_key="to-delete", plaintext="s3cret",
        )

    async with async_session_scope() as session:
        assert await store.delete_secret(
            session, scope=_SCOPE, secret_key="to-delete",
        ) is True

    async with async_session_scope() as session:
        assert await _find(session, "to-delete") is None
