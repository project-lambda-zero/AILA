"""Tests for the RFC-09 step 4 prompt version store.

Covers immutable content-hash-deduplicated register, monotonic versioning,
resolve by version and by alias, the alias flip audit log, and the
missing-version guard.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlmodel import select

from aila.platform.prompts.version_models import PromptAliasChangeRecord
from aila.platform.prompts.version_store import (
    PromptVersionNotFoundError,
    PromptVersionStore,
)
from aila.storage.database import session_scope


def _key() -> str:
    return f"vr/audit-{uuid4().hex[:8]}"


@pytest.mark.asyncio
async def test_register_is_content_hash_idempotent(test_db) -> None:
    del test_db
    store = PromptVersionStore()
    key = _key()
    v1 = await store.register(key, "BODY ONE", author="op", notes="first")
    v1_again = await store.register(key, "BODY ONE", author="op", notes="dup")
    v2 = await store.register(key, "BODY TWO", author="op", notes="second")
    assert v1 == "1.0.0"
    assert v1_again == v1  # identical body -> same version, no duplicate
    assert v2 == "1.0.1"


@pytest.mark.asyncio
async def test_resolve_by_version(test_db) -> None:
    del test_db
    store = PromptVersionStore()
    key = _key()
    v = await store.register(key, "HELLO", author="op", notes="")
    row = await store.resolve(key, version=v)
    assert row is not None
    assert row.body == "HELLO"


@pytest.mark.asyncio
async def test_resolve_unknown_returns_none(test_db) -> None:
    del test_db
    store = PromptVersionStore()
    key = _key()
    assert await store.resolve(key, version="9.9.9") is None
    assert await store.resolve(key, alias="production") is None
    assert await store.resolve(key) is None


@pytest.mark.asyncio
async def test_set_alias_then_resolve_by_alias(test_db) -> None:
    del test_db
    store = PromptVersionStore()
    key = _key()
    v1 = await store.register(key, "V1 BODY")
    v2 = await store.register(key, "V2 BODY")
    await store.set_alias(key, "production", v1, actor="op", reason="deploy v1")
    assert (await store.resolve(key, alias="production")).body == "V1 BODY"
    # Rollback / re-deploy flips the pointer.
    await store.set_alias(key, "production", v2, actor="op", reason="deploy v2")
    assert (await store.resolve(key, alias="production")).body == "V2 BODY"

    with session_scope() as sess:
        changes = sess.exec(
            select(PromptAliasChangeRecord).where(
                PromptAliasChangeRecord.key == key,
                PromptAliasChangeRecord.alias == "production",
            )
        ).all()
    assert len(changes) == 2
    by_to = {c.to_version: c for c in changes}
    assert by_to[v1].from_version is None
    assert by_to[v2].from_version == v1


@pytest.mark.asyncio
async def test_set_alias_unknown_version_raises(test_db) -> None:
    del test_db
    store = PromptVersionStore()
    key = _key()
    with pytest.raises(PromptVersionNotFoundError):
        await store.set_alias(key, "production", "1.0.0", actor="op", reason="x")
