"""Tests for the RFC-09 step 4 prompt version store.

Covers immutable content-hash-deduplicated register, monotonic versioning,
resolve by version and by alias, the alias flip audit log, and the
missing-version guard.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlmodel import select

from aila.platform.prompts.version_models import (
    PromptAliasChangeRecord,
    PromptVersionRecord,
)
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
async def test_register_after_archive_does_not_reuse_suffix(test_db) -> None:
    """Archiving an old version must not make a later register reuse (and
    collide with) an already-issued suffix -- the next suffix is one past
    the highest issued, not the surviving row count."""
    del test_db
    store = PromptVersionStore()
    key = _key()
    v0 = await store.register(key, "BODY 0")
    await store.register(key, "BODY 1")
    await store.register(key, "BODY 2")
    assert v0 == "1.0.0"
    # Archive the oldest version. A count-based next suffix would now emit
    # "1.0.2", colliding with the surviving BODY 2 row.
    with session_scope() as sess:
        row = sess.exec(
            select(PromptVersionRecord).where(
                PromptVersionRecord.key == key,
                PromptVersionRecord.version == v0,
            )
        ).one()
        sess.delete(row)
        sess.commit()
    v3 = await store.register(key, "BODY 3")
    assert v3 == "1.0.3"


@pytest.mark.asyncio
async def test_set_alias_unknown_version_raises(test_db) -> None:
    del test_db
    store = PromptVersionStore()
    key = _key()
    with pytest.raises(PromptVersionNotFoundError):
        await store.set_alias(key, "production", "1.0.0", actor="op", reason="x")


@pytest.mark.asyncio
async def test_resolve_prefers_family_specific_key(test_db) -> None:
    """When ``model_family`` is set the store checks ``{key}/{family}`` first.

    Family-specific and default-variant rows co-exist under sibling keys; a
    caller passing ``model_family="claude"`` must resolve the family row,
    while a caller passing ``model_family=None`` still sees the bare key.
    """
    del test_db
    store = PromptVersionStore()
    base = _key()
    family_key = f"{base}/claude"
    v_family = await store.register(family_key, "CLAUDE BODY", author="op")
    v_default = await store.register(base, "DEFAULT BODY", author="op")
    await store.set_alias(
        family_key, "production", v_family, actor="op", reason="promote family",
    )
    await store.set_alias(
        base, "production", v_default, actor="op", reason="promote default",
    )

    got_family = await store.resolve(base, alias="production", model_family="claude")
    assert got_family is not None
    assert got_family.body == "CLAUDE BODY"
    got_default = await store.resolve(base, alias="production")
    assert got_default is not None
    assert got_default.body == "DEFAULT BODY"


@pytest.mark.asyncio
async def test_resolve_family_missing_falls_back_to_default_variant(test_db) -> None:
    """A family with no family-specific row falls back to the bare key row."""
    del test_db
    store = PromptVersionStore()
    base = _key()
    v_default = await store.register(base, "DEFAULT BODY", author="op")
    await store.set_alias(
        base, "production", v_default, actor="op", reason="promote default",
    )

    got = await store.resolve(base, alias="production", model_family="gpt")
    assert got is not None
    assert got.body == "DEFAULT BODY"


@pytest.mark.asyncio
async def test_resolve_by_explicit_version_honours_family(test_db) -> None:
    """An explicit version query is scoped to the family-specific key first."""
    del test_db
    store = PromptVersionStore()
    base = _key()
    family_key = f"{base}/claude"
    v_family = await store.register(family_key, "CLAUDE V1", author="op")
    # Same version string exists on both keys; the family key wins.
    v_default = await store.register(base, "DEFAULT V1", author="op")
    assert v_family == v_default  # both are the first version on their key

    got = await store.resolve(base, version=v_family, model_family="claude")
    assert got is not None
    assert got.body == "CLAUDE V1"


@pytest.mark.asyncio
async def test_resolve_family_missing_and_no_default_returns_none(test_db) -> None:
    del test_db
    store = PromptVersionStore()
    base = _key()
    got = await store.resolve(base, alias="production", model_family="claude")
    assert got is None
