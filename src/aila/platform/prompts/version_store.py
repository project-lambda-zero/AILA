"""Async CRUD for the immutable prompt-version + alias store (RFC-09 step 4).

The platform owns register (immutable, content-hash-deduplicated), resolve
(by explicit version or by alias pointer), and set_alias (an audited pointer
flip = deploy / rollback). Canonical aliases are ``candidate`` / ``staging``
/ ``production``, but any string is accepted so a caller can add its own.
"""
from __future__ import annotations

import hashlib

from sqlmodel import select

from aila.platform.contracts._common import utc_now
from aila.platform.prompts.version_models import (
    PromptAliasChangeRecord,
    PromptAliasRecord,
    PromptVersionRecord,
)
from aila.storage.database import async_session_scope

__all__ = ["PromptVersionNotFoundError", "PromptVersionStore"]


class PromptVersionNotFoundError(RuntimeError):
    """Raised when set_alias targets a version that does not exist."""


def _content_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class PromptVersionStore:
    """Register, resolve, and alias immutable prompt versions."""

    async def register(
        self, key: str, body: str, *, author: str = "", notes: str = "",
    ) -> str:
        """Register ``body`` under ``key`` and return its version.

        Immutable and content-hash-deduplicated: re-registering an identical
        body returns the existing version rather than creating a duplicate.
        A new body gets the next monotonic version for the key.
        """
        content_hash = _content_hash(body)
        async with async_session_scope() as session:
            existing = (
                await session.exec(
                    select(PromptVersionRecord).where(
                        PromptVersionRecord.key == key,
                        PromptVersionRecord.content_hash == content_hash,
                    )
                )
            ).first()
            if existing is not None:
                return existing.version
            prior = (
                await session.exec(
                    select(PromptVersionRecord).where(
                        PromptVersionRecord.key == key,
                    )
                )
            ).all()
            # Next suffix is one past the highest issued suffix, not the
            # row count: archiving an old version must not make a later
            # register reuse (and collide with) an already-issued number.
            next_suffix = 0
            for rec in prior:
                try:
                    issued = int(rec.version.rsplit(".", 1)[-1])
                except ValueError:
                    continue
                next_suffix = max(next_suffix, issued + 1)
            version = f"1.0.{next_suffix}"
            session.add(PromptVersionRecord(
                key=key, version=version, content_hash=content_hash,
                body=body, author=author, notes=notes,
            ))
            await session.commit()
            return version

    async def list_versions(self, key: str) -> list[PromptVersionRecord]:
        """Every registered version for ``key``, oldest first."""
        async with async_session_scope() as session:
            return list((await session.exec(
                select(PromptVersionRecord)
                .where(PromptVersionRecord.key == key)
                .order_by(PromptVersionRecord.created_at)
            )).all())

    async def list_aliases(self, key: str) -> list[PromptAliasRecord]:
        """Every alias pointer for ``key``."""
        async with async_session_scope() as session:
            return list((await session.exec(
                select(PromptAliasRecord).where(PromptAliasRecord.key == key)
            )).all())

    async def resolve(
        self, key: str, *, alias: str | None = None, version: str | None = None,
    ) -> PromptVersionRecord | None:
        """Resolve a version by explicit ``version`` or by ``alias`` pointer.

        Returns None when nothing matches (the caller falls back to the
        file-backed base prompt).
        """
        async with async_session_scope() as session:
            if version is not None:
                return (
                    await session.exec(
                        select(PromptVersionRecord).where(
                            PromptVersionRecord.key == key,
                            PromptVersionRecord.version == version,
                        )
                    )
                ).first()
            if alias is None:
                return None
            pointer = (
                await session.exec(
                    select(PromptAliasRecord).where(
                        PromptAliasRecord.key == key,
                        PromptAliasRecord.alias == alias,
                    )
                )
            ).first()
            if pointer is None:
                return None
            return (
                await session.exec(
                    select(PromptVersionRecord).where(
                        PromptVersionRecord.key == key,
                        PromptVersionRecord.version == pointer.version,
                    )
                )
            ).first()

    async def set_alias(
        self, key: str, alias: str, version: str, *, actor: str = "", reason: str = "",
    ) -> None:
        """Point ``alias`` at ``version`` and record the flip in the audit log.

        Raises PromptVersionNotFoundError when the version does not exist.
        """
        async with async_session_scope() as session:
            target = (
                await session.exec(
                    select(PromptVersionRecord).where(
                        PromptVersionRecord.key == key,
                        PromptVersionRecord.version == version,
                    )
                )
            ).first()
            if target is None:
                raise PromptVersionNotFoundError(
                    f"no version {version!r} registered for key {key!r}",
                )
            pointer = (
                await session.exec(
                    select(PromptAliasRecord).where(
                        PromptAliasRecord.key == key,
                        PromptAliasRecord.alias == alias,
                    )
                )
            ).first()
            from_version = pointer.version if pointer is not None else None
            if pointer is None:
                session.add(PromptAliasRecord(key=key, alias=alias, version=version))
            else:
                pointer.version = version
                pointer.updated_at = utc_now()
                session.add(pointer)
            session.add(PromptAliasChangeRecord(
                key=key, alias=alias, from_version=from_version,
                to_version=version, actor=actor, reason=reason,
            ))
            await session.commit()
