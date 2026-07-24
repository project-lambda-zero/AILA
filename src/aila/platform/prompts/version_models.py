"""Immutable prompt-version + release-alias tables (RFC-09 step 4).

A prompt body is stored as an immutable, content-hashed version; a mutable
alias (candidate / staging / production) points at a version; every alias
flip is recorded in an append-only change log. Resolution reads a version by
alias or explicit version. The platform owns storage, versioning, and the
alias audit; a module supplies the body under its own key. Keys are opaque
strings the caller composes (for example ``"vr/audit"``); the platform never
parses a module out of them.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Index, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now

__all__ = [
    "PromptAliasChangeRecord",
    "PromptAliasRecord",
    "PromptVersionRecord",
]


class PromptVersionRecord(SQLModel, table=True):
    """One immutable prompt version. A new body is a new content hash and a
    new version; the same body re-registered resolves to the existing row."""

    __tablename__ = "prompt_versions"
    __table_args__ = (
        UniqueConstraint("key", "version", name="uq_prompt_versions_key_version"),
        UniqueConstraint(
            "key", "content_hash", name="uq_prompt_versions_key_content_hash",
        ),
        Index("ix_prompt_versions_key", "key"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    key: str = Field(max_length=256)
    version: str = Field(max_length=32)
    content_hash: str = Field(max_length=64)
    body: str = Field(sa_type=Text)
    author: str = Field(default="", max_length=128)
    notes: str = Field(default="", sa_type=Text)
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )


class PromptAliasRecord(SQLModel, table=True):
    """Mutable pointer from a (key, alias) to a version. One row per pair."""

    __tablename__ = "prompt_aliases"
    __table_args__ = (
        UniqueConstraint("key", "alias", name="uq_prompt_aliases_key_alias"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    key: str = Field(max_length=256, index=True)
    alias: str = Field(max_length=32)
    version: str = Field(max_length=32)
    updated_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )


class PromptAliasChangeRecord(SQLModel, table=True):
    """Append-only audit of every alias flip (deploy / rollback)."""

    __tablename__ = "prompt_alias_changes"
    __table_args__ = (
        Index("ix_prompt_alias_changes_key_alias", "key", "alias"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    key: str = Field(max_length=256)
    alias: str = Field(max_length=32)
    from_version: str | None = Field(default=None, max_length=32)
    to_version: str = Field(max_length=32)
    actor: str = Field(default="", max_length=128)
    reason: str = Field(default="", sa_type=Text)
    changed_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )
