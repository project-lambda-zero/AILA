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

from aila.platform.contracts import utc_now

__all__ = [
    "PromptAliasChangeRecord",
    "PromptAliasRecord",
    "PromptVersionRecord",
]


class PromptVersionRecord(SQLModel, table=True):
    """One immutable prompt version -- now the immutable agent-config bundle
    (RFC-09 Amendment 2). ``body`` is the prompt text; ``roster_json`` is the
    persona roster, ``routing_json`` the per-task_type model routing, and
    ``exemplars_json`` the exemplars folded into the resolved body. All three
    default to their empty representation so a prompt-only register (every
    caller that predates the amendment) produces a byte-identical
    prompt-only bundle. ``content_hash`` is the sha256 of the canonical
    ``{body, roster, routing, exemplars}`` json -- the SAME body with
    different extras is a different bundle version, and the same bundle
    re-registered dedups to the existing row via the (key, content_hash)
    uniqueness. Cost / seal rows identify the bundle by
    ``prompt_version`` + ``prompt_content_hash`` -- no separate bundle id
    column is stored."""

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
    # Bundle extras (RFC-09 Amendment 2). Empty defaults keep every
    # pre-amendment register byte-identical to today: a prompt-only
    # bundle carries ``{}`` / ``{}`` / ``[]`` in these columns.
    roster_json: str = Field(default="{}", sa_type=Text)
    routing_json: str = Field(default="{}", sa_type=Text)
    exemplars_json: str = Field(default="[]", sa_type=Text)
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
