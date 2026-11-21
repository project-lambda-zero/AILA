"""Platform-owned metadata for encrypted evidence artifacts.

Only artifact descriptors live in PostgreSQL. Evidence bytes are encrypted and
stored by :mod:`aila.platform.services.evidence_store` on the configured file
or object-backed filesystem; plaintext content is never a database field.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Column, DateTime, Index, String
from sqlmodel import Field, SQLModel

from ..platform.contracts._common import utc_now
from .mixins import TeamScopedMixin

__all__ = ["EvidenceArtifactRecord"]


class EvidenceArtifactRecord(TeamScopedMixin, SQLModel, table=True):
    """Descriptor for one encrypted chunk appended to an evidence stream."""

    __tablename__ = "evidence_artifact"
    __table_args__ = (
        Index(
            "ix_evidence_artifact_stream_offset",
            "module_id",
            "owner_id",
            "stream",
            "byte_offset",
        ),
    )

    artifact_id: str = Field(primary_key=True, max_length=36)
    module_id: str = Field(sa_column=Column(String(128), nullable=False, index=True))
    owner_id: str = Field(sa_column=Column(String(128), nullable=False, index=True))
    stream: str = Field(sa_column=Column(String(256), nullable=False, index=True))
    byte_offset: int = Field(sa_type=BigInteger)
    length: int = Field(sa_type=BigInteger)
    sha256: str = Field(sa_column=Column(String(64), nullable=False))
    storage_path: str = Field(sa_column=Column(String(512), nullable=False, unique=True))
    key_version: str = Field(sa_column=Column(String(128), nullable=False))
    chunk_size: int = Field(sa_type=BigInteger)
    encrypted_length: int = Field(sa_type=BigInteger)
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
    )
