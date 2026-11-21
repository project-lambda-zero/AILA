"""Encrypted, file-backed evidence store.

Evidence bytes are sealed in fixed-size AES-256-GCM frames with the active
master key and written to ``<root>/<artifact_id>.bin``. The database holds
only metadata (``EvidenceArtifactRecord``): plaintext never reaches disk or
PostgreSQL. Each frame's associated data binds artifact, module, owner,
stream, byte offset, frame index and key version, so a ciphertext cannot be
moved between artifacts or streams without failing authentication.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from ...storage.evidence_models import EvidenceArtifactRecord
from ...storage.secrets import MasterKeyMaterial, MasterKeyProvider

__all__ = [
    "EvidenceChunk",
    "EvidenceStore",
    "EvidenceStoreError",
    "EvidenceStoreSettings",
]

_log = logging.getLogger(__name__)

_NONCE_BYTES = 12
_FRAME_HEADER = struct.Struct(">I")  # ciphertext length prefix per frame
_ARTIFACT_EXTENSION = ".bin"
_TEMP_EXTENSION = ".tmp"


class EvidenceStoreError(RuntimeError):
    """Raised when evidence cannot be stored, read, or authenticated."""


class EvidenceStoreSettings(Protocol):
    """Platform settings the store needs (satisfied by ``PlatformSettings``)."""

    secret_keyring_path: Path
    secret_active_key_version: str


@dataclass(frozen=True, slots=True)
class EvidenceChunk:
    """Metadata for one appended evidence stream segment."""

    artifact_id: str
    owner_id: str
    stream: str
    offset: int
    length: int
    sha256: str


def _frame_aad(
    *,
    artifact_id: str,
    module_id: str,
    owner_id: str,
    stream: str,
    byte_offset: int,
    frame_index: int,
    key_version: str,
) -> bytes:
    parts = (artifact_id, module_id, owner_id, stream, key_version)
    header = "\x1f".join(parts).encode("utf-8")
    return header + b"\x1e" + struct.pack(">QQ", byte_offset, frame_index)


class EvidenceStore:
    """Seals evidence bytes to disk and authorises reads by artifact identity."""

    def __init__(
        self,
        settings: EvidenceStoreSettings,
        *,
        root_dir: Path,
        chunk_bytes: int,
        max_artifact_bytes: int,
        key_provider: MasterKeyProvider | None = None,
    ) -> None:
        if chunk_bytes <= 0:
            raise EvidenceStoreError("evidence chunk_bytes must be positive.")
        if max_artifact_bytes <= 0:
            raise EvidenceStoreError("evidence max_artifact_bytes must be positive.")
        self._root = root_dir
        self._chunk_bytes = chunk_bytes
        self._max_artifact_bytes = max_artifact_bytes
        self._key_provider = key_provider or MasterKeyProvider(
            settings.secret_keyring_path,
            settings.secret_active_key_version,
        )

    @property
    def root_dir(self) -> Path:
        return self._root

    async def append(
        self,
        session: AsyncSession,
        *,
        team_id: str | None,
        module_id: str,
        owner_id: str,
        stream: str,
        data: bytes,
    ) -> EvidenceChunk:
        """Seal ``data`` to a new artifact and stage its metadata in ``session``.

        The session is flushed but not committed: the caller's transaction owns
        durability so the metadata row and any event row commit together.
        """
        if len(data) > self._max_artifact_bytes:
            raise EvidenceStoreError(
                f"evidence payload is {len(data)} bytes; limit is {self._max_artifact_bytes}."
            )
        active = self._active_material()
        key = active.key_bytes
        key_version = active.version
        artifact_id = str(uuid4())
        sha256 = hashlib.sha256(data).hexdigest()
        cipher = AESGCM(key)

        frames: list[bytes] = []
        for frame_index, start in enumerate(range(0, len(data), self._chunk_bytes)):
            plaintext = data[start : start + self._chunk_bytes]
            nonce = secrets.token_bytes(_NONCE_BYTES)
            aad = _frame_aad(
                artifact_id=artifact_id,
                module_id=module_id,
                owner_id=owner_id,
                stream=stream,
                byte_offset=start,
                frame_index=frame_index,
                key_version=key_version,
            )
            sealed = cipher.encrypt(nonce, plaintext, aad)
            frames.append(nonce + _FRAME_HEADER.pack(len(sealed)) + sealed)
        blob = b"".join(frames)

        try:
            self._root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise EvidenceStoreError(f"evidence root {self._root} is not writable: {exc}") from exc
        final_path = self._root / f"{artifact_id}{_ARTIFACT_EXTENSION}"
        temp_path = self._root / f"{artifact_id}{_TEMP_EXTENSION}"
        storage_path = final_path.name
        self._write_atomic(temp_path, final_path, blob)

        record = EvidenceArtifactRecord(
            artifact_id=artifact_id,
            module_id=module_id,
            owner_id=owner_id,
            stream=stream,
            byte_offset=0,
            length=len(data),
            sha256=sha256,
            storage_path=storage_path,
            key_version=key_version,
            chunk_size=self._chunk_bytes,
            encrypted_length=len(blob),
        )
        record.team_id = team_id
        session.add(record)
        try:
            await session.flush()
        except SQLAlchemyError:
            self._discard(final_path)
            raise
        return EvidenceChunk(
            artifact_id=artifact_id,
            owner_id=owner_id,
            stream=stream,
            offset=0,
            length=len(data),
            sha256=sha256,
        )

    async def read(
        self,
        session: AsyncSession,
        *,
        artifact_id: str,
        module_id: str,
        team_id: str | None,
    ) -> bytes:
        """Return the plaintext for ``artifact_id`` if module and team match.

        Authorisation is checked against the metadata row before the file is
        opened, so a mismatch never triggers decryption.
        """
        record = (
            await session.exec(
                select(EvidenceArtifactRecord).where(col(EvidenceArtifactRecord.artifact_id) == artifact_id)
            )
        ).first()
        if record is None:
            raise EvidenceStoreError(f"evidence artifact {artifact_id} not found.")
        if record.module_id != module_id or record.team_id != team_id:
            raise EvidenceStoreError(f"evidence artifact {artifact_id} is not accessible to this caller.")

        path = self._root / record.storage_path
        try:
            blob = path.read_bytes()
        except OSError as exc:
            raise EvidenceStoreError(f"evidence artifact {artifact_id} is unreadable: {exc}") from exc
        if len(blob) != record.encrypted_length:
            raise EvidenceStoreError(f"evidence artifact {artifact_id} has an unexpected size on disk.")

        key = self._key_for(record.key_version)
        cipher = AESGCM(key)
        plaintext_parts: list[bytes] = []
        cursor = 0
        byte_offset = 0
        frame_index = 0
        while cursor < len(blob):
            header_end = cursor + _NONCE_BYTES + _FRAME_HEADER.size
            if header_end > len(blob):
                raise EvidenceStoreError(f"evidence artifact {artifact_id} is truncated.")
            nonce = blob[cursor : cursor + _NONCE_BYTES]
            (sealed_len,) = _FRAME_HEADER.unpack(blob[cursor + _NONCE_BYTES : header_end])
            sealed_end = header_end + sealed_len
            if sealed_end > len(blob):
                raise EvidenceStoreError(f"evidence artifact {artifact_id} is truncated.")
            aad = _frame_aad(
                artifact_id=record.artifact_id,
                module_id=record.module_id,
                owner_id=record.owner_id,
                stream=record.stream,
                byte_offset=byte_offset,
                frame_index=frame_index,
                key_version=record.key_version,
            )
            try:
                plain = cipher.decrypt(nonce, blob[header_end:sealed_end], aad)
            except InvalidTag as exc:
                raise EvidenceStoreError(f"evidence artifact {artifact_id} failed authentication.") from exc
            plaintext_parts.append(plain)
            byte_offset += len(plain)
            frame_index += 1
            cursor = sealed_end

        plaintext = b"".join(plaintext_parts)
        if len(plaintext) != record.length:
            raise EvidenceStoreError(f"evidence artifact {artifact_id} length mismatch.")
        if hashlib.sha256(plaintext).hexdigest() != record.sha256:
            raise EvidenceStoreError(f"evidence artifact {artifact_id} failed SHA-256 verification.")
        return plaintext

    async def health(self) -> None:
        """Raise ``EvidenceStoreError`` unless the root is writable and the key loads."""
        try:
            self._root.mkdir(parents=True, exist_ok=True)
            probe = self._root / f".health-{uuid4()}{_TEMP_EXTENSION}"
            with probe.open("xb") as handle:
                handle.write(b"ok")
                handle.flush()
                os.fsync(handle.fileno())
            probe.unlink()
        except OSError as exc:
            raise EvidenceStoreError(f"evidence root {self._root} is not writable: {exc}") from exc
        self._active_material()

    def _active_material(self) -> MasterKeyMaterial:
        try:
            return self._key_provider.active_key()
        except RuntimeError as exc:
            raise EvidenceStoreError(f"evidence encryption key unavailable: {exc}") from exc

    def _key_for(self, version: str) -> bytes:
        try:
            return self._key_provider.key_for_version(version)
        except RuntimeError as exc:
            raise EvidenceStoreError(f"evidence decryption key {version} unavailable: {exc}") from exc

    def _write_atomic(self, temp_path: Path, final_path: Path, blob: bytes) -> None:
        try:
            with temp_path.open("xb") as handle:
                handle.write(blob)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, final_path)
        except OSError as exc:
            self._discard(temp_path)
            raise EvidenceStoreError(f"evidence write to {final_path.name} failed: {exc}") from exc

    @staticmethod
    def _discard(path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            _log.warning("could not remove evidence file %s after failed write", path.name)
