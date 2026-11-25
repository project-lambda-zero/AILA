"""Content-addressed, file-backed plaintext evidence snapshots.

The store treats every object as immutable bytes. Database indexing and
finding/replay/retest/report references bind to the returned descriptor;
this module deliberately has no database or module ownership dependencies.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import BinaryIO, TypeAlias

from .runtime import run_blocking_io

__all__ = [
    "EvidenceDescriptor",
    "EvidenceStorageProfile",
    "PlaintextEvidenceCorruptError",
    "PlaintextEvidenceNotFoundError",
    "PlaintextEvidenceRangeError",
    "PlaintextEvidenceReferencedError",
    "PlaintextEvidenceStore",
    "PlaintextEvidenceStoreError",
    "PlaintextEvidenceTooLargeError",
    "ReferenceCountCallback",
]

_log = logging.getLogger(__name__)

_DEFAULT_MEDIA_TYPE = "application/octet-stream"
_IO_CHUNK_BYTES = 1024 * 1024
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class EvidenceStorageProfile(StrEnum):
    """Storage confidentiality profiles shared by evidence callers."""

    PLAINTEXT = "plaintext"
    SEALED = "sealed"


@dataclass(frozen=True, slots=True)
class EvidenceDescriptor:
    """Immutable metadata required to index and bind one evidence version."""

    profile: EvidenceStorageProfile
    storage_key: str
    byte_length: int
    media_type: str
    sha256: str


class PlaintextEvidenceStoreError(RuntimeError):
    """Raised when plaintext evidence cannot be safely stored or consumed."""


class PlaintextEvidenceNotFoundError(PlaintextEvidenceStoreError):
    """Raised when the addressed evidence object does not exist."""


class PlaintextEvidenceCorruptError(PlaintextEvidenceStoreError):
    """Raised when on-disk bytes do not match their immutable descriptor."""


class PlaintextEvidenceTooLargeError(PlaintextEvidenceStoreError):
    """Raised when an input or stored object exceeds the configured bound."""


class PlaintextEvidenceRangeError(PlaintextEvidenceStoreError, ValueError):
    """Raised when a requested byte range is outside the evidence object."""


class PlaintextEvidenceReferencedError(PlaintextEvidenceStoreError):
    """Raised when retention would delete an object that still has references."""


ReferenceCountCallback: TypeAlias = Callable[[str], int]


class PlaintextEvidenceStore:
    """Store verified plaintext objects beneath ``blobs/<prefix>/<sha256>``.

    ``reference_count`` is authoritative when supplied: deletion proceeds only
    when it returns zero. Otherwise the store requires the configured
    ``retention_token`` on every deletion. There is intentionally no unsafe
    unauthenticated garbage-collection mode.
    """

    def __init__(
        self,
        *,
        root_dir: Path,
        max_artifact_bytes: int,
        reference_count: ReferenceCountCallback | None = None,
        retention_token: str | None = None,
    ) -> None:
        if isinstance(max_artifact_bytes, bool) or not isinstance(max_artifact_bytes, int):
            raise PlaintextEvidenceStoreError("evidence max_artifact_bytes must be an integer.")
        if max_artifact_bytes <= 0:
            raise PlaintextEvidenceStoreError("evidence max_artifact_bytes must be positive.")
        if reference_count is not None and not callable(reference_count):
            raise PlaintextEvidenceStoreError("evidence reference_count must be callable.")
        if retention_token is not None and not retention_token:
            raise PlaintextEvidenceStoreError("evidence retention_token must not be empty.")
        try:
            self._root = root_dir.resolve()
        except OSError as exc:
            raise PlaintextEvidenceStoreError(f"evidence root {root_dir} is invalid: {exc}") from exc
        self._max_artifact_bytes = max_artifact_bytes
        self._reference_count = reference_count
        self._retention_token = retention_token

    @property
    def root_dir(self) -> Path:
        return self._root

    @property
    def max_artifact_bytes(self) -> int:
        return self._max_artifact_bytes

    def put(
        self,
        data: bytes,
        *,
        media_type: str = _DEFAULT_MEDIA_TYPE,
    ) -> EvidenceDescriptor:
        """Atomically persist ``data`` and return its content descriptor."""
        if not isinstance(data, bytes):
            raise PlaintextEvidenceStoreError("plaintext evidence data must be bytes.")
        normalized_media_type = self._normalize_media_type(media_type)
        if len(data) > self._max_artifact_bytes:
            raise PlaintextEvidenceTooLargeError(
                f"evidence payload is {len(data)} bytes; limit is {self._max_artifact_bytes}."
            )
        digest = hashlib.sha256(data).hexdigest()
        descriptor = self._descriptor(digest, len(data), normalized_media_type)
        final_path = self._path_for_digest(digest)
        temporary_path: Path | None = None
        try:
            final_path.parent.mkdir(parents=True, exist_ok=True)
            if self._deduplicate(descriptor):
                return descriptor
            descriptor_fd, temporary_name = tempfile.mkstemp(
                dir=final_path.parent,
                prefix=f".{digest}.",
                suffix=".tmp",
            )
            temporary_path = Path(temporary_name)
            with os.fdopen(descriptor_fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            if self._deduplicate(descriptor):
                return descriptor
            os.replace(temporary_path, final_path)
        except OSError as exc:
            raise PlaintextEvidenceStoreError(
                f"evidence write for {digest} failed: {exc}"
            ) from exc
        finally:
            if temporary_path is not None:
                self._discard(temporary_path)
        return descriptor

    async def put_async(
        self,
        data: bytes,
        *,
        media_type: str = _DEFAULT_MEDIA_TYPE,
    ) -> EvidenceDescriptor:
        """Async companion to :meth:`put`."""
        return await run_blocking_io(self.put, data, media_type=media_type)

    def verify(self, descriptor: EvidenceDescriptor) -> EvidenceDescriptor:
        """Verify the complete object and return its immutable descriptor."""
        with self._open_verified(descriptor):
            pass
        return descriptor

    async def verify_async(self, descriptor: EvidenceDescriptor) -> EvidenceDescriptor:
        """Async companion to :meth:`verify`."""
        return await run_blocking_io(self.verify, descriptor)

    def read(self, descriptor: EvidenceDescriptor) -> bytes:
        """Return the complete object after size and SHA-256 verification."""
        path = self._path_for_descriptor(descriptor)
        with self._open_file(path, descriptor) as handle:
            try:
                data = handle.read()
            except OSError as exc:
                raise PlaintextEvidenceStoreError(
                    f"evidence object {descriptor.sha256} is unreadable: {exc}"
                ) from exc
        self._verify_bytes(descriptor, data)
        return data

    async def read_async(self, descriptor: EvidenceDescriptor) -> bytes:
        """Async companion to :meth:`read`."""
        return await run_blocking_io(self.read, descriptor)

    def open(self, descriptor: EvidenceDescriptor) -> BinaryIO:
        """Return a binary reader positioned at zero after full verification.

        The caller owns the returned handle and must close it. The same open
        file description is used for verification and subsequent reads.
        """
        return self._open_verified(descriptor)

    async def open_async(self, descriptor: EvidenceDescriptor) -> BinaryIO:
        """Async companion to :meth:`open`; the returned reader is synchronous."""
        return await run_blocking_io(self.open, descriptor)

    def read_range(
        self,
        descriptor: EvidenceDescriptor,
        *,
        offset: int,
        length: int,
    ) -> bytes:
        """Return exactly ``length`` bytes at ``offset`` after verification."""
        self._validate_range(descriptor, offset, length)
        with self._open_verified(descriptor) as handle:
            try:
                handle.seek(offset)
                data = handle.read(length)
            except OSError as exc:
                raise PlaintextEvidenceStoreError(
                    f"evidence range read for {descriptor.sha256} failed: {exc}"
                ) from exc
        if len(data) != length:
            raise PlaintextEvidenceCorruptError(
                f"evidence object {descriptor.sha256} changed during range read."
            )
        return data

    async def read_range_async(
        self,
        descriptor: EvidenceDescriptor,
        *,
        offset: int,
        length: int,
    ) -> bytes:
        """Async companion to :meth:`read_range`."""
        return await run_blocking_io(self.read_range, descriptor, offset=offset, length=length)

    def export(self, descriptor: EvidenceDescriptor, destination: Path) -> Path:
        """Atomically export a verified snapshot without executing its bytes."""
        source_path = self._path_for_descriptor(descriptor)
        destination = Path(destination)
        try:
            if destination.resolve() == source_path.resolve():
                raise PlaintextEvidenceStoreError("evidence export cannot overwrite its source object.")
        except OSError as exc:
            raise PlaintextEvidenceStoreError(f"evidence export destination is invalid: {exc}") from exc

        temporary_path: Path | None = None
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor_fd, temporary_name = tempfile.mkstemp(
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
            )
            temporary_path = Path(temporary_name)
            copied = hashlib.sha256()
            copied_length = 0
            with os.fdopen(descriptor_fd, "wb") as target, self._open_verified(descriptor) as source:
                while True:
                    chunk = source.read(_IO_CHUNK_BYTES)
                    if not chunk:
                        break
                    copied_length += len(chunk)
                    if copied_length > self._max_artifact_bytes:
                        raise PlaintextEvidenceTooLargeError(
                            f"evidence object {descriptor.sha256} exceeds the configured limit."
                        )
                    copied.update(chunk)
                    target.write(chunk)
                target.flush()
                os.fsync(target.fileno())
            if copied_length != descriptor.byte_length:
                raise PlaintextEvidenceCorruptError(
                    f"evidence object {descriptor.sha256} length mismatch during export."
                )
            if copied.hexdigest() != descriptor.sha256:
                raise PlaintextEvidenceCorruptError(
                    f"evidence object {descriptor.sha256} failed SHA-256 verification during export."
                )
            os.replace(temporary_path, destination)
        except OSError as exc:
            raise PlaintextEvidenceStoreError(
                f"evidence export for {descriptor.sha256} failed: {exc}"
            ) from exc
        finally:
            if temporary_path is not None:
                self._discard(temporary_path)
        return destination

    async def export_async(self, descriptor: EvidenceDescriptor, destination: Path) -> Path:
        """Async companion to :meth:`export`."""
        return await run_blocking_io(self.export, descriptor, destination)

    def delete(
        self,
        descriptor: EvidenceDescriptor,
        *,
        reference_token: str | None = None,
    ) -> None:
        """Delete an unreferenced object, failing closed on reference safety."""
        path = self._path_for_descriptor(descriptor)
        self._assert_unreferenced(descriptor, reference_token)
        try:
            path.unlink()
        except FileNotFoundError as exc:
            raise PlaintextEvidenceNotFoundError(
                f"evidence object {descriptor.sha256} not found."
            ) from exc
        except OSError as exc:
            raise PlaintextEvidenceStoreError(
                f"evidence deletion for {descriptor.sha256} failed: {exc}"
            ) from exc

    async def delete_async(
        self,
        descriptor: EvidenceDescriptor,
        *,
        reference_token: str | None = None,
    ) -> None:
        """Async companion to :meth:`delete`."""
        await run_blocking_io(self.delete, descriptor, reference_token=reference_token)

    def _deduplicate(self, descriptor: EvidenceDescriptor) -> bool:
        try:
            with self._open_verified(descriptor):
                pass
        except PlaintextEvidenceNotFoundError:
            return False
        return True

    def _descriptor(self, digest: str, byte_length: int, media_type: str) -> EvidenceDescriptor:
        return EvidenceDescriptor(
            profile=EvidenceStorageProfile.PLAINTEXT,
            storage_key=self._storage_key(digest),
            byte_length=byte_length,
            media_type=media_type,
            sha256=digest,
        )

    @staticmethod
    def _storage_key(digest: str) -> str:
        return str(PurePosixPath("blobs") / digest[:2] / digest)

    def _path_for_descriptor(self, descriptor: EvidenceDescriptor) -> Path:
        if not isinstance(descriptor, EvidenceDescriptor):
            raise PlaintextEvidenceStoreError("plaintext evidence requires an EvidenceDescriptor.")
        if descriptor.profile is not EvidenceStorageProfile.PLAINTEXT:
            raise PlaintextEvidenceStoreError("plaintext evidence store requires the plaintext profile.")
        if isinstance(descriptor.byte_length, bool) or not isinstance(descriptor.byte_length, int):
            raise PlaintextEvidenceStoreError("evidence byte_length must be an integer.")
        if descriptor.byte_length < 0:
            raise PlaintextEvidenceStoreError("evidence byte_length must not be negative.")
        if descriptor.byte_length > self._max_artifact_bytes:
            raise PlaintextEvidenceTooLargeError(
                f"evidence descriptor is {descriptor.byte_length} bytes; "
                f"limit is {self._max_artifact_bytes}."
            )
        if descriptor.media_type != self._normalize_media_type(descriptor.media_type):
            raise PlaintextEvidenceStoreError("evidence media_type must be normalized.")
        path = self._path_for_digest(descriptor.sha256)
        if descriptor.storage_key != self._storage_key(descriptor.sha256):
            raise PlaintextEvidenceStoreError("evidence storage_key does not match its SHA-256.")
        return path

    def _path_for_digest(self, digest: str) -> Path:
        if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
            raise PlaintextEvidenceStoreError("evidence SHA-256 must be 64 lowercase hexadecimal characters.")
        relative = PurePosixPath(self._storage_key(digest))
        candidate = self._root.joinpath(*relative.parts)
        expected = self._root / "blobs" / digest[:2] / digest
        try:
            resolved = candidate.resolve(strict=False)
        except OSError as exc:
            raise PlaintextEvidenceStoreError(f"evidence path for {digest} is invalid: {exc}") from exc
        if resolved != expected:
            raise PlaintextEvidenceStoreError("evidence storage path escapes the content-addressed root.")
        return candidate

    def _open_file(self, path: Path, descriptor: EvidenceDescriptor) -> BinaryIO:
        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor_fd = os.open(path, flags)
            handle = os.fdopen(descriptor_fd, "rb")
        except FileNotFoundError as exc:
            raise PlaintextEvidenceNotFoundError(
                f"evidence object {descriptor.sha256} not found."
            ) from exc
        except OSError as exc:
            raise PlaintextEvidenceStoreError(
                f"evidence object {descriptor.sha256} is unreadable: {exc}"
            ) from exc
        try:
            actual_length = os.fstat(handle.fileno()).st_size
            if actual_length > self._max_artifact_bytes:
                raise PlaintextEvidenceTooLargeError(
                    f"evidence object {descriptor.sha256} is {actual_length} bytes; "
                    f"limit is {self._max_artifact_bytes}."
                )
            if actual_length != descriptor.byte_length:
                raise PlaintextEvidenceCorruptError(
                    f"evidence object {descriptor.sha256} has an unexpected size on disk."
                )
        except OSError as exc:
            handle.close()
            raise PlaintextEvidenceStoreError(
                f"evidence object {descriptor.sha256} could not be inspected: {exc}"
            ) from exc
        except BaseException:
            # Always release the descriptor; the original failure propagates unchanged.
            handle.close()
            raise
        return handle

    def _open_verified(self, descriptor: EvidenceDescriptor) -> BinaryIO:
        path = self._path_for_descriptor(descriptor)
        handle = self._open_file(path, descriptor)
        try:
            digest = hashlib.sha256()
            verified_length = 0
            while True:
                chunk = handle.read(_IO_CHUNK_BYTES)
                if not chunk:
                    break
                verified_length += len(chunk)
                digest.update(chunk)
            if verified_length != descriptor.byte_length:
                raise PlaintextEvidenceCorruptError(
                    f"evidence object {descriptor.sha256} length mismatch."
                )
            if digest.hexdigest() != descriptor.sha256:
                raise PlaintextEvidenceCorruptError(
                    f"evidence object {descriptor.sha256} failed SHA-256 verification."
                )
            handle.seek(0)
        except OSError as exc:
            handle.close()
            raise PlaintextEvidenceStoreError(
                f"evidence object {descriptor.sha256} is unreadable: {exc}"
            ) from exc
        except BaseException:
            # Always release the descriptor; the original failure propagates unchanged.
            handle.close()
            raise
        return handle

    def _verify_bytes(self, descriptor: EvidenceDescriptor, data: bytes) -> None:
        if len(data) > self._max_artifact_bytes:
            raise PlaintextEvidenceTooLargeError(
                f"evidence object {descriptor.sha256} exceeds the configured limit."
            )
        if len(data) != descriptor.byte_length:
            raise PlaintextEvidenceCorruptError(
                f"evidence object {descriptor.sha256} length mismatch."
            )
        if hashlib.sha256(data).hexdigest() != descriptor.sha256:
            raise PlaintextEvidenceCorruptError(
                f"evidence object {descriptor.sha256} failed SHA-256 verification."
            )

    def _validate_range(self, descriptor: EvidenceDescriptor, offset: int, length: int) -> None:
        self._path_for_descriptor(descriptor)
        for name, value in (("offset", offset), ("length", length)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise PlaintextEvidenceRangeError(f"evidence range {name} must be a non-negative integer.")
        if offset > descriptor.byte_length or offset + length > descriptor.byte_length:
            raise PlaintextEvidenceRangeError(
                f"evidence range [{offset}, {offset + length}) exceeds object length {descriptor.byte_length}."
            )

    def _assert_unreferenced(
        self,
        descriptor: EvidenceDescriptor,
        reference_token: str | None,
    ) -> None:
        if self._reference_count is not None:
            references = self._reference_count(descriptor.sha256)
            if isinstance(references, bool) or not isinstance(references, int) or references < 0:
                raise PlaintextEvidenceStoreError("evidence reference_count returned an invalid count.")
            if references:
                raise PlaintextEvidenceReferencedError(
                    f"evidence object {descriptor.sha256} still has {references} references."
                )
            return
        if not isinstance(reference_token, str) or self._retention_token is None:
            raise PlaintextEvidenceStoreError(
                "evidence deletion requires a zero reference count or a valid retention token."
            )
        if not hmac.compare_digest(
            reference_token.encode("utf-8"),
            self._retention_token.encode("utf-8"),
        ):
            raise PlaintextEvidenceStoreError("evidence retention token is invalid.")

    @staticmethod
    def _normalize_media_type(media_type: str) -> str:
        if not isinstance(media_type, str):
            raise PlaintextEvidenceStoreError("evidence media_type must be a string.")
        normalized = media_type.strip()
        if not normalized or any(ord(character) < 32 or ord(character) == 127 for character in normalized):
            raise PlaintextEvidenceStoreError("evidence media_type must be non-empty and contain no controls.")
        return normalized

    @staticmethod
    def _discard(path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            _log.warning("could not remove plaintext evidence staging file %s", path.name)
