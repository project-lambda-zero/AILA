"""Encrypted evidence store: round-trip, authorisation order, tamper and failure paths."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel.ext.asyncio.session import AsyncSession

from aila.platform.services.evidence_store import EvidenceStore, EvidenceStoreError
from aila.storage.secrets import MasterKeyMaterial, MasterKeyProvider

_CHUNK = 16
_CANARY = b"EVIDENCE-CANARY-0123456789-ABCDEFGHIJ"


@dataclass
class _Settings:
    secret_keyring_path: Path
    secret_active_key_version: str


class _Result:
    def __init__(self, record: object | None) -> None:
        self._record = record

    def first(self) -> object | None:
        return self._record


class _FakeSession:
    """Holds staged records; reads return the most recently added record.

    Tests store one artifact per session, so the ``where`` clause is not inspected.
    """

    def __init__(self, *, fail_flush: bool = False) -> None:
        self.added: list[object] = []
        self._fail_flush = fail_flush

    def add(self, record: object) -> None:
        self.added.append(record)

    async def flush(self) -> None:
        if self._fail_flush:
            raise SQLAlchemyError("flush rejected")

    async def exec(self, _statement: object) -> _Result:
        return _Result(self.added[-1] if self.added else None)


class _StaticKeys:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def active_key(self) -> MasterKeyMaterial:
        return MasterKeyMaterial(version="v1", key_bytes=self._key)

    def key_for_version(self, version: str) -> bytes:
        assert version == "v1"
        return self._key


class _BrokenKeys:
    def active_key(self) -> MasterKeyMaterial:
        raise RuntimeError("keyring unavailable")

    def key_for_version(self, _version: str) -> bytes:
        raise RuntimeError("keyring unavailable")


def _session(*, fail_flush: bool = False) -> AsyncSession:
    return cast(AsyncSession, _FakeSession(fail_flush=fail_flush))


def _store(root: Path, *, keys: object | None = None) -> EvidenceStore:
    provider = keys if keys is not None else _StaticKeys(os.urandom(32))
    return EvidenceStore(
        _Settings(secret_keyring_path=root / "keyring.json", secret_active_key_version="v1"),
        root_dir=root,
        chunk_bytes=_CHUNK,
        max_artifact_bytes=1 << 20,
        key_provider=cast(MasterKeyProvider, provider),
    )


async def _append(store: EvidenceStore, session: AsyncSession, data: bytes):
    return await store.append(
        session,
        team_id="team-a",
        module_id="vr",
        owner_id="owner-1",
        stream="stdout",
        data=data,
    )


@pytest.mark.parametrize("size", [0, 1, _CHUNK - 1, _CHUNK, _CHUNK + 1, 3 * _CHUNK + 5])
async def test_round_trip_across_chunk_boundaries(tmp_path: Path, size: int) -> None:
    store = _store(tmp_path / "evidence")
    data = os.urandom(size)
    session = _session()

    chunk = await _append(store, session, data)
    read_back = await store.read(session, artifact_id=chunk.artifact_id, module_id="vr", team_id="team-a")

    assert read_back == data
    assert chunk.length == size
    assert chunk.offset == 0


async def test_plaintext_never_reaches_disk(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    store = _store(root)

    await _append(store, _session(), _CANARY * 4)

    blobs = [path.read_bytes() for path in root.iterdir()]
    assert blobs, "append must write a ciphertext file"
    assert all(_CANARY not in blob for blob in blobs)


async def test_read_rejects_other_module_before_opening_file(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    store = _store(root)
    session = _session()
    chunk = await _append(store, session, b"payload")
    for path in root.iterdir():
        path.unlink()

    with pytest.raises(EvidenceStoreError, match="not accessible"):
        await store.read(session, artifact_id=chunk.artifact_id, module_id="malware", team_id="team-a")


async def test_read_rejects_other_team_before_opening_file(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    store = _store(root)
    session = _session()
    chunk = await _append(store, session, b"payload")
    for path in root.iterdir():
        path.unlink()

    with pytest.raises(EvidenceStoreError, match="not accessible"):
        await store.read(session, artifact_id=chunk.artifact_id, module_id="vr", team_id="team-b")


async def test_tampered_ciphertext_fails_authentication(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    store = _store(root)
    session = _session()
    chunk = await _append(store, session, b"0123456789abcdefXYZ")
    blob_path = root / f"{chunk.artifact_id}.bin"
    tampered = bytearray(blob_path.read_bytes())
    tampered[-1] ^= 0x01
    blob_path.write_bytes(bytes(tampered))

    with pytest.raises(EvidenceStoreError, match="failed authentication"):
        await store.read(session, artifact_id=chunk.artifact_id, module_id="vr", team_id="team-a")


async def test_unwritable_root_raises_store_error(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.write_bytes(b"not a directory")
    store = _store(root)

    with pytest.raises(EvidenceStoreError, match="not writable"):
        await _append(store, _session(), b"payload")
    with pytest.raises(EvidenceStoreError, match="not writable"):
        await store.health()


async def test_key_provider_failure_raises_store_error(tmp_path: Path) -> None:
    store = _store(tmp_path / "evidence", keys=_BrokenKeys())

    with pytest.raises(EvidenceStoreError, match="encryption key unavailable"):
        await _append(store, _session(), b"payload")
    with pytest.raises(EvidenceStoreError, match="encryption key unavailable"):
        await store.health()


async def test_failed_flush_leaves_no_artifact_behind(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    store = _store(root)

    with pytest.raises(SQLAlchemyError):
        await _append(store, _session(fail_flush=True), b"payload")

    assert list(root.iterdir()) == []


async def test_health_passes_and_leaves_no_probe_file(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    store = _store(root)

    await store.health()

    assert list(root.iterdir()) == []
