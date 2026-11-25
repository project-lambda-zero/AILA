from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from aila.platform.services.plaintext_evidence import (
    EvidenceDescriptor,
    EvidenceStorageProfile,
    PlaintextEvidenceCorruptError,
    PlaintextEvidenceNotFoundError,
    PlaintextEvidenceRangeError,
    PlaintextEvidenceReferencedError,
    PlaintextEvidenceStore,
    PlaintextEvidenceStoreError,
    PlaintextEvidenceTooLargeError,
)


def _store(tmp_path: Path, max_artifact_bytes: int = 1024, **kwargs: object) -> PlaintextEvidenceStore:
    return PlaintextEvidenceStore(
        root_dir=tmp_path / "root",
        max_artifact_bytes=max_artifact_bytes,
        **kwargs,  # type: ignore[arg-type]
    )


def _object_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file())


def _object_path(store: PlaintextEvidenceStore, descriptor: EvidenceDescriptor) -> Path:
    return store.root_dir / descriptor.storage_key


def _tamper_same_length(path: Path) -> None:
    original = path.read_bytes()
    path.write_bytes(bytes([original[0] ^ 0xFF]) + original[1:])


def test_put_round_trip_and_content_addressed_layout(tmp_path: Path) -> None:
    store = _store(tmp_path)
    descriptor = store.put(b"evidence-bytes", media_type="text/plain; charset=utf-8")

    assert descriptor.profile is EvidenceStorageProfile.PLAINTEXT
    assert descriptor.byte_length == len(b"evidence-bytes")
    assert descriptor.media_type == "text/plain; charset=utf-8"
    assert descriptor.storage_key == f"blobs/{descriptor.sha256[:2]}/{descriptor.sha256}"
    assert _object_path(store, descriptor).read_bytes() == b"evidence-bytes"
    assert store.read(descriptor) == b"evidence-bytes"
    assert store.verify(descriptor) == descriptor


def test_put_empty_payload_round_trips(tmp_path: Path) -> None:
    store = _store(tmp_path)
    descriptor = store.put(b"")

    assert descriptor.byte_length == 0
    assert store.read(descriptor) == b""
    assert store.read_range(descriptor, offset=0, length=0) == b""


def test_put_identical_bytes_deduplicates_to_one_object(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = store.put(b"same")
    second = store.put(b"same")

    assert first == second
    files = _object_files(store.root_dir)
    assert files == [_object_path(store, first)]
    assert not any(path.name.endswith(".tmp") for path in files)


def test_put_rejects_non_bytes_payload(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(PlaintextEvidenceStoreError, match="must be bytes"):
        store.put("text")  # type: ignore[arg-type]


def test_put_rejects_payload_above_bound_and_allows_exact_bound(tmp_path: Path) -> None:
    store = _store(tmp_path, max_artifact_bytes=4)

    assert store.put(b"abcd").byte_length == 4
    with pytest.raises(PlaintextEvidenceTooLargeError, match="evidence payload is 5 bytes; limit is 4"):
        store.put(b"abcde")


def test_put_dedup_re_verifies_existing_object(tmp_path: Path) -> None:
    store = _store(tmp_path)
    descriptor = store.put(b"original")
    _tamper_same_length(_object_path(store, descriptor))

    with pytest.raises(PlaintextEvidenceCorruptError, match="failed SHA-256 verification"):
        store.put(b"original")


@pytest.mark.parametrize("target", ["replace", "fsync"])
def test_put_failure_leaves_no_object_or_staging_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    store = _store(tmp_path)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("injected failure")

    monkeypatch.setattr(os, target, fail)
    with pytest.raises(PlaintextEvidenceStoreError, match="write for"):
        store.put(b"partial")
    monkeypatch.undo()

    assert _object_files(store.root_dir) == []


def test_read_detects_same_length_tampering(tmp_path: Path) -> None:
    store = _store(tmp_path)
    descriptor = store.put(b"abcdef")
    _tamper_same_length(_object_path(store, descriptor))

    with pytest.raises(PlaintextEvidenceCorruptError, match="failed SHA-256 verification"):
        store.read(descriptor)
    with pytest.raises(PlaintextEvidenceCorruptError, match="failed SHA-256 verification"):
        store.verify(descriptor)
    with pytest.raises(PlaintextEvidenceCorruptError, match="failed SHA-256 verification"):
        store.open(descriptor)
    with pytest.raises(PlaintextEvidenceCorruptError, match="failed SHA-256 verification"):
        store.read_range(descriptor, offset=0, length=2)


def test_read_detects_truncated_object_size(tmp_path: Path) -> None:
    store = _store(tmp_path)
    descriptor = store.put(b"abcdef")
    _object_path(store, descriptor).write_bytes(b"abc")

    with pytest.raises(PlaintextEvidenceCorruptError, match="unexpected size on disk"):
        store.read(descriptor)


def test_read_rejects_oversize_object_on_disk(tmp_path: Path) -> None:
    store = _store(tmp_path, max_artifact_bytes=8)
    descriptor = store.put(b"abcd")
    _object_path(store, descriptor).write_bytes(b"x" * 20)

    with pytest.raises(PlaintextEvidenceTooLargeError, match="limit is 8"):
        store.read(descriptor)


def test_read_missing_object_raises_not_found(tmp_path: Path) -> None:
    store = _store(tmp_path)
    descriptor = store.put(b"gone")
    _object_path(store, descriptor).unlink()

    with pytest.raises(PlaintextEvidenceNotFoundError, match="not found"):
        store.read(descriptor)


def test_open_returns_verified_reader_at_position_zero(tmp_path: Path) -> None:
    store = _store(tmp_path)
    descriptor = store.put(b"stream-me")

    handle = store.open(descriptor)
    try:
        assert handle.tell() == 0
        assert handle.read() == b"stream-me"
    finally:
        handle.close()


def test_read_range_returns_exact_slice(tmp_path: Path) -> None:
    store = _store(tmp_path)
    descriptor = store.put(b"abcdef")

    assert store.read_range(descriptor, offset=2, length=3) == b"cde"
    assert store.read_range(descriptor, offset=6, length=0) == b""
    assert store.read_range(descriptor, offset=0, length=6) == b"abcdef"


@pytest.mark.parametrize(
    ("offset", "length", "message"),
    [
        (2, 5, "exceeds object length 4"),
        (5, 0, "exceeds object length 4"),
        (-1, 1, "must be a non-negative integer"),
        (0, -1, "must be a non-negative integer"),
        (True, 1, "must be a non-negative integer"),
        (0, False, "must be a non-negative integer"),
    ],
)
def test_read_range_rejects_invalid_bounds(
    tmp_path: Path,
    offset: int,
    length: int,
    message: str,
) -> None:
    store = _store(tmp_path)
    descriptor = store.put(b"abcd")

    with pytest.raises(PlaintextEvidenceRangeError, match=message):
        store.read_range(descriptor, offset=offset, length=length)


def test_descriptor_length_above_bound_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path, max_artifact_bytes=4)
    valid = store.put(b"abcd")
    oversized = replace(valid, byte_length=100)

    with pytest.raises(PlaintextEvidenceTooLargeError, match="limit is 4"):
        store.verify(oversized)


@pytest.mark.parametrize("bad_digest", ["../escape", "A" * 64, "a" * 63, "g" * 64])
def test_malformed_sha256_is_rejected(tmp_path: Path, bad_digest: str) -> None:
    store = _store(tmp_path)
    valid = store.put(b"abcd")

    with pytest.raises(PlaintextEvidenceStoreError, match="must be 64 lowercase hexadecimal"):
        store.read(replace(valid, sha256=bad_digest))


def test_storage_key_mismatch_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    valid = store.put(b"abcd")

    with pytest.raises(PlaintextEvidenceStoreError, match="storage_key does not match"):
        store.read(replace(valid, storage_key="blobs/zz/other"))


def test_sealed_profile_descriptor_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    valid = store.put(b"abcd")

    with pytest.raises(PlaintextEvidenceStoreError, match="requires the plaintext profile"):
        store.read(replace(valid, profile=EvidenceStorageProfile.SEALED))


def test_unnormalized_descriptor_media_type_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    valid = store.put(b"abcd")

    with pytest.raises(PlaintextEvidenceStoreError, match="must be normalized"):
        store.read(replace(valid, media_type=" text/plain"))


@pytest.mark.parametrize(
    ("media_type", "message"),
    [
        ("   ", "must be non-empty"),
        ("text\x00plain", "contain no controls"),
        ("text\x7fplain", "contain no controls"),
    ],
)
def test_media_type_validation(tmp_path: Path, media_type: str, message: str) -> None:
    store = _store(tmp_path)

    with pytest.raises(PlaintextEvidenceStoreError, match=message):
        store.put(b"x", media_type=media_type)


def test_media_type_is_stripped_and_defaults_to_octet_stream(tmp_path: Path) -> None:
    store = _store(tmp_path)

    assert store.put(b"x").media_type == "application/octet-stream"
    assert store.put(b"y", media_type="  text/csv  ").media_type == "text/csv"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_artifact_bytes": 0},
        {"max_artifact_bytes": True},
        {"max_artifact_bytes": 10, "reference_count": "not-callable"},
        {"max_artifact_bytes": 10, "retention_token": ""},
    ],
)
def test_constructor_validates_configuration(tmp_path: Path, kwargs: dict[str, object]) -> None:
    with pytest.raises(PlaintextEvidenceStoreError):
        PlaintextEvidenceStore(root_dir=tmp_path / "root", **kwargs)  # type: ignore[arg-type]


def test_export_writes_exact_bytes_without_staging_leftovers(tmp_path: Path) -> None:
    store = _store(tmp_path)
    descriptor = store.put(b"export-me")
    destination = tmp_path / "out" / "artifact.bin"

    assert store.export(descriptor, destination) == destination
    assert destination.read_bytes() == b"export-me"
    assert list(destination.parent.iterdir()) == [destination]


def test_export_refuses_to_overwrite_its_source_object(tmp_path: Path) -> None:
    store = _store(tmp_path)
    descriptor = store.put(b"source")

    with pytest.raises(PlaintextEvidenceStoreError, match="cannot overwrite its source object"):
        store.export(descriptor, _object_path(store, descriptor))
    assert _object_path(store, descriptor).read_bytes() == b"source"


def test_export_corrupt_source_publishes_nothing(tmp_path: Path) -> None:
    store = _store(tmp_path)
    descriptor = store.put(b"abcdef")
    _tamper_same_length(_object_path(store, descriptor))
    destination = tmp_path / "out" / "artifact.bin"

    with pytest.raises(PlaintextEvidenceCorruptError, match="failed SHA-256 verification"):
        store.export(descriptor, destination)
    assert not destination.exists()
    assert list(destination.parent.iterdir()) == []


def test_export_failure_publishes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    descriptor = store.put(b"abcdef")
    destination = tmp_path / "out" / "artifact.bin"

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("injected failure")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(PlaintextEvidenceStoreError, match="export for"):
        store.export(descriptor, destination)
    monkeypatch.undo()

    assert not destination.exists()
    assert list(destination.parent.iterdir()) == []


def test_delete_with_reference_count_callback(tmp_path: Path) -> None:
    referenced_store = _store(tmp_path / "referenced", reference_count=lambda _sha: 1)
    referenced = referenced_store.put(b"kept")
    with pytest.raises(PlaintextEvidenceReferencedError, match="still has 1 references"):
        referenced_store.delete(referenced)
    assert _object_path(referenced_store, referenced).exists()

    free_store = _store(tmp_path / "free", reference_count=lambda _sha: 0)
    free = free_store.put(b"dropped")
    free_store.delete(free)
    assert not _object_path(free_store, free).exists()


def test_reference_count_must_be_non_negative_integer(tmp_path: Path) -> None:
    store = _store(tmp_path, reference_count=lambda _sha: -1)
    descriptor = store.put(b"x")

    with pytest.raises(PlaintextEvidenceStoreError, match="invalid count"):
        store.delete(descriptor)


def test_delete_without_callback_or_token_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    descriptor = store.put(b"x")

    with pytest.raises(PlaintextEvidenceStoreError, match="requires a zero reference count or a valid retention token"):
        store.delete(descriptor)
    assert _object_path(store, descriptor).exists()


def test_delete_with_retention_token(tmp_path: Path) -> None:
    store = _store(tmp_path, retention_token="secret-token")
    descriptor = store.put(b"x")

    with pytest.raises(PlaintextEvidenceStoreError, match="requires a zero reference count or a valid retention token"):
        store.delete(descriptor)
    with pytest.raises(PlaintextEvidenceStoreError, match="retention token is invalid"):
        store.delete(descriptor, reference_token="wrong-token")
    assert _object_path(store, descriptor).exists()

    store.delete(descriptor, reference_token="secret-token")
    assert not _object_path(store, descriptor).exists()


def test_delete_missing_object_raises_not_found(tmp_path: Path) -> None:
    store = _store(tmp_path, reference_count=lambda _sha: 0)
    descriptor = store.put(b"x")
    _object_path(store, descriptor).unlink()

    with pytest.raises(PlaintextEvidenceNotFoundError, match="not found"):
        store.delete(descriptor)


async def test_async_companions_round_trip(tmp_path: Path) -> None:
    store = _store(tmp_path, reference_count=lambda _sha: 0)
    descriptor = await store.put_async(b"async-bytes")

    assert await store.verify_async(descriptor) == descriptor
    assert await store.read_async(descriptor) == b"async-bytes"
    assert await store.read_range_async(descriptor, offset=6, length=5) == b"bytes"

    handle = await store.open_async(descriptor)
    try:
        assert handle.read() == b"async-bytes"
    finally:
        handle.close()

    exported = await store.export_async(descriptor, tmp_path / "out" / "async.bin")
    assert exported.read_bytes() == b"async-bytes"

    await store.delete_async(descriptor)
    assert not _object_path(store, descriptor).exists()
