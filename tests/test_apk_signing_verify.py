"""Focused tests for APK v2 signature verification.

Verifies the observable contract of ``parse_signing``: the returned
``signature_verified`` boolean is computed from the signature (not
merely from the presence of parsed certificates), and the verifier
fails closed on any tamper. Uses an in-repo synthetic APK signed with
a locally-generated RSA key so the test has no external dependencies.

The signer here follows the APK Signature Scheme v2 layout end-to-end
(https://source.android.com/docs/security/features/apksigning/v2), so
the fixture doubles as a small executable spec of the format.
"""
from __future__ import annotations

import datetime
import hashlib
import struct
import zipfile
from collections.abc import Iterable
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric import padding as _padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aila.platform.apk.apk_signing import parse_signing

_V2_BLOCK_ID = 0x7109871A
_APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
_SIG_ALG_RSA_PKCS1_SHA256 = 0x0103
_CHUNK = 1 << 20


def _lp(payload: bytes) -> bytes:
    return struct.pack("<I", len(payload)) + payload


def _lp_seq(items: Iterable[bytes]) -> bytes:
    body = b"".join(_lp(item) for item in items)
    return _lp(body)


def _make_unsigned_apk(path: Path) -> None:
    """Write a minimal ZIP that ``parse_signing`` will treat as an APK."""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as z:
        # A handful of entries so the ZIP-entries section is non-trivial
        # and so the "excludes central directory / EOCD" split is real.
        z.writestr("AndroidManifest.xml", b"<manifest package='x'/>")
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 512)
        z.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 128)


def _compute_content_digest_sha256(
    entries_end: int, cd: bytes, eocd: bytes, apk_bytes: bytes
) -> bytes:
    """Reimplement the APK v2 chunked SHA-256 digest for cross-check."""
    chunk_digests: list[bytes] = []

    def _feed(buf: bytes) -> None:
        pos = 0
        while pos < len(buf):
            take = min(_CHUNK, len(buf) - pos)
            h = hashlib.sha256()
            h.update(b"\xa5" + struct.pack("<I", take))
            h.update(buf[pos : pos + take])
            chunk_digests.append(h.digest())
            pos += take

    _feed(apk_bytes[:entries_end])
    _feed(cd)
    _feed(eocd)
    master = hashlib.sha256()
    master.update(b"\x5a" + struct.pack("<I", len(chunk_digests)))
    for d in chunk_digests:
        master.update(d)
    return master.digest()


def _build_v2_signed_apk(
    src_path: Path,
    dst_path: Path,
    key: rsa.RSAPrivateKey,
    cert: x509.Certificate,
    *,
    corrupt_signature: bool = False,
) -> None:
    """Read the unsigned APK, inject a real v2 signing block, write to dst.

    Steps mirror the reference verifier: derive the three digest
    sections from the source layout, sign the ``signed_data`` bytes,
    then splice the resulting signing block between the ZIP entries
    and the central directory. When ``corrupt_signature`` is True the
    signature bytes are XORed with a byte before emission so the block
    is well-formed but cryptographically invalid.
    """
    raw = src_path.read_bytes()
    # Locate EOCD (short APKs have no comment, so it sits at len-22).
    eocd_offset = raw.rfind(b"PK\x05\x06")
    assert eocd_offset >= 0, "eocd_not_found"
    eocd = raw[eocd_offset:]
    cd_offset = struct.unpack_from("<I", eocd, 16)[0]
    cd = raw[cd_offset:eocd_offset]

    # Original entries live at [0, cd_offset). After splicing, entries
    # STAY at [0, cd_offset) -- the signing block goes between entries
    # and the CD, and the EOCD's cd-offset field is updated to point
    # past the signing block. The content-digest, however, treats the
    # CD as if it lived immediately after the entries, so the digest
    # patches the EOCD's cd-offset to signing_block_start (== old
    # cd_offset). See the Android spec for the rationale.
    entries = raw[:cd_offset]
    entries_end = cd_offset

    # For digest computation, the EOCD must have its cd-offset field
    # rewritten to point at the signing-block start (== the pre-signing
    # cd_offset). In our splice, signing_block_start == entries_end.
    eocd_for_digest = bytearray(eocd)
    struct.pack_into("<I", eocd_for_digest, 16, entries_end)
    apk_digest_sha256 = _compute_content_digest_sha256(
        entries_end, cd, bytes(eocd_for_digest), raw
    )

    cert_der = cert.public_bytes(_ser.Encoding.DER)
    spki = key.public_key().public_bytes(
        _ser.Encoding.DER, _ser.PublicFormat.SubjectPublicKeyInfo
    )

    # signed_data = digests || certificates || additional_attributes
    digest_entry = struct.pack("<I", _SIG_ALG_RSA_PKCS1_SHA256) + _lp(
        apk_digest_sha256
    )
    digests_seq = _lp_seq([digest_entry])
    certs_seq = _lp_seq([cert_der])
    additional_attrs = _lp(b"")  # empty sequence
    signed_data = digests_seq + certs_seq + additional_attrs

    signature = key.sign(
        signed_data, _padding.PKCS1v15(), _hashes.SHA256()
    )
    if corrupt_signature:
        # Flip a bit in the signature so verification MUST fail but the
        # block itself is still structurally intact.
        signature = bytes([signature[0] ^ 0x01]) + signature[1:]
    sig_entry = struct.pack("<I", _SIG_ALG_RSA_PKCS1_SHA256) + _lp(signature)
    signatures_seq = _lp_seq([sig_entry])

    signer = _lp(signed_data) + signatures_seq + _lp(spki)
    signers_seq = _lp_seq([signer])

    # id-value pair for v2.
    pair_value = signers_seq
    pair = (
        struct.pack("<Q", 4 + len(pair_value))  # length: id (4) + value
        + struct.pack("<I", _V2_BLOCK_ID)
        + pair_value
    )

    # Assemble the block: leading size, pair(s), trailing size, magic.
    # Both size fields count everything AFTER the leading size, i.e.
    # pair(s) + trailing size (8) + magic (16) = len(pair) + 24.
    inner_size = len(pair) + 24
    sig_block = (
        struct.pack("<Q", inner_size)
        + pair
        + struct.pack("<Q", inner_size)
        + _APK_SIG_BLOCK_MAGIC
    )

    new_cd_offset = entries_end + len(sig_block)
    new_eocd = bytearray(eocd)
    struct.pack_into("<I", new_eocd, 16, new_cd_offset)

    dst_path.write_bytes(entries + sig_block + cd + bytes(new_eocd))


@pytest.fixture(scope="module")
def rsa_key_and_cert() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "AILA APK Verify Test")]
    )
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, _hashes.SHA256())
    )
    return key, cert


def test_parse_signing_verifies_valid_v2_apk(
    tmp_path: Path,
    rsa_key_and_cert: tuple[rsa.RSAPrivateKey, x509.Certificate],
) -> None:
    key, cert = rsa_key_and_cert
    unsigned = tmp_path / "unsigned.apk"
    signed = tmp_path / "signed.apk"
    _make_unsigned_apk(unsigned)
    _build_v2_signed_apk(unsigned, signed, key, cert)

    result = parse_signing(str(signed))

    assert result["schemes"] == ["v2"], result
    assert result["signature_verified"] is True, result
    assert result["verification_reason"] == "v2_verified", result
    assert len(result["certificates"]) == 1
    fp = hashlib.sha256(cert.public_bytes(_ser.Encoding.DER)).hexdigest()
    assert result["certificates"][0]["sha256"] == fp


def test_parse_signing_rejects_tampered_signature(
    tmp_path: Path,
    rsa_key_and_cert: tuple[rsa.RSAPrivateKey, x509.Certificate],
) -> None:
    key, cert = rsa_key_and_cert
    unsigned = tmp_path / "unsigned.apk"
    signed = tmp_path / "signed_bad_sig.apk"
    _make_unsigned_apk(unsigned)
    _build_v2_signed_apk(
        unsigned, signed, key, cert, corrupt_signature=True
    )

    result = parse_signing(str(signed))

    # The signing block still parses so schemes reports v2 and the cert
    # summary is still emitted, but the verdict is False.
    assert "v2" in result["schemes"]
    assert result["signature_verified"] is False
    assert result["verification_reason"] == "v2_signer_signature_invalid"


def test_parse_signing_rejects_tampered_apk_body(
    tmp_path: Path,
    rsa_key_and_cert: tuple[rsa.RSAPrivateKey, x509.Certificate],
) -> None:
    key, cert = rsa_key_and_cert
    unsigned = tmp_path / "unsigned.apk"
    signed = tmp_path / "signed.apk"
    _make_unsigned_apk(unsigned)
    _build_v2_signed_apk(unsigned, signed, key, cert)

    # Flip a byte inside a ZIP entry payload. The APK content-digest
    # will no longer match what the signed_data records, so
    # verification MUST fail even though the signature itself is
    # cryptographically valid over the (unmodified) signed_data bytes.
    raw = bytearray(signed.read_bytes())
    # Find the "dex" magic and corrupt the byte after it.
    idx = raw.find(b"dex\n035\x00")
    assert idx > 0
    raw[idx + 8] ^= 0x01
    signed.write_bytes(bytes(raw))

    result = parse_signing(str(signed))

    assert "v2" in result["schemes"]
    assert result["signature_verified"] is False
    # The signature over signed_data still validates because we did
    # NOT touch the signing block; only the APK content-digest changes.
    assert result["verification_reason"] == "v2_signer_content_digest_mismatch"


def test_parse_signing_unsigned_apk_marks_verified_false(tmp_path: Path) -> None:
    apk = tmp_path / "unsigned.apk"
    _make_unsigned_apk(apk)

    result = parse_signing(str(apk))

    assert result["schemes"] == []
    assert result["signature_verified"] is False
    assert result["verification_reason"] == "no_signature_block"


def test_parse_signing_unreadable_file_fails_closed(tmp_path: Path) -> None:
    bogus = tmp_path / "not-a-zip.apk"
    bogus.write_bytes(b"this is not a zip file at all")

    result = parse_signing(str(bogus))

    assert result["signature_verified"] is False
    assert result["verification_reason"].startswith("apk_unreadable:")
