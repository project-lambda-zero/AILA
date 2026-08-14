"""APK code-signing parser.

Reads the code-signing artefacts embedded in an ``.apk`` (a ZIP file):

* v1 -- JAR signing: PKCS#7 / CMS ``SignedData`` inside ``META-INF/*.RSA``
  (or ``.DSA`` / ``.EC``) accompanied by ``META-INF/*.SF``.
* v2 -- APK Signing Block id ``0x7109871a``.
* v3 -- APK Signing Block id ``0xf05368c0``.

The APK Signing Block sits between the last file entry and the ZIP
central directory. It ends with the 16-byte magic ``APK Sig Block 42``
and is a sequence of id-value pairs (uint64 length + uint32 id +
value bytes). See Android's public APK-signing documentation for the
exact layout.

Output mirrors the certificate summary the prior pipeline emitted so downstream checks continue to see the same fields
(subject / issuer / validity window / signature algorithm / serial /
sha256 fingerprint) without a heavyweight analysis dependency.

Pure static: opens a file on disk, does not spawn any subprocess and
does not touch the network. Failures produce a partial dict with an
``error`` key rather than raising.
"""
from __future__ import annotations

import hashlib
import struct
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from asn1crypto import cms as _cms
from cryptography import x509 as _x509
from cryptography.exceptions import InvalidSignature as _InvalidSignature
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives import serialization as _serialization
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric import padding as _padding
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

__all__ = ["parse_signing"]

# APK Signing Block trailer magic. Sits immediately before the ZIP
# central directory when a v2/v3 block is present.
_APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"

# Well-known id-value pair ids inside the APK Signing Block. Additional
# ids (Google-signed metadata, stamp block, etc.) may be present in real
# files; only v2/v3 are recognised here because they are the only ones
# that carry the certificate chain the summary needs.
_V2_BLOCK_ID = 0x7109871A
_V3_BLOCK_ID = 0xF05368C0

# Extensions of the PKCS#7 signature file inside META-INF/. The neighbour
# ``.SF`` file is the JAR signature manifest; presence of both is what
# marks scheme v1 as applied.
_V1_SIG_EXTS = (".RSA", ".DSA", ".EC")

# Upper bound on the ZIP end-of-central-directory back-scan. The EOCD
# record has a 2-byte comment length field, so its start sits at most
# 22 (fixed record) + 65535 (comment) bytes from the file end.
_EOCD_MAX_SCAN = 22 + 0xFFFF
_EOCD_SIG = b"PK\x05\x06"

# APK Signature Scheme v2 / v3 signature-algorithm ids. See
# https://source.android.com/docs/security/features/apksigning/v2 for the
# full table. DSA (0x0301) is deliberately absent from the verifier's
# supported set: it is rare in practice and treated as unverified so a
# DSA-only signature never yields ``signature_verified=True``.
_SIG_ALG_RSA_PSS_SHA256 = 0x0101
_SIG_ALG_RSA_PSS_SHA512 = 0x0102
_SIG_ALG_RSA_PKCS1_SHA256 = 0x0103
_SIG_ALG_RSA_PKCS1_SHA512 = 0x0104
_SIG_ALG_ECDSA_SHA256 = 0x0201
_SIG_ALG_ECDSA_SHA512 = 0x0202
_SIG_ALG_DSA_SHA256 = 0x0301

# Ranking of signature algorithms for "pick the strongest" per the
# Android spec. Higher rank wins. Only ids in this table are supported
# by the verifier; anything else is treated as unverified.
_SIG_ALG_RANK: dict[int, int] = {
    _SIG_ALG_RSA_PKCS1_SHA256: 1,
    _SIG_ALG_ECDSA_SHA256: 1,
    _SIG_ALG_RSA_PSS_SHA256: 2,
    _SIG_ALG_RSA_PKCS1_SHA512: 3,
    _SIG_ALG_ECDSA_SHA512: 3,
    _SIG_ALG_RSA_PSS_SHA512: 4,
}

# Content digest algorithm keyed by signature algorithm id. Determines
# which chunked APK-content digest a given signer's ``signed_data``
# digest entry must match.
_SIG_ALG_HASH: dict[int, str] = {
    _SIG_ALG_RSA_PSS_SHA256: "sha256",
    _SIG_ALG_RSA_PKCS1_SHA256: "sha256",
    _SIG_ALG_ECDSA_SHA256: "sha256",
    _SIG_ALG_RSA_PSS_SHA512: "sha512",
    _SIG_ALG_RSA_PKCS1_SHA512: "sha512",
    _SIG_ALG_ECDSA_SHA512: "sha512",
}

# APK content-digest chunk size (Android spec). Each section is split
# into contiguous chunks of this size; the last chunk in a section may
# be shorter. Chunks NEVER span section boundaries.
_APK_CHUNK_SIZE = 1 << 20  # 1 MiB


@dataclass(frozen=True)
class _ApkLayout:
    """Byte offsets and pair map for an APK carrying a v2/v3 sig block."""

    pairs: dict[int, bytes]
    signing_block_start: int
    cd_offset: int
    eocd_offset: int
    file_size: int
    eocd_record: bytes


def _cert_summary(der: bytes) -> dict[str, Any]:
    """Reduce a DER-encoded X.509 to the summary dict this module emits.

    Any per-field parse failure yields ``""`` for that field rather than
    raising, so a partially-broken certificate still contributes its
    sha256 fingerprint and whatever fields did parse. The sha256 is
    computed over the input DER bytes directly so it matches what
    ``keytool`` / ``apksigner`` print.
    """
    fingerprint = hashlib.sha256(der).hexdigest()
    summary: dict[str, Any] = {
        "subject": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "signature_algorithm": "",
        "serial": "",
        "sha256": fingerprint,
    }
    try:
        cert = _x509.load_der_x509_certificate(der)
    except (ValueError, TypeError) as exc:
        summary["error"] = f"cert_parse_failed: {type(exc).__name__}"
        return summary
    try:
        summary["subject"] = cert.subject.rfc4514_string()
    except (ValueError, AttributeError):
        pass
    try:
        summary["issuer"] = cert.issuer.rfc4514_string()
    except (ValueError, AttributeError):
        pass
    try:
        summary["not_before"] = cert.not_valid_before_utc.isoformat()
    except (ValueError, AttributeError):
        pass
    try:
        summary["not_after"] = cert.not_valid_after_utc.isoformat()
    except (ValueError, AttributeError):
        pass
    try:
        oid = cert.signature_algorithm_oid
        summary["signature_algorithm"] = getattr(oid, "_name", "") or oid.dotted_string
    except (ValueError, AttributeError):
        pass
    try:
        summary["serial"] = str(cert.serial_number)
    except (ValueError, AttributeError):
        pass
    return summary


def _v1_cert_ders(zf: zipfile.ZipFile) -> tuple[bool, list[bytes]]:
    """Collect the DER certificate bytes carried by scheme v1.

    Returns ``(present, ders)`` where ``present`` is True when the JAR
    signing pair (``.SF`` + one of ``.RSA`` / ``.DSA`` / ``.EC``) is
    observed under ``META-INF/``. A malformed CMS blob still counts as
    v1-present because the observable ZIP layout is what defines the
    scheme; only the cert list ends up empty for that blob.
    """
    sf_stems: set[str] = set()
    sig_entries: list[tuple[str, str]] = []
    for name in zf.namelist():
        if not name.startswith("META-INF/"):
            continue
        upper = name.upper()
        base = upper.rsplit("/", 1)[-1]
        if base.endswith(".SF"):
            sf_stems.add(base[:-3])
        else:
            for ext in _V1_SIG_EXTS:
                if base.endswith(ext):
                    sig_entries.append((name, base[: -len(ext)]))
                    break
    matched = [name for name, stem in sig_entries if stem in sf_stems]
    if not matched:
        return False, []

    ders: list[bytes] = []
    for entry in matched:
        try:
            raw = zf.read(entry)
        except (KeyError, RuntimeError, zipfile.BadZipFile, OSError):
            continue
        try:
            content_info = _cms.ContentInfo.load(raw)
        except (ValueError, TypeError, KeyError):
            continue
        try:
            if content_info["content_type"].native != "signed_data":
                continue
            signed_data = content_info["content"]
            for choice in signed_data["certificates"]:
                if getattr(choice, "name", None) != "certificate":
                    continue
                try:
                    ders.append(choice.chosen.dump())
                except (ValueError, TypeError):
                    continue
        except (ValueError, KeyError, TypeError):
            continue
    return True, ders


def _find_eocd_offset(blob: bytes, file_size: int) -> int:
    """Return the absolute offset of the ZIP end-of-central-directory.

    ``blob`` is the tail of the file (up to ``_EOCD_MAX_SCAN`` bytes).
    Scans backward for the EOCD signature and picks the last plausible
    match (a comment can legally contain the same four bytes, so the
    tail-most match is the one whose comment-length field points exactly
    at the end of the file).
    """
    base = file_size - len(blob)
    idx = len(blob)
    while True:
        idx = blob.rfind(_EOCD_SIG, 0, idx)
        if idx < 0:
            raise ValueError("eocd_not_found")
        if idx + 22 > len(blob):
            continue
        comment_len = struct.unpack_from("<H", blob, idx + 20)[0]
        if base + idx + 22 + comment_len == file_size:
            return base + idx
    # unreachable -- rfind loop either returns or raises above


def _read_apk_layout(apk_path: str) -> _ApkLayout | None:
    """Return layout info + ``{id: value_bytes}`` for the APK Signing Block.

    Returns ``None`` when the file has no such block or when the on-disk
    layout does not validate (leading/trailing size mismatch, truncated
    pair, oversized length). The pair-region walk is deliberately
    lenient: a single malformed pair terminates the walk but preceding
    pairs are still returned in ``pairs``.

    The extra layout fields (``signing_block_start``, ``cd_offset``,
    ``eocd_offset``, ``file_size``, ``eocd_record``) are what the v2/v3
    APK content-digest computation needs on top of the raw pair map.
    """
    pairs: dict[int, bytes] = {}
    with open(apk_path, "rb") as fh:
        fh.seek(0, 2)
        file_size = fh.tell()
        if file_size < 22:
            return None
        scan_len = min(file_size, _EOCD_MAX_SCAN)
        fh.seek(file_size - scan_len)
        tail = fh.read(scan_len)
        try:
            eocd_offset = _find_eocd_offset(tail, file_size)
        except ValueError:
            return None
        # Central-directory offset lives at EOCD + 16 (uint32 LE). A
        # zip64 apk would store 0xFFFFFFFF here and put the real offset
        # in a zip64 locator; the caller ends up with no signing block
        # in that path, which is fine -- APKs almost never use zip64.
        eocd_local = eocd_offset - (file_size - scan_len)
        cd_offset = struct.unpack_from("<I", tail, eocd_local + 16)[0]
        # EOCD record runs from ``eocd_offset`` to end of file (inclusive
        # of any trailing comment). Slice it out of the already-buffered
        # tail so the content-digest path can hash it without a re-read.
        eocd_record = bytes(tail[eocd_local:])
        if cd_offset >= file_size or cd_offset < 24:
            return None
        fh.seek(cd_offset - 24)
        trailer = fh.read(24)
        if len(trailer) != 24 or trailer[8:] != _APK_SIG_BLOCK_MAGIC:
            return None
        trailing_size = struct.unpack_from("<Q", trailer, 0)[0]
        # Total on-disk size of the block is trailing_size + 8 (the
        # leading size field itself is not counted in trailing_size).
        total = trailing_size + 8
        if total > cd_offset or trailing_size < 24:
            return None
        block_start = cd_offset - total
        fh.seek(block_start)
        block = fh.read(total)
        if len(block) != total:
            return None
        leading_size = struct.unpack_from("<Q", block, 0)[0]
        if leading_size != trailing_size:
            return None
        # Pair region: skip the leading uint64 size field, stop before
        # the trailing size + magic (24 bytes).
        cursor = 8
        end = total - 24
        while cursor + 12 <= end:
            length = struct.unpack_from("<Q", block, cursor)[0]
            if length < 4 or cursor + 8 + length > end:
                break
            pair_id = struct.unpack_from("<I", block, cursor + 8)[0]
            value = block[cursor + 12 : cursor + 8 + length]
            pairs.setdefault(pair_id, value)
            cursor += 8 + length
    return _ApkLayout(
        pairs=pairs,
        signing_block_start=block_start,
        cd_offset=cd_offset,
        eocd_offset=eocd_offset,
        file_size=file_size,
        eocd_record=eocd_record,
    )


def _first_v2v3_cert(value: bytes) -> bytes | None:
    """Extract the first DER certificate embedded in a v2/v3 block value.

    Layout (all length prefixes are uint32 little-endian):
    ``signers`` = length-prefixed sequence; each signer contains
    ``signed_data`` (length-prefixed) then ``signatures`` then
    ``public_key``; ``signed_data`` contains ``digests`` (lp seq) then
    ``certificates`` (lp seq of lp DER cert). The first certificate is
    the signing certificate -- returning it is enough to reproduce the
    prior certificate summary.
    """
    if len(value) < 4:
        return None
    signers_len = struct.unpack_from("<I", value, 0)[0]
    if signers_len + 4 > len(value):
        return None
    signers = value[4 : 4 + signers_len]
    cursor = 0
    while cursor + 4 <= len(signers):
        signer_len = struct.unpack_from("<I", signers, cursor)[0]
        if signer_len == 0 or cursor + 4 + signer_len > len(signers):
            return None
        signer = signers[cursor + 4 : cursor + 4 + signer_len]
        cert = _first_cert_in_signer(signer)
        if cert is not None:
            return cert
        cursor += 4 + signer_len
    return None


def _first_cert_in_signer(signer: bytes) -> bytes | None:
    """Return the first DER certificate inside one signer entry.

    ``signer`` is the payload of a single signer, i.e. the concatenation
    of ``signed_data`` (uint32-length-prefixed) plus signatures + key.
    Only the ``signed_data`` half is inspected; digests are skipped and
    the first certificate in the certificates sequence is returned.
    """
    if len(signer) < 4:
        return None
    signed_data_len = struct.unpack_from("<I", signer, 0)[0]
    if signed_data_len == 0 or 4 + signed_data_len > len(signer):
        return None
    signed_data = signer[4 : 4 + signed_data_len]
    if len(signed_data) < 4:
        return None
    digests_len = struct.unpack_from("<I", signed_data, 0)[0]
    certs_start = 4 + digests_len
    if certs_start + 4 > len(signed_data):
        return None
    certs_len = struct.unpack_from("<I", signed_data, certs_start)[0]
    if certs_start + 4 + certs_len > len(signed_data):
        return None
    certs = signed_data[certs_start + 4 : certs_start + 4 + certs_len]
    if len(certs) < 4:
        return None
    first_cert_len = struct.unpack_from("<I", certs, 0)[0]
    if first_cert_len == 0 or 4 + first_cert_len > len(certs):
        return None
    return certs[4 : 4 + first_cert_len]


def _compute_apk_content_digests(
    apk_path: str,
    layout: _ApkLayout,
    hash_names: set[str],
) -> dict[str, bytes]:
    """Compute the APK Signing Scheme v2 chunked content digests.

    Per the spec, three byte-regions of the APK contribute to the
    content digest, in order:

    1. ZIP entries: ``[0, signing_block_start)``.
    2. ZIP central directory: ``[cd_offset, eocd_offset)``.
    3. EOCD record: ``layout.eocd_record``, but with the "offset of
       start of central directory" field (uint32 LE at offset +16)
       overwritten with ``signing_block_start``.

    Each section is split into contiguous 1 MiB chunks (last chunk may
    be shorter); chunks NEVER span a section boundary. Per-chunk digest:
    ``H(0xa5 || uint32_le(chunk_len) || chunk_bytes)``. Master digest:
    ``H(0x5a || uint32_le(chunk_count) || concat(chunk_digests))``.

    Reads the file once per digest algorithm, computing all requested
    algorithms in the same pass. Returns ``{hash_name: master_digest}``.
    An unknown hash name is silently skipped.
    """
    factories: dict[str, Callable[[], Any]] = {}
    for name in hash_names:
        if name == "sha256":
            factories["sha256"] = hashlib.sha256
        elif name == "sha512":
            factories["sha512"] = hashlib.sha512
    if not factories:
        return {}

    # Section 3 (EOCD with patched CD offset). Buffer once so it flows
    # through the same chunking loop as the other two disk-backed
    # sections. The CD-offset patch is critical: signing changes where
    # the CD lives on disk, but the digest must be stable across signed
    # / unsigned layouts, so the digest treats the CD as if it sat
    # immediately after the ZIP entries.
    eocd = bytearray(layout.eocd_record)
    if len(eocd) < 20:
        raise ValueError("eocd_too_short")
    struct.pack_into("<I", eocd, 16, layout.signing_block_start)
    eocd_patched = bytes(eocd)

    chunk_digests: dict[str, list[bytes]] = {name: [] for name in factories}

    # A tiny header struct is reused per chunk to avoid rebuilding it in
    # a hot loop over multi-hundred-MiB APKs.
    hdr_prefix = b"\xa5"

    def _hash_range(fh: Any, start: int, end: int) -> None:
        pos = start
        while pos < end:
            chunk_len = min(_APK_CHUNK_SIZE, end - pos)
            fh.seek(pos)
            data = fh.read(chunk_len)
            if len(data) != chunk_len:
                raise ValueError("short_read")
            hdr = hdr_prefix + struct.pack("<I", chunk_len)
            for name, factory in factories.items():
                h = factory()
                h.update(hdr)
                h.update(data)
                chunk_digests[name].append(h.digest())
            pos += chunk_len

    def _hash_buffer(buf: bytes) -> None:
        pos = 0
        n = len(buf)
        while pos < n:
            chunk_len = min(_APK_CHUNK_SIZE, n - pos)
            hdr = hdr_prefix + struct.pack("<I", chunk_len)
            for name, factory in factories.items():
                h = factory()
                h.update(hdr)
                h.update(buf[pos : pos + chunk_len])
                chunk_digests[name].append(h.digest())
            pos += chunk_len

    with open(apk_path, "rb") as fh:
        _hash_range(fh, 0, layout.signing_block_start)
        _hash_range(fh, layout.cd_offset, layout.eocd_offset)
    _hash_buffer(eocd_patched)

    masters: dict[str, bytes] = {}
    for name, factory in factories.items():
        h = factory()
        h.update(b"\x5a")
        h.update(struct.pack("<I", len(chunk_digests[name])))
        for d in chunk_digests[name]:
            h.update(d)
        masters[name] = h.digest()
    return masters


def _read_lp_bytes(buf: bytes, cursor: int) -> tuple[bytes, int]:
    """Read a uint32-LE length-prefixed byte sequence from ``buf``.

    Returns ``(payload, next_cursor)``. Raises ``ValueError`` on any
    truncation or overflow so callers can uniformly attribute the
    failure to a malformed structure.
    """
    if cursor + 4 > len(buf):
        raise ValueError("truncated_length_prefix")
    length = struct.unpack_from("<I", buf, cursor)[0]
    start = cursor + 4
    end = start + length
    if end > len(buf):
        raise ValueError("length_prefix_overruns_buffer")
    return buf[start:end], end


def _parse_v2v3_signers(value: bytes) -> list[dict[str, Any]]:
    """Return every signer of a v2 / v3 signing block ``value`` fully parsed.

    Each element is
    ``{signed_data: bytes, digests: [(alg, digest_bytes), ...],
       certificates: [bytes, ...], signatures: [(alg, sig_bytes), ...],
       public_key: bytes}``. A per-signer parse failure aborts that
    signer only; the walk continues so a partially-corrupt block still
    yields whatever verified in isolation.
    """
    out: list[dict[str, Any]] = []
    signers_seq, _ = _read_lp_bytes(value, 0)
    cursor = 0
    while cursor < len(signers_seq):
        try:
            signer, cursor = _read_lp_bytes(signers_seq, cursor)
        except ValueError:
            break
        try:
            parsed = _parse_single_signer(signer)
        except (ValueError, struct.error):
            continue
        out.append(parsed)
    return out


def _parse_single_signer(signer: bytes) -> dict[str, Any]:
    """Parse one v2 / v3 signer entry.

    Structure (all length prefixes uint32 LE):
    ``signed_data`` (LP) := ``digests`` (LP seq of {alg_id: u32,
    digest: LP bytes}), ``certificates`` (LP seq of LP DER cert),
    ``additional_attributes`` (LP seq -- ignored here).

    Then at signer level: ``signatures`` (LP seq of {alg_id: u32, sig:
    LP bytes}), ``public_key`` (LP SubjectPublicKeyInfo DER).
    """
    signed_data, cur = _read_lp_bytes(signer, 0)
    signatures_seq, cur = _read_lp_bytes(signer, cur)
    public_key, _ = _read_lp_bytes(signer, cur)

    # signed_data parse
    digests_seq, sd_cur = _read_lp_bytes(signed_data, 0)
    certs_seq, sd_cur = _read_lp_bytes(signed_data, sd_cur)
    # additional_attributes may or may not be present at this point in
    # some hand-rolled blocks; skip if absent.

    digests: list[tuple[int, bytes]] = []
    dc = 0
    while dc < len(digests_seq):
        entry, dc = _read_lp_bytes(digests_seq, dc)
        if len(entry) < 4:
            raise ValueError("digest_entry_truncated")
        alg = struct.unpack_from("<I", entry, 0)[0]
        digest_bytes, _ = _read_lp_bytes(entry, 4)
        digests.append((alg, digest_bytes))

    certificates: list[bytes] = []
    cc = 0
    while cc < len(certs_seq):
        der, cc = _read_lp_bytes(certs_seq, cc)
        certificates.append(der)

    signatures: list[tuple[int, bytes]] = []
    sc = 0
    while sc < len(signatures_seq):
        entry, sc = _read_lp_bytes(signatures_seq, sc)
        if len(entry) < 4:
            raise ValueError("signature_entry_truncated")
        alg = struct.unpack_from("<I", entry, 0)[0]
        sig_bytes, _ = _read_lp_bytes(entry, 4)
        signatures.append((alg, sig_bytes))

    return {
        "signed_data": signed_data,
        "digests": digests,
        "certificates": certificates,
        "signatures": signatures,
        "public_key": public_key,
    }


def _verify_signature(
    public_key: Any,
    sig_alg_id: int,
    signature: bytes,
    data: bytes,
) -> None:
    """Verify one signature against ``public_key``.

    Raises ``InvalidSignature`` on mismatch, ``ValueError`` on any
    unsupported combination (alg id, key type) or padding-parameter
    inconsistency. Callers catch both.
    """
    if sig_alg_id in (_SIG_ALG_RSA_PSS_SHA256, _SIG_ALG_RSA_PSS_SHA512):
        if not isinstance(public_key, _rsa.RSAPublicKey):
            raise ValueError("rsa_pss_requires_rsa_public_key")
        digest_algo = (
            _hashes.SHA256()
            if sig_alg_id == _SIG_ALG_RSA_PSS_SHA256
            else _hashes.SHA512()
        )
        salt_len = 32 if sig_alg_id == _SIG_ALG_RSA_PSS_SHA256 else 64
        padding = _padding.PSS(
            mgf=_padding.MGF1(digest_algo),
            salt_length=salt_len,
        )
        public_key.verify(signature, data, padding, digest_algo)
        return
    if sig_alg_id in (_SIG_ALG_RSA_PKCS1_SHA256, _SIG_ALG_RSA_PKCS1_SHA512):
        if not isinstance(public_key, _rsa.RSAPublicKey):
            raise ValueError("rsa_pkcs1_requires_rsa_public_key")
        digest_algo = (
            _hashes.SHA256()
            if sig_alg_id == _SIG_ALG_RSA_PKCS1_SHA256
            else _hashes.SHA512()
        )
        public_key.verify(signature, data, _padding.PKCS1v15(), digest_algo)
        return
    if sig_alg_id in (_SIG_ALG_ECDSA_SHA256, _SIG_ALG_ECDSA_SHA512):
        if not isinstance(public_key, _ec.EllipticCurvePublicKey):
            raise ValueError("ecdsa_requires_ec_public_key")
        digest_algo = (
            _hashes.SHA256()
            if sig_alg_id == _SIG_ALG_ECDSA_SHA256
            else _hashes.SHA512()
        )
        public_key.verify(signature, data, _ec.ECDSA(digest_algo))
        return
    raise ValueError(f"unsupported_sig_alg_id: 0x{sig_alg_id:04x}")


def _verify_v2v3_block(
    value: bytes,
    apk_path: str,
    layout: _ApkLayout,
) -> tuple[bool, str]:
    """Fully verify a v2 or v3 signing-block value.

    Returns ``(verified, reason)``. ``verified`` is True only when every
    signer in the block passes the full four-step check the Android
    spec requires:

    1. At least one signature the verifier supports.
    2. The strongest supported signature validates against the signer's
       embedded ``public_key`` over the ``signed_data`` bytes.
    3. That ``public_key`` matches the SubjectPublicKeyInfo of the
       first certificate (i.e. the signing cert vouches for the key
       that just verified the signature).
    4. The ``digests`` list inside ``signed_data`` contains an entry
       for the same content-digest algorithm as the winning signature,
       and its value equals the APK content-digest computed over the
       file.

    A parse failure, an unsupported-only algorithm set, a signature
    mismatch, a cert / key mismatch, or a content-digest mismatch all
    produce ``(False, reason)``. Empty signer list is also failure.
    """
    try:
        signers = _parse_v2v3_signers(value)
    except (ValueError, struct.error) as exc:
        return False, f"parse_failed: {type(exc).__name__}"
    if not signers:
        return False, "no_signers"

    # First pass: figure out which hash algorithms we actually need so
    # the file is read the minimum number of times.
    needed_hashes: set[str] = set()
    for signer in signers:
        for alg_id, _ in signer["signatures"]:
            hash_name = _SIG_ALG_HASH.get(alg_id)
            if hash_name is not None:
                needed_hashes.add(hash_name)
    if not needed_hashes:
        return False, "no_supported_signature_algorithm"

    try:
        content_digests = _compute_apk_content_digests(
            apk_path, layout, needed_hashes
        )
    except (OSError, ValueError, struct.error) as exc:
        return False, f"content_digest_failed: {type(exc).__name__}"

    for signer in signers:
        # Step 1: pick the strongest supported signature.
        supported = [
            (alg_id, sig)
            for alg_id, sig in signer["signatures"]
            if alg_id in _SIG_ALG_RANK
        ]
        if not supported:
            return False, "signer_no_supported_algorithm"
        supported.sort(key=lambda pair: _SIG_ALG_RANK[pair[0]], reverse=True)
        chosen_alg, chosen_sig = supported[0]

        # Step 3 (done before step 2 so we don't do RSA work with a
        # key that doesn't match the cert anyway): the embedded
        # public_key must equal the cert's SubjectPublicKeyInfo.
        if not signer["certificates"]:
            return False, "signer_missing_certificate"
        try:
            cert = _x509.load_der_x509_certificate(signer["certificates"][0])
        except (ValueError, TypeError) as exc:
            return False, f"signer_cert_parse_failed: {type(exc).__name__}"
        try:
            cert_spki = cert.public_key().public_bytes(
                _serialization.Encoding.DER,
                _serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except (ValueError, TypeError) as exc:
            return False, f"signer_spki_export_failed: {type(exc).__name__}"
        if cert_spki != signer["public_key"]:
            return False, "signer_public_key_does_not_match_certificate"

        # Step 2: verify the signature over signed_data.
        try:
            public_key = _serialization.load_der_public_key(signer["public_key"])
        except (ValueError, TypeError) as exc:
            return False, f"signer_public_key_parse_failed: {type(exc).__name__}"
        try:
            _verify_signature(public_key, chosen_alg, chosen_sig, signer["signed_data"])
        except _InvalidSignature:
            return False, "signer_signature_invalid"
        except (ValueError, TypeError) as exc:
            return False, f"signer_signature_verify_error: {type(exc).__name__}"

        # Step 4: the digest algorithm matching our chosen signature must
        # appear in signed_data.digests AND its value must equal the
        # APK content digest we computed.
        hash_name = _SIG_ALG_HASH.get(chosen_alg)
        if hash_name is None:  # unreachable -- filtered above
            return False, "signer_missing_hash_mapping"
        expected = content_digests.get(hash_name)
        if expected is None:
            return False, "signer_content_digest_unavailable"
        matched = False
        for alg_id, digest_value in signer["digests"]:
            if _SIG_ALG_HASH.get(alg_id) != hash_name:
                continue
            if digest_value == expected:
                matched = True
                break
        if not matched:
            return False, "signer_content_digest_mismatch"

    return True, ""


def _dedupe_certs(ders: list[bytes]) -> list[dict[str, Any]]:
    """Convert DER byte blobs into summary dicts, deduping by fingerprint.

    Order of first occurrence is preserved. The sha256 fingerprint is
    computed from the raw DER (independently of whether the certificate
    itself parses cleanly), so duplicates across schemes fold together
    even if one copy is truncated or malformed.
    """
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for der in ders:
        # Re-encode via cryptography when possible so the fingerprint is
        # normalised to canonical DER. Fall back to the raw bytes when
        # the parse fails.
        canonical = der
        try:
            parsed = _x509.load_der_x509_certificate(der)
            canonical = parsed.public_bytes(_serialization.Encoding.DER)
        except (ValueError, TypeError):
            pass
        fingerprint = hashlib.sha256(canonical).hexdigest()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        out.append(_cert_summary(canonical))
    return out

def parse_signing(apk_path: str) -> dict[str, Any]:
    """Parse the APK at ``apk_path`` and return its code-signing summary.

    The return shape is stable across success and partial-failure paths:
    ``schemes`` lists the detected scheme identifiers (subset of
    ``"v1"``, ``"v2"``, ``"v3"``), ``signing_scheme`` is the same list
    joined with ``", "`` for prompt-side display, ``certificates``
    is a list of per-cert summary dicts deduplicated across schemes,
    and ``signature_verified`` / ``verification_reason`` carry the
    fail-closed verdict of the cryptographic verification.

    Fail-closed policy:

    * v3 present -- verify v3 fully (Android APK Signature Scheme v2
      four-step check applied to the v3 block); the v3 verdict wins.
    * else v2 present -- verify v2 fully; the v2 verdict wins.
    * else v1 only -- ``signature_verified=False`` with reason
      ``"v1_only_scheme_not_cryptographically_verified"``. The pure-
      Python JAR signature chain (per-entry hash -> .SF -> PKCS#7) is
      intentionally NOT reduced to a boolean here because a partial
      check would risk a False-positive verdict; consumers must treat
      the summary as informational when only v1 is present.
    * no schemes / unreadable -- ``signature_verified=False`` with a
      concrete reason (``"no_signature_block"`` / the ``error`` key).

    An unreadable / non-ZIP file returns a dict with an ``error`` key
    of the form ``"apk_unreadable: <ExcType>"`` and empty scheme /
    certificate lists. Per-scheme parse failures do not abort the whole
    call: the scheme that could be recognised at the container level is
    still recorded even when its inner parse yields no certificates.
    """
    result: dict[str, Any] = {
        "schemes": [],
        "signing_scheme": "",
        "certificates": [],
        "signature_verified": False,
        "verification_reason": "no_signature_block",
    }

    all_ders: list[bytes] = []
    schemes: list[str] = []

    try:
        zf = zipfile.ZipFile(apk_path, "r")
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        result["error"] = f"apk_unreadable: {type(exc).__name__}"
        result["verification_reason"] = f"apk_unreadable: {type(exc).__name__}"
        return result

    try:
        try:
            v1_present, v1_ders = _v1_cert_ders(zf)
        except (zipfile.BadZipFile, OSError, RuntimeError, KeyError, ValueError):
            v1_present, v1_ders = False, []
        if v1_present:
            schemes.append("v1")
            all_ders.extend(v1_ders)
    finally:
        try:
            zf.close()
        except OSError:
            pass

    try:
        layout = _read_apk_layout(apk_path)
    except (OSError, ValueError, struct.error):
        layout = None
    pairs = layout.pairs if layout is not None else {}

    v2_value = pairs.get(_V2_BLOCK_ID)
    v3_value = pairs.get(_V3_BLOCK_ID)

    if v2_value is not None:
        schemes.append("v2")
        try:
            cert = _first_v2v3_cert(v2_value)
        except (struct.error, ValueError):
            cert = None
        if cert is not None:
            all_ders.append(cert)

    if v3_value is not None:
        schemes.append("v3")
        try:
            cert = _first_v2v3_cert(v3_value)
        except (struct.error, ValueError):
            cert = None
        if cert is not None:
            all_ders.append(cert)

    # Verification verdict. v3 takes precedence over v2; v1-only is
    # never reported verified. Any exception below MUST leave the
    # verdict as False -- fail-closed.
    if layout is not None and v3_value is not None:
        try:
            verified, reason = _verify_v2v3_block(v3_value, apk_path, layout)
        except (OSError, ValueError, struct.error, TypeError) as exc:
            verified, reason = False, f"v3_verify_crashed: {type(exc).__name__}"
        result["signature_verified"] = verified
        result["verification_reason"] = "v3_verified" if verified else f"v3_{reason}"
    elif layout is not None and v2_value is not None:
        try:
            verified, reason = _verify_v2v3_block(v2_value, apk_path, layout)
        except (OSError, ValueError, struct.error, TypeError) as exc:
            verified, reason = False, f"v2_verify_crashed: {type(exc).__name__}"
        result["signature_verified"] = verified
        result["verification_reason"] = "v2_verified" if verified else f"v2_{reason}"
    elif v1_present:
        result["signature_verified"] = False
        result["verification_reason"] = (
            "v1_only_scheme_not_cryptographically_verified"
        )
    # else: leave defaults (False, "no_signature_block").

    result["schemes"] = schemes
    result["signing_scheme"] = ", ".join(schemes)
    result["certificates"] = _dedupe_certs(all_ders)
    return result


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print(json.dumps(parse_signing("/nonexistent.apk"), indent=2))
    else:
        print(json.dumps(parse_signing(sys.argv[1]), indent=2))
