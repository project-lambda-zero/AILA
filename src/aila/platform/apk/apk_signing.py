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
from typing import Any

from asn1crypto import cms as _cms
from cryptography import x509 as _x509
from cryptography.hazmat.primitives import serialization as _serialization

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


def _read_apk_sig_block(apk_path: str) -> dict[int, bytes]:
    """Return the ``{id: value_bytes}`` mapping from the APK Signing Block.

    Returns an empty mapping when the file has no such block or when the
    on-disk layout does not validate (leading/trailing size mismatch,
    truncated pair, oversized length). The scan is deliberately lenient:
    a single malformed pair terminates the walk but preceding pairs are
    still returned.
    """
    pairs: dict[int, bytes] = {}
    with open(apk_path, "rb") as fh:
        fh.seek(0, 2)
        file_size = fh.tell()
        if file_size < 22:
            return pairs
        scan_len = min(file_size, _EOCD_MAX_SCAN)
        fh.seek(file_size - scan_len)
        tail = fh.read(scan_len)
        try:
            eocd = _find_eocd_offset(tail, file_size)
        except ValueError:
            return pairs
        # Central-directory offset lives at EOCD + 16 (uint32 LE). A
        # zip64 apk would store 0xFFFFFFFF here and put the real offset
        # in a zip64 locator; the caller ends up with no signing block
        # in that path, which is fine -- APKs almost never use zip64.
        eocd_local = eocd - (file_size - scan_len)
        cd_offset = struct.unpack_from("<I", tail, eocd_local + 16)[0]
        if cd_offset >= file_size or cd_offset < 24:
            return pairs
        fh.seek(cd_offset - 24)
        trailer = fh.read(24)
        if len(trailer) != 24 or trailer[8:] != _APK_SIG_BLOCK_MAGIC:
            return pairs
        trailing_size = struct.unpack_from("<Q", trailer, 0)[0]
        # Total on-disk size of the block is trailing_size + 8 (the
        # leading size field itself is not counted in trailing_size).
        total = trailing_size + 8
        if total > cd_offset or trailing_size < 24:
            return pairs
        block_start = cd_offset - total
        fh.seek(block_start)
        block = fh.read(total)
        if len(block) != total:
            return pairs
        leading_size = struct.unpack_from("<Q", block, 0)[0]
        if leading_size != trailing_size:
            return pairs
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
    return pairs


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
    joined with ``", "`` for prompt-side display, and ``certificates``
    is a list of per-cert summary dicts deduplicated across schemes.

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
    }

    all_ders: list[bytes] = []
    schemes: list[str] = []

    try:
        zf = zipfile.ZipFile(apk_path, "r")
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        result["error"] = f"apk_unreadable: {type(exc).__name__}"
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
        pairs = _read_apk_sig_block(apk_path)
    except (OSError, ValueError, struct.error):
        pairs = {}

    if _V2_BLOCK_ID in pairs:
        schemes.append("v2")
        try:
            cert = _first_v2v3_cert(pairs[_V2_BLOCK_ID])
        except (struct.error, ValueError):
            cert = None
        if cert is not None:
            all_ders.append(cert)

    if _V3_BLOCK_ID in pairs:
        schemes.append("v3")
        try:
            cert = _first_v2v3_cert(pairs[_V3_BLOCK_ID])
        except (struct.error, ValueError):
            cert = None
        if cert is not None:
            all_ders.append(cert)

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
