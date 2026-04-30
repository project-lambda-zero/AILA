"""AES-256-GCM content encryption for audit seal records.

Uses HKDF for key derivation from the HMAC key (per RFC 5869).
Mirrors the MasterKeySecretProtector pattern from storage/secrets.py:
  - 12-byte random nonce (NIST recommended for AES-GCM)
  - Nonce prepended to ciphertext before base64 encoding
  - AESGCM from cryptography library for authenticated encryption

Encrypt-on-write only: new records get encrypted content, existing
plaintext records are NOT retroactively encrypted.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_NONCE_SIZE = 12  # 96-bit nonce for AES-GCM (NIST SP 800-38D)
_KEY_SIZE = 32  # 256-bit key
_HKDF_INFO = b"aila-seal-content-encryption"


def derive_encryption_key(hmac_key: str) -> bytes:
    """Derive a 256-bit AES key from the HMAC key via HKDF (RFC 5869).

    Uses HKDF with SHA-256 for proper domain-separated key derivation.
    The info parameter binds the derived key to its intended use
    (seal content encryption), preventing cross-domain key reuse.

    NOT raw SHA-256 -- HKDF provides cryptographic key stretching with
    extract-then-expand, which is the correct primitive for deriving
    symmetric keys from other key material.

    Args:
        hmac_key: The HMAC key string (from ConfigRegistry).

    Returns:
        32-byte AES key suitable for AESGCM.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_SIZE,
        salt=None,
        info=_HKDF_INFO,
    )
    return hkdf.derive(hmac_key.encode("utf-8"))


def encrypt_content(plaintext: str, key: bytes) -> str:
    """Encrypt plaintext with AES-256-GCM.

    Returns a base64-encoded string containing: nonce (12 bytes) || ciphertext || tag (16 bytes).
    This format follows the MasterKeySecretProtector pattern from storage/secrets.py
    where nonce is prepended to ciphertext for self-contained decryption.

    Args:
        plaintext: UTF-8 string to encrypt.
        key: 32-byte AES key (from derive_encryption_key).

    Returns:
        Base64-encoded string: nonce + ciphertext + GCM tag.
    """
    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # Prepend nonce to ciphertext (standard pattern -- enables stateless decryption)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_content(encrypted_b64: str, key: bytes) -> str:
    """Decrypt AES-256-GCM ciphertext.

    Expects the base64-encoded format produced by encrypt_content():
    nonce (12 bytes) || ciphertext || GCM authentication tag (16 bytes).

    Args:
        encrypted_b64: Base64-encoded string from encrypt_content().
        key: 32-byte AES key (same key used for encryption).

    Returns:
        The decrypted plaintext string.

    Raises:
        cryptography.exceptions.InvalidTag: If the ciphertext was tampered
            with or the wrong key is used.
        ValueError: If the base64 input is malformed.
    """
    raw = base64.b64decode(encrypted_b64)
    if len(raw) < _NONCE_SIZE + 16:
        raise ValueError(
            f"Encrypted payload too short: expected at least {_NONCE_SIZE + 16} bytes, got {len(raw)}"
        )
    nonce = raw[:_NONCE_SIZE]
    ct = raw[_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")
