"""AES-256-GCM secret encryption, keyring management, and secret CRUD.

Secrets (provider API keys, SSH passwords) are never stored in plaintext.
The encryption chain is:

1. MasterKeyProvider reads or creates a JSON keyring file at
   settings.secret_keyring_path.  The keyring holds one or more base64-encoded
   32-byte keys indexed by version string ("v1", "v2", ...).
2. MasterKeySecretProtector.encrypt() uses the active key to AES-GCM encrypt
   the plaintext with (scope:secret_key:version:algorithm) as associated data.
3. SecretStore persists the ciphertext, nonce, key_version, and hint to
   SecretRecord in the database.

Decryption reverses: SecretStore.get_secret_by_key() looks up the record,
dispatches to the named backend (only "master-key" is supported), and calls
MasterKeySecretProtector.decrypt() which re-derives the AAD from stored fields.

Secrets are NOT stored in the database in any recoverable plaintext form.
The keyring file is the only source of key material — loss of the keyring
means encrypted secrets are unrecoverable.

Env-var resolution: secrets are resolved via SecretStore.resolve_provider_secret()
which looks up the DB record.  There is no env-var fallback chain for secrets —
callers that need env-var override must check the env var before calling
resolve_provider_secret().
"""

from __future__ import annotations

import base64
import json
import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from filelock import FileLock
from sqlmodel import select

_log = logging.getLogger(__name__)

from ..config import get_settings
from ..platform.contracts._common import utc_now
from .database import async_session_scope
from .db_models import SecretRecord


class SecretStoreSettings(Protocol):
    """Structural protocol for settings objects passed to SecretStore."""

    database_url: str
    secret_keyring_path: Path
    secret_active_key_version: str


@dataclass(slots=True)
class MasterKeyMaterial:
    """Resolved key material for the currently active keyring version."""

    version: str
    key_bytes: bytes


class MasterKeyProvider:
    """Reads and manages the on-disk JSON keyring file.

    The keyring file stores one or more base64-encoded 32-byte AES keys indexed
    by version string.  If the file does not exist, a new keyring is created with
    a freshly generated key for the active version.

    On Unix systems, the keyring file is created with mode 0o600 (owner read/write
    only).  On Windows, file permissions are left to the OS (icacls hardening is
    tracked as an active requirement in PROJECT.md).

    Raises RuntimeError on any configuration error — malformed JSON, missing active
    version, or invalid base64 key — to fail fast before attempting any encryption.
    """

    def __init__(self, keyring_path: Path, active_version: str):
        self.keyring_path = keyring_path.resolve()
        self.keyring_path.parent.mkdir(parents=True, exist_ok=True)
        self.active_version = active_version.strip() or "v1"
        self._file_lock = FileLock(str(self.keyring_path) + ".lock", timeout=5)
        self._keyring = self._load_or_create_keyring()

    def active_key(self) -> MasterKeyMaterial:
        """Return the active key material from the in-memory keyring.

        Returns:
            MasterKeyMaterial with version string and 32-byte key bytes.
        """
        version = str(self._keyring["active_version"])
        key_bytes = self._decode_key(str(self._keyring["keys"][version]))
        return MasterKeyMaterial(version=version, key_bytes=key_bytes)

    def key_for_version(self, version: str) -> bytes:
        """Return the 32-byte key for a specific version — used during decryption.

        Args:
            version: The key version string stored on the SecretRecord.

        Returns:
            32-byte AES key bytes.

        Raises:
            RuntimeError: If the version is not present in the keyring.
        """
        try:
            encoded = self._keyring["keys"][version]
        except KeyError as exc:
            raise RuntimeError(f"Secret key version '{version}' is not present in the keyring.") from exc
        return self._decode_key(str(encoded))

    def _load_or_create_keyring(self) -> dict[str, object]:
        with self._file_lock:
            return self._load_or_create_keyring_unlocked()

    def _load_or_create_keyring_unlocked(self) -> dict[str, object]:
        """Inner load logic — caller must hold self._file_lock."""
        if self.keyring_path.exists():
            raw = self.keyring_path.read_bytes().strip()
            if not raw:
                return self._create_keyring_unlocked()
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    f"Secret keyring file {self.keyring_path} is not a valid JSON keyring document."
                ) from exc

            if not isinstance(payload, dict) or "keys" not in payload:
                raise RuntimeError(f"Secret keyring file {self.keyring_path} is not a valid keyring document.")
            keys = payload.get("keys")
            active_version = payload.get("active_version") or self.active_version
            if not isinstance(keys, dict) or not keys:
                raise RuntimeError(f"Secret keyring file {self.keyring_path} contains no keys.")
            if active_version not in keys:
                raise RuntimeError(
                    f"Secret keyring file {self.keyring_path} does not contain the active version '{active_version}'."
                )
            payload["active_version"] = active_version
            self._write_keyring_unlocked(payload)
            return payload

        return self._create_keyring_unlocked()

    def _create_keyring(self) -> dict[str, object]:
        with self._file_lock:
            return self._create_keyring_unlocked()

    def _create_keyring_unlocked(self) -> dict[str, object]:
        """Inner create logic — caller must hold self._file_lock."""
        payload = {
            "active_version": self.active_version,
            "keys": {
                self.active_version: self._encode_key(os.urandom(32)),
            },
        }
        self._write_keyring_unlocked(payload)
        return payload

    def _write_keyring(self, payload: dict[str, object]) -> None:
        with self._file_lock:
            self._write_keyring_unlocked(payload)

    def _write_keyring_unlocked(self, payload: dict[str, object]) -> None:
        """Inner write logic — caller must hold self._file_lock."""
        self.keyring_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        if os.name != "nt":
            self.keyring_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    @staticmethod
    def _encode_key(key_bytes: bytes) -> str:
        return base64.urlsafe_b64encode(key_bytes).decode("ascii")

    @staticmethod
    def _decode_key(encoded: str) -> bytes:
        try:
            return base64.urlsafe_b64decode(encoded.encode("ascii"))
        except Exception as exc:  # pragma: no cover - malformed keyring
            raise ValueError("Secret keyring contains an invalid encoded key.") from exc


class MasterKeySecretProtector:
    """AES-256-GCM encrypt/decrypt using keys from a MasterKeyProvider.

    Associated data (AAD) for each secret is derived from
    "{scope}:{secret_key}:{version}:{algorithm}" so ciphertext from one
    (scope, key) pair cannot be replayed against a different pair even if the
    same key is used.
    """

    backend_name = "master-key"
    algorithm_name = "aes-256-gcm"

    def __init__(self, key_provider: MasterKeyProvider):
        self.key_provider = key_provider

    def encrypt(self, *, scope: str, secret_key: str, plaintext: str) -> tuple[str, str, str, str]:
        """Encrypt plaintext and return (ciphertext_b64, nonce_b64, version, algorithm).

        Uses a fresh 12-byte nonce for each encryption call.  The associated data
        binds the ciphertext to its (scope, secret_key, version, algorithm) tuple
        to prevent ciphertext reuse attacks.

        Args:
            scope: Logical scope (e.g. "provider").
            secret_key: The secret name within the scope.
            plaintext: The raw secret value to encrypt.

        Returns:
            Tuple of (base64-ciphertext, base64-nonce, key-version, algorithm-name)
            ready to store in SecretRecord fields.
        """
        key = self.key_provider.active_key()
        nonce = os.urandom(12)
        aad = self._associated_data(scope, secret_key, key.version, self.algorithm_name)
        ciphertext = AESGCM(key.key_bytes).encrypt(nonce, plaintext.encode("utf-8"), aad)
        return (
            base64.b64encode(ciphertext).decode("ascii"),
            base64.b64encode(nonce).decode("ascii"),
            key.version,
            self.algorithm_name,
        )

    def decrypt(self, record: SecretRecord) -> str:
        """Decrypt a SecretRecord and return the plaintext.

        Re-derives the associated data from record fields so decryption fails
        if the record is tampered with or moved to a different (scope, key) pair.

        Args:
            record: The SecretRecord to decrypt.

        Returns:
            The decrypted plaintext string.

        Raises:
            RuntimeError: If the algorithm is unsupported, the nonce is missing,
                the key version is not in the keyring, or decryption fails.
        """
        if record.algorithm != self.algorithm_name:
            raise RuntimeError(
                f"Secret '{record.scope}/{record.secret_key}' uses unsupported algorithm '{record.algorithm}'."
            )
        if not record.nonce:
            raise RuntimeError(
                f"Secret '{record.scope}/{record.secret_key}' has no nonce and cannot be decrypted with the master key protector."
            )
        key_bytes = self.key_provider.key_for_version(record.key_version)
        nonce = base64.b64decode(record.nonce.encode("ascii"))
        ciphertext = base64.b64decode(record.ciphertext.encode("ascii"))
        aad = self._associated_data(record.scope, record.secret_key, record.key_version, record.algorithm)
        plaintext = AESGCM(key_bytes).decrypt(nonce, ciphertext, aad)
        return plaintext.decode("utf-8")

    @staticmethod
    def _associated_data(scope: str, secret_key: str, key_version: str, algorithm: str) -> bytes:
        return f"{scope}:{secret_key}:{key_version}:{algorithm}".encode()


class SecretStore:
    """High-level secret management API for the AILA platform.

    Combines MasterKeyProvider and MasterKeySecretProtector to provide
    create/read/delete operations on encrypted secrets.  Callers must ensure
    init_db() has been awaited before using this store.

    Secrets are never stored in the DB in plaintext.  The only way to recover
    a secret is to have both the database (for ciphertext) and the keyring file
    (for key material).  If the keyring is lost, encrypted secrets are unrecoverable.

    Provider-scoped convenience methods (resolve_provider_secret,
    upsert_provider_secret, etc.) use scope="provider" and are the primary
    interface for LLM API key management.
    """

    def __init__(self, settings: SecretStoreSettings | None = None):
        self.settings = settings or get_settings()
        self.key_provider = MasterKeyProvider(
            self.settings.secret_keyring_path,
            self.settings.secret_active_key_version,
        )
        self.master_protector = MasterKeySecretProtector(self.key_provider)

    async def upsert_secret(
        self,
        session,
        *,
        scope: str,
        secret_key: str,
        plaintext: str,
        secret_id: str | None = None,
    ) -> SecretRecord:
        """Create or update an encrypted secret record.

        Lookup order: if secret_id is provided, fetches by primary key first; then
        falls back to (scope, secret_key) lookup.  This allows updating an existing
        secret by ID without knowing its scope/key, or by key without knowing its ID.

        Re-encrypts on every call (new nonce, current active key version).  The hint
        is updated to reflect the new plaintext value.

        Args:
            session: Active AsyncSession.
            scope: Logical scope (e.g. "provider").
            secret_key: The secret name within the scope.
            plaintext: The raw secret value to encrypt and store.
            secret_id: Optional primary key for lookup.  Raises ValueError if the
                found record's scope/key does not match the provided values.

        Returns:
            The refreshed SecretRecord after commit.

        Raises:
            ValueError: If secret_id resolves to a record with mismatched scope/key.
        """
        record = None
        if secret_id:
            record = await session.get(SecretRecord, secret_id)
            if record is not None and (record.scope != scope or record.secret_key != secret_key):
                raise ValueError(
                    "Secret id does not match the provided scope and secret_key."
                )
        if record is None:
            record = (await session.exec(
                select(SecretRecord).where(
                    SecretRecord.scope == scope,
                    SecretRecord.secret_key == secret_key,
                )
            )).first()

        ciphertext, nonce, key_version, algorithm = self.master_protector.encrypt(
            scope=scope,
            secret_key=secret_key,
            plaintext=plaintext,
        )
        hint = mask_secret_hint(plaintext)

        if record is None:
            record = SecretRecord(
                scope=scope,
                secret_key=secret_key,
                backend=self.master_protector.backend_name,
                key_version=key_version,
                algorithm=algorithm,
                nonce=nonce,
                hint=hint,
                ciphertext=ciphertext,
            )
        else:
            record.backend = self.master_protector.backend_name
            record.key_version = key_version
            record.algorithm = algorithm
            record.nonce = nonce
            record.hint = hint
            record.ciphertext = ciphertext
            record.updated_at = utc_now()
        session.add(record)
        await session.commit()
        await session.refresh(record)
        return record

    async def get_secret_by_id(self, session, secret_id: str | None) -> str | None:
        """Decrypt and return the plaintext for a secret by primary key.

        Returns None if secret_id is falsy or the record does not exist.
        """
        if not secret_id:
            return None
        record = await session.get(SecretRecord, secret_id)
        if record is None:
            return None
        return self._decrypt_record(record)

    async def get_secret_by_key(self, session, *, scope: str, secret_key: str) -> str | None:
        """Decrypt and return the plaintext for a secret by (scope, secret_key).

        Returns None if no record matches.
        """
        record = (await session.exec(
            select(SecretRecord).where(
                SecretRecord.scope == scope,
                SecretRecord.secret_key == secret_key,
            )
        )).first()
        if record is None:
            return None
        return self._decrypt_record(record)

    async def delete_secret(self, session, *, secret_id: str | None = None, scope: str | None = None, secret_key: str | None = None) -> bool:
        """Delete a secret by ID or by (scope, secret_key).

        Lookup: secret_id takes priority; falls back to (scope, secret_key).

        Returns:
            True if the record existed and was deleted; False if not found.
        """
        record = None
        if secret_id:
            record = await session.get(SecretRecord, secret_id)
        elif scope and secret_key:
            record = (await session.exec(
                select(SecretRecord).where(
                    SecretRecord.scope == scope,
                    SecretRecord.secret_key == secret_key,
                )
            )).first()
        if record is None:
            return False
        await session.delete(record)
        await session.commit()
        return True

    async def list_metadata(self, session, scope: str, *, limit: int | None = None) -> list[dict[str, object]]:
        """List secret metadata (no plaintext) for a given scope.

        Returns dicts with id, scope, secret_key, backend, algorithm, key_version,
        hint, and updated_at.  Plaintext is never included.

        Args:
            session: Active AsyncSession.
            scope: The scope to list (e.g. "provider").
            limit: Optional row limit.

        Returns:
            List of metadata dicts ordered by secret_key ascending.
        """
        statement = (
            select(SecretRecord)
            .where(SecretRecord.scope == scope)
            .order_by(SecretRecord.secret_key)
        )
        if limit is not None:
            statement = statement.limit(limit)
        records = list(await session.exec(statement))
        return [
            {
                "id": record.id,
                "scope": record.scope,
                "secret_key": record.secret_key,
                "backend": record.backend,
                "algorithm": record.algorithm,
                "key_version": record.key_version,
                "hint": record.hint,
                "updated_at": record.updated_at.isoformat(),
            }
            for record in records
        ]

    async def resolve_provider_secret(self, secret_key: str) -> str | None:
        """Resolve a provider-scoped secret by key.

        Opens its own async_session_scope.  Returns None if the secret has not been set.
        No env-var fallback — callers that want env-var override must check the
        env var before calling this method.
        """
        async with async_session_scope(self.settings) as session:
            return await self.get_secret_by_key(session, scope="provider", secret_key=secret_key)

    async def upsert_provider_secret(self, secret_key: str, plaintext: str) -> dict[str, object]:
        """Encrypt and store a provider-scoped secret, returning its metadata dict."""
        async with async_session_scope(self.settings) as session:
            record = await self.upsert_secret(
                session,
                scope="provider",
                secret_key=secret_key,
                plaintext=plaintext,
            )
            return {
                "id": record.id,
                "scope": record.scope,
                "secret_key": record.secret_key,
                "backend": record.backend,
                "algorithm": record.algorithm,
                "key_version": record.key_version,
                "hint": record.hint,
                "updated_at": record.updated_at.isoformat(),
            }

    async def delete_provider_secret(self, secret_key: str) -> bool:
        """Delete a provider-scoped secret.  Returns True if it existed."""
        async with async_session_scope(self.settings) as session:
            return await self.delete_secret(session, scope="provider", secret_key=secret_key)

    async def list_provider_secrets(self, *, limit: int | None = None) -> list[dict[str, object]]:
        """List metadata for all provider-scoped secrets.  No plaintext returned."""
        async with async_session_scope(self.settings) as session:
            return await self.list_metadata(session, "provider", limit=limit)

    def _decrypt_record(self, record: SecretRecord) -> str:
        if record.backend == self.master_protector.backend_name:
            try:
                return self.master_protector.decrypt(record)
            except Exception as exc:
                from aila.platform.exceptions import UpstreamError
                raise UpstreamError(
                    f"Secret '{record.scope}/{record.secret_key}' could not be decrypted with the active keyring."
                ) from exc
        raise RuntimeError(
            f"Secret backend '{record.backend}' is not supported on this host for secret '{record.scope}/{record.secret_key}'."
        )


def mask_secret_hint(value: str) -> str:
    """Produce a safe display hint for a secret value.

    Returns the first 2 characters followed by "**" for secrets of 4+ chars.
    Returns "[N chars]" for short secrets to avoid exposing them.
    Returns "empty" for blank inputs.

    Args:
        value: The plaintext secret value.

    Returns:
        A hint string safe to display in CLI output (e.g. "sk**").
    """
    if not value:
        return "empty"
    if len(value) < 4:
        return f"[{len(value)} chars]"
    return value[:2] + "**"

