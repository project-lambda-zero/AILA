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
The keyring file is the only source of key material -- loss of the keyring
means encrypted secrets are unrecoverable.

Env-var resolution: secrets are resolved via SecretStore.resolve_provider_secret()
which looks up the DB record.  There is no env-var fallback chain for secrets --
callers that need env-var override must check the env var before calling
resolve_provider_secret().

Key rotation: SecretStore.rotate_all_secrets() adds a new key version to the
keyring, marks it active, and re-encrypts every stored SecretRecord under it.
The prior active version stays in the keyring so records that fail to migrate
remain decryptable, and every rotation appends one audit row to the tamper-
evident platform journal.

Keyring file protection: on Unix the file is chmod 0600 on every write. On
Windows the same restriction is applied via ``icacls`` (inheritance stripped,
full control granted only to the current process owner) so the on-disk key
material is not readable by other users of the host.
"""

from __future__ import annotations

import base64
import binascii
import getpass
import json
import logging
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from filelock import FileLock
from sqlmodel import select

_log = logging.getLogger(__name__)

from ..config import get_settings
from ..platform.contracts._common import utc_now
from .database import async_session_scope
from .db_models import SecretRecord

__all__ = [
    "MasterKeyMaterial",
    "MasterKeyProvider",
    "MasterKeySecretProtector",
    "SecretStore",
    "SecretStoreSettings",
    "mask_secret_hint",
]


def _apply_owner_only_acl_windows(path: Path) -> None:
    """Restrict a keyring file to the current process owner on Windows.

    Mirrors the Unix ``chmod S_IRUSR|S_IWUSR`` restriction: the file's ACL is
    replaced with a single ACE granting Full control to the current user.
    Inherited ACEs from the parent directory are dropped so a permissive
    parent (Users, Authenticated Users) cannot leak read access to the key
    material.

    Best-effort: if ``icacls`` is missing, times out, or refuses the change,
    the ACL is left at the Windows default and a warning is logged. The caller
    still gets a functioning keyring; the operator is expected to lock the
    file down manually if the warning appears.

    No-op on non-Windows platforms.
    """
    if os.name != "nt":
        return
    try:
        user_name = getpass.getuser()
    except (OSError, KeyError):
        _log.warning(
            "Cannot resolve current user for icacls hardening on %s; keyring ACL left at Windows default.",
            path,
        )
        return
    if not user_name:
        _log.warning(
            "Empty username resolved for icacls hardening on %s; keyring ACL left at Windows default.",
            path,
        )
        return
    # ``icacls`` resolves a bare account name against the local SAM first, which
    # is exactly what we want -- the process owner. Prepending ``USERDOMAIN``
    # would break on non-domain-joined hosts where USERDOMAIN=='WORKGROUP' is a
    # sentinel and not a real principal. If two candidate accounts collide by
    # name, LookupAccountName's local-first search still picks the right one.
    principal_candidates: list[str] = [user_name]
    computer = os.environ.get("COMPUTERNAME")
    if computer and computer.upper() != "WORKGROUP":
        principal_candidates.append(f"{computer}\\{user_name}")

    last_stderr = ""
    for principal in principal_candidates:
        # /inheritance:r  -- strip inherited ACEs so Users/Authenticated Users are gone
        # /grant:r <p>:F  -- replace any existing ACE for the principal with Full control
        # This is the standard owner-only-lockdown pattern and is idempotent, so a
        # repeat call on the same file just re-asserts the ACL.
        try:
            subprocess.run(
                [
                    "icacls",
                    str(path),
                    "/inheritance:r",
                    "/grant:r",
                    f"{principal}:F",
                ],
                check=True,
                capture_output=True,
                timeout=10,
            )
            return
        except FileNotFoundError:
            _log.warning(
                "icacls binary not available; keyring ACL on %s left at Windows default.",
                path,
            )
            return
        except subprocess.CalledProcessError as exc:
            last_stderr = (exc.stderr or b"").decode("utf-8", errors="replace").strip()
            continue
        except (subprocess.TimeoutExpired, OSError) as exc:
            _log.warning(
                "Failed to apply owner-only ACL to keyring %s (%s); Windows ACL left unchanged.",
                path,
                type(exc).__name__,
            )
            return

    _log.warning(
        "icacls could not resolve a valid owner principal for keyring %s (last error: %s); Windows ACL left unchanged.",
        path,
        last_stderr or "unknown",
    )


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
    only).  On Windows, the equivalent lockdown is applied via ``icacls``
    (inheritance stripped, Full control granted only to the current process
    owner) -- see :func:`_apply_owner_only_acl_windows`.

    Additional key versions may be added at runtime via :meth:`add_key_version`
    to support secret-key rotation (see :meth:`SecretStore.rotate_all_secrets`).
    Older versions stay in the keyring so already-encrypted records can still
    be decrypted during and after the rotation.

    Raises RuntimeError on any configuration error -- malformed JSON, missing active
    version, or invalid base64 key -- to fail fast before attempting any encryption.
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
        """Return the 32-byte key for a specific version -- used during decryption.

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
        """Inner load logic -- caller must hold self._file_lock."""
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
        """Inner create logic -- caller must hold self._file_lock."""
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
        """Inner write logic -- caller must hold self._file_lock.

        On POSIX hosts the file is chmod'd to owner read/write only. On Windows
        the same intent is expressed with ``icacls``: inheritance is stripped
        and Full control is granted only to the current process owner.
        """
        self.keyring_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        if os.name == "nt":
            _apply_owner_only_acl_windows(self.keyring_path)
        else:
            self.keyring_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def list_versions(self) -> list[str]:
        """Return every key version currently present in the keyring, sorted.

        The active version stays in this list; callers wanting to distinguish
        it can compare against :attr:`active_version`.
        """
        keys = self._keyring.get("keys", {})
        if not isinstance(keys, dict):
            return []
        return sorted(str(v) for v in keys.keys())

    def next_version_label(self) -> str:
        """Suggest the next monotonic version label for :meth:`add_key_version`.

        If the existing versions follow the ``v<N>`` convention, returns
        ``v<max(N)+1>``. Otherwise appends ``-rot<count>`` to the current
        active version so the new label is still unique.
        """
        existing = self.list_versions()
        numeric: list[int] = []
        for label in existing:
            if label.startswith("v") and label[1:].isdigit():
                numeric.append(int(label[1:]))
        if numeric:
            return f"v{max(numeric) + 1}"
        return f"{self.active_version}-rot{len(existing) + 1}"

    def add_key_version(
        self,
        new_version: str,
        *,
        activate: bool = True,
        key_bytes: bytes | None = None,
    ) -> MasterKeyMaterial:
        """Add a fresh key version to the keyring and optionally activate it.

        The prior active version is left in the ``keys`` map so records still
        encrypted under it can be decrypted. This is the primitive that
        :meth:`SecretStore.rotate_all_secrets` uses to introduce a new key
        before re-encrypting existing ciphertext.

        Args:
            new_version: Version label for the new key. Must not already exist
                in the keyring.
            activate: When True (default) the ``active_version`` field is
                pointed at ``new_version`` so future encryptions use it.
            key_bytes: Optional explicit 32-byte key material. When None a
                fresh key is generated with :func:`os.urandom`. Provided as an
                escape hatch for external key-management integrations; the
                default caller path never sets it.

        Returns:
            The :class:`MasterKeyMaterial` for the new version.

        Raises:
            ValueError: If ``new_version`` is blank, already present, or
                ``key_bytes`` is not exactly 32 bytes.
        """
        label = (new_version or "").strip()
        if not label:
            raise ValueError("MasterKeyProvider.add_key_version requires a non-empty version label.")
        if key_bytes is None:
            material = os.urandom(32)
        else:
            if len(key_bytes) != 32:
                raise ValueError(
                    f"MasterKeyProvider.add_key_version requires a 32-byte key (got {len(key_bytes)} bytes)."
                )
            material = bytes(key_bytes)

        with self._file_lock:
            payload = dict(self._keyring)
            existing_keys = payload.get("keys", {})
            if not isinstance(existing_keys, dict):
                raise RuntimeError(
                    f"Secret keyring file {self.keyring_path} is not a valid keyring document."
                )
            keys = dict(existing_keys)
            if label in keys:
                raise ValueError(
                    f"MasterKeyProvider.add_key_version: version '{label}' already exists in the keyring."
                )
            keys[label] = self._encode_key(material)
            payload["keys"] = keys
            if activate:
                payload["active_version"] = label
            self._write_keyring_unlocked(payload)
            self._keyring = payload
            if activate:
                self.active_version = label

        return MasterKeyMaterial(version=label, key_bytes=material)

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
        No env-var fallback -- callers that want env-var override must check the
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

    async def rotate_all_secrets(
        self,
        *,
        new_version: str | None = None,
    ) -> dict[str, object]:
        """Introduce a new master-key version and re-encrypt every stored secret.

        Rotation flow:

        1. A new key version is generated and appended to the keyring via
           :meth:`MasterKeyProvider.add_key_version`. The prior active version
           stays in the keyring so records not yet migrated (or that fail to
           migrate) remain decryptable throughout the transition.
        2. Every :class:`SecretRecord` handled by the master-key backend is
           decrypted with the key stored on the record, re-encrypted under the
           new active version, and rewritten in place. The record's
           ``key_version``, ``nonce``, ``ciphertext``, ``algorithm``, and
           ``updated_at`` fields are all refreshed.
        3. A single ``audit`` row is appended to the hash-chained platform
           journal (kind="audit", action="secret.key_rotation") summarising
           the rotation. The payload holds counts and version labels only --
           no plaintext ever enters the journal.

        A record that fails to decrypt (corrupted ciphertext, missing prior
        key, unsupported backend) is skipped and reported in the ``failures``
        list; those records keep their old ``key_version`` so a subsequent
        rotation can retry them.

        Args:
            new_version: Optional explicit label for the new key version. When
                omitted the next monotonic ``vN`` label is chosen via
                :meth:`MasterKeyProvider.next_version_label`. Must not equal
                the currently active version and must not already exist in the
                keyring.

        Returns:
            A summary dict with:
              - ``previous_active_version``: the version active before the call
              - ``new_active_version``: the new active version
              - ``reencrypted_count``: number of records successfully migrated
              - ``failures``: list of ``{scope, secret_key, prior_version, failure}``
                dicts, one per record that could not be re-encrypted
              - ``retained_versions``: every version now present in the keyring
                (all prior versions are retained so old records still decrypt)

        Raises:
            ValueError: If ``new_version`` collides with an existing version or
                equals the currently active version.
        """
        # Lazy import: journal -> db_models -> secrets would recurse at module load.
        from aila.platform.services.journal import JournalEntry, append

        previous_version = self.key_provider.active_version
        resolved_new_version = (new_version or "").strip() or self.key_provider.next_version_label()
        if resolved_new_version == previous_version:
            raise ValueError(
                f"rotate_all_secrets: new version '{resolved_new_version}' equals the currently active version."
            )

        # add_key_version raises ValueError on a duplicate label; propagate
        # unchanged so the caller sees the collision before we touch any rows.
        self.key_provider.add_key_version(resolved_new_version, activate=True)

        reencrypted_count = 0
        failures: list[dict[str, str]] = []

        async with async_session_scope(self.settings) as session:
            records = list(await session.exec(select(SecretRecord)))
            for record in records:
                if record.backend != self.master_protector.backend_name:
                    failures.append(
                        {
                            "scope": record.scope,
                            "secret_key": record.secret_key,
                            "prior_version": record.key_version,
                            "failure": "unsupported_backend",
                        }
                    )
                    continue
                try:
                    plaintext = self.master_protector.decrypt(record)
                except (RuntimeError, InvalidTag, ValueError, binascii.Error) as exc:
                    _log.error(
                        "rotate_all_secrets: could not decrypt %s/%s under version '%s': %s",
                        record.scope,
                        record.secret_key,
                        record.key_version,
                        type(exc).__name__,
                    )
                    failures.append(
                        {
                            "scope": record.scope,
                            "secret_key": record.secret_key,
                            "prior_version": record.key_version,
                            "failure": type(exc).__name__,
                        }
                    )
                    continue

                ciphertext, nonce, key_version, algorithm = self.master_protector.encrypt(
                    scope=record.scope,
                    secret_key=record.secret_key,
                    plaintext=plaintext,
                )
                record.ciphertext = ciphertext
                record.nonce = nonce
                record.key_version = key_version
                record.algorithm = algorithm
                record.updated_at = utc_now()
                session.add(record)
                reencrypted_count += 1

            retained_versions = self.key_provider.list_versions()
            await append(
                session,
                entry=JournalEntry(
                    kind="audit",
                    source="secrets.rotation",
                    action="secret.key_rotation",
                    status="ok" if not failures else "partial",
                    payload={
                        "previous_active_version": previous_version,
                        "new_active_version": resolved_new_version,
                        "reencrypted_count": reencrypted_count,
                        "failure_count": len(failures),
                        "failures": failures,
                        "retained_versions": retained_versions,
                    },
                    contains_secret=False,
                ),
            )
            await session.commit()

        _log.info(
            "rotate_all_secrets: %s -> %s, re-encrypted=%d, failures=%d",
            previous_version,
            resolved_new_version,
            reencrypted_count,
            len(failures),
        )
        return {
            "previous_active_version": previous_version,
            "new_active_version": resolved_new_version,
            "reencrypted_count": reencrypted_count,
            "failures": failures,
            "retained_versions": retained_versions,
        }

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

