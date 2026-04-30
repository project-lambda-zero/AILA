from __future__ import annotations

from typing import Any

from sqlmodel import select

from ...storage.database import async_session_scope
from ...storage.db_models import SecretRecord
from ...storage.secrets import SecretStore
from ..config import PlatformSettings
from ._common import Tool, normalize_limit, optional_text, require_text


class SecretsManageTool(Tool):
    """Platform tool for managing encrypted secrets stored in the platform database.

    Secrets are AES-256-GCM encrypted at rest via SecretStore. Plaintext is
    never returned — only metadata (id, scope, secret_key, hint, algorithm)
    is exposed through get and list actions. Secrets are referenced by ID or
    scope+key combination, not by their plaintext value, so agents can identify
    a secret without ever seeing its content.

    Supports actions: put, get, delete, list.
    """

    name = "secrets_manage"
    description = "Create, fetch, delete, or list secret metadata by scope and key."
    inputs = {
        "action": {"type": "string", "description": "One of put, get, delete, or list."},
        "scope": {
            "type": "string",
            "description": "Secret scope such as provider or system-password.",
            "nullable": True,
        },
        "secret_key": {
            "type": "string",
            "description": "Secret key within the scope.",
            "nullable": True,
        },
        "secret_id": {
            "type": "string",
            "description": "Optional secret identifier for get or delete actions.",
            "nullable": True,
        },
        "plaintext": {
            "type": "string",
            "description": "Plaintext secret value for put actions.",
            "nullable": True,
        },
        "limit": {
            "type": "integer",
            "description": "Maximum number of secret metadata records to return for list.",
            "nullable": True,
        },
    }
    output_type = "object"

    def __init__(self, settings: PlatformSettings, store: SecretStore | None = None):
        self.settings = settings
        self.store = store or SecretStore(self.settings)

    async def forward(
        self,
        action: str,
        scope: str | None = None,
        secret_key: str | None = None,
        secret_id: str | None = None,
        plaintext: str | None = None,
        limit: int | None = None,
    ) -> dict:
        normalized_action = require_text(action, tool_name="secrets.manage", field_name="action").lower()
        async with async_session_scope(self.settings) as session:
            if normalized_action == "put":
                if limit is not None:
                    raise ValueError("secrets.manage put does not accept limit.")
                normalized_scope = require_text(scope, tool_name="secrets.manage", field_name="scope")
                normalized_key = require_text(secret_key, tool_name="secrets.manage", field_name="secret_key")
                if plaintext is None:
                    raise ValueError("secrets.manage put requires plaintext.")
                record = await self.store.upsert_secret(
                    session,
                    scope=normalized_scope,
                    secret_key=normalized_key,
                    plaintext=plaintext,
                    secret_id=secret_id,
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
            if normalized_action == "get":
                if plaintext is not None or limit is not None:
                    raise ValueError("secrets.manage get does not accept plaintext or limit.")
                validate_secret_selector(
                    action="get",
                    secret_id=secret_id,
                    scope=scope,
                    secret_key=secret_key,
                )
                record = await _secret_record(
                    session,
                    secret_id=secret_id,
                    scope=optional_text(scope, tool_name="secrets.manage", field_name="scope"),
                    secret_key=optional_text(secret_key, tool_name="secrets.manage", field_name="secret_key"),
                )
                return {
                    "found": record is not None,
                    "item": _secret_metadata_payload(record) if record is not None else None,
                }
            if normalized_action == "delete":
                if plaintext is not None or limit is not None:
                    raise ValueError("secrets.manage delete does not accept plaintext or limit.")
                validate_secret_selector(
                    action="delete",
                    secret_id=secret_id,
                    scope=scope,
                    secret_key=secret_key,
                )
                deleted = await self.store.delete_secret(
                    session,
                    secret_id=secret_id,
                    scope=optional_text(scope, tool_name="secrets.manage", field_name="scope"),
                    secret_key=optional_text(secret_key, tool_name="secrets.manage", field_name="secret_key"),
                )
                return {"deleted": deleted}
            if normalized_action == "list":
                normalized_scope = require_text(scope, tool_name="secrets.manage", field_name="scope")
                if secret_id is not None or secret_key is not None or plaintext is not None:
                    raise ValueError("secrets.manage list accepts scope and limit only.")
                normalized_limit = normalize_limit(limit, default=100, maximum=500)
                items = await self.store.list_metadata(session, normalized_scope, limit=normalized_limit)
                return {
                    "scope": normalized_scope,
                    "count": len(items),
                    "returned": len(items),
                    "limit": normalized_limit,
                    "items": items,
                }
        raise ValueError(f"Unsupported secrets.manage action '{action}'.")


async def _secret_record(session: Any, *, secret_id: str | None, scope: str | None, secret_key: str | None) -> SecretRecord | None:
    if secret_id:
        return await session.get(SecretRecord, secret_id)
    if scope and secret_key:
        return (await session.exec(
            select(SecretRecord).where(
                SecretRecord.scope == scope,
                SecretRecord.secret_key == secret_key,
            )
        )).first()
    raise ValueError("secrets.manage get requires secret_id or scope + secret_key.")


def _secret_metadata_payload(record: SecretRecord) -> dict:
    return {
        "id": record.id,
        "scope": record.scope,
        "secret_key": record.secret_key,
        "backend": record.backend,
        "algorithm": record.algorithm,
        "key_version": record.key_version,
        "hint": record.hint,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
    }


def validate_secret_selector(*, action: str, secret_id: str | None, scope: str | None, secret_key: str | None) -> None:
    has_secret_id = optional_text(secret_id, tool_name="secrets.manage", field_name="secret_id") is not None
    has_scope = optional_text(scope, tool_name="secrets.manage", field_name="scope") is not None
    has_secret_key = optional_text(secret_key, tool_name="secrets.manage", field_name="secret_key") is not None
    if has_secret_id and (has_scope or has_secret_key):
        raise ValueError(f"secrets.manage {action} accepts secret_id or scope + secret_key, not both.")
    if not has_secret_id and has_scope != has_secret_key:
        raise ValueError(f"secrets.manage {action} requires secret_id or scope + secret_key.")
