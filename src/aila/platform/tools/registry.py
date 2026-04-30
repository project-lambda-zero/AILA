from __future__ import annotations

from sqlalchemy import or_
from sqlmodel import select

from ...storage.database import async_session_scope
from ...storage.db_models import ManagedSystemRecord
from ...storage.memory import PermanentMemoryStore
from ...storage.secrets import SecretStore
from ..config import PlatformSettings
from ..contracts.platform import RegisteredSystem, SSHIntegrationInput
from ._common import Tool, utc_now


class SystemRegistryTool(Tool):
    """Platform tool for managing the permanent SSH integration registry.

    Provides upsert (add or update), list, get (by name or host), and delete
    operations on ManagedSystemRecord entries. Passwords are stored via
    SecretStore at upsert time and loaded only during SSH connection setup,
    never returned in get or list responses.

    Supports actions: upsert, list, get, delete.
    """

    name = "system_registry"
    description = "Register, update, list, or fetch SSH-connected Linux systems stored in the permanent database."
    inputs = {
        "action": {"type": "string", "description": "One of upsert, list, get, or delete."},
        "integration": {
            "type": "object",
            "description": "SSH integration fields to save when action is upsert.",
            "nullable": True,
        },
        "names": {
            "type": "array",
            "description": "Optional system names to fetch when action is get.",
            "nullable": True,
        },
    }
    output_type = "object"

    def __init__(self, settings: PlatformSettings):
        self.settings = settings
        self.secret_store = SecretStore(self.settings)

    async def forward(
        self,
        action: str,
        integration: dict | SSHIntegrationInput | None = None,
        names: list[str] | None = None,
    ) -> dict:
        async with async_session_scope(self.settings) as session:
            if action == "upsert":
                if isinstance(integration, SSHIntegrationInput):
                    payload = integration
                else:
                    payload = SSHIntegrationInput.model_validate(integration or {})
                existing = (await session.exec(
                    select(ManagedSystemRecord).where(ManagedSystemRecord.name == payload.name)
                )).first()
                password_secret_id = payload.password_secret_id or (existing.password_secret_id if existing else None)
                if payload.password:
                    secret_record = await self.secret_store.upsert_secret(
                        session,
                        scope="system-password",
                        secret_key=payload.name,
                        plaintext=payload.password,
                        secret_id=password_secret_id,
                    )
                    password_secret_id = secret_record.id

                if existing:
                    existing.host = payload.host
                    existing.username = payload.username
                    existing.port = payload.port
                    existing.distro = payload.distro
                    existing.description = payload.description
                    existing.private_key_path = payload.private_key_path
                    existing.password_secret_id = password_secret_id
                    existing.known_hosts_path = payload.known_hosts_path
                    existing.host_key_fingerprint = payload.host_key_fingerprint
                    existing.updated_at = utc_now()
                    session.add(existing)
                    await session.commit()
                    await session.refresh(existing)
                    systems = [self._to_schema(existing)]
                    message = f"Updated SSH integration '{existing.name}'."
                else:
                    record = ManagedSystemRecord(
                        name=payload.name,
                        host=payload.host,
                        username=payload.username,
                        port=payload.port,
                        distro=payload.distro,
                        description=payload.description,
                        private_key_path=payload.private_key_path,
                        password_secret_id=password_secret_id,
                        known_hosts_path=payload.known_hosts_path,
                        host_key_fingerprint=payload.host_key_fingerprint,
                    )
                    session.add(record)
                    await session.commit()
                    await session.refresh(record)
                    systems = [self._to_schema(record)]
                    message = f"Stored SSH integration '{record.name}'."
                return {
                    "message": message,
                    "count": len(systems),
                    "integrations": [item.model_dump(mode="json") for item in systems],
                }

            if action == "delete":
                if not names:
                    raise ValueError("Deleting integrations requires at least one system name.")
                records = list((await session.exec(select(ManagedSystemRecord).where(ManagedSystemRecord.name.in_(names)))))
                deleted_names = sorted(record.name for record in records)
                for record in records:
                    if record.password_secret_id:
                        await self.secret_store.delete_secret(session, secret_id=record.password_secret_id)
                    await session.delete(record)
                await session.commit()
                return {
                    "message": f"Deleted {len(deleted_names)} SSH integrations.",
                    "count": len(deleted_names),
                    "integrations": [self._to_schema(record).model_dump(mode='json') for record in records],
                    "deleted_names": deleted_names,
                }

            if action == "get" and names:
                requested_names = [str(name) for name in names]
                records = list(
                    (await session.exec(
                        select(ManagedSystemRecord).where(
                            or_(
                                ManagedSystemRecord.name.in_(requested_names),
                                ManagedSystemRecord.host.in_(requested_names),
                            )
                        )
                    ))
                )
                systems = [self._to_schema(record) for record in records]
                resolved_names = self._resolved_request_names(systems, requested_names)
                missing_names = self._missing_request_names(requested_names, resolved_names)
                duplicate_requested_names = self._duplicate_request_names(requested_names)
                return {
                    "message": f"Resolved {len(systems)} SSH integrations for {len(requested_names)} requested target selectors.",
                    "count": len(systems),
                    "integrations": [item.model_dump(mode="json") for item in systems],
                    "requested_names": requested_names,
                    "resolved_names": resolved_names,
                    "missing_names": missing_names,
                    "duplicate_requested_names": duplicate_requested_names,
                }

            records = list((await session.exec(select(ManagedSystemRecord).order_by(ManagedSystemRecord.name))))
            systems = [self._to_schema(record) for record in records]
            return {
                "message": f"Loaded {len(systems)} registered SSH integrations.",
                "count": len(systems),
                "integrations": [item.model_dump(mode="json") for item in systems],
            }

    @staticmethod
    def _to_schema(record: ManagedSystemRecord) -> RegisteredSystem:
        return RegisteredSystem(
            id=record.id,
            name=record.name,
            host=record.host,
            username=record.username,
            port=record.port,
            distro=record.distro,
            description=record.description,
            private_key_path=record.private_key_path,
            password_secret_id=record.password_secret_id,
            known_hosts_path=record.known_hosts_path,
            host_key_fingerprint=record.host_key_fingerprint,
            created_at=record.created_at,
            updated_at=record.updated_at,
        )

    @staticmethod
    def _resolved_request_names(systems: list[RegisteredSystem], requested_names: list[str]) -> list[str]:
        requested_set = set(requested_names)
        resolved_names: list[str] = []
        seen: set[str] = set()
        for system in systems:
            for selector in (system.name, system.host):
                if selector in requested_set and selector not in seen:
                    seen.add(selector)
                    resolved_names.append(selector)
        return resolved_names

    @staticmethod
    def _missing_request_names(requested_names: list[str], resolved_names: list[str]) -> list[str]:
        resolved_set = set(resolved_names)
        missing: list[str] = []
        seen: set[str] = set()
        for selector in requested_names:
            if selector in resolved_set or selector in seen:
                continue
            seen.add(selector)
            missing.append(selector)
        return missing

    @staticmethod
    def _duplicate_request_names(requested_names: list[str]) -> list[str]:
        counts: dict[str, int] = {}
        duplicates: list[str] = []
        for selector in requested_names:
            counts[selector] = counts.get(selector, 0) + 1
            if counts[selector] == 2:
                duplicates.append(selector)
        return duplicates


class PermanentMemoryTool(Tool):
    """Platform tool for storing and retrieving durable key-value memory entries.

    Used by agents to persist integration profiles, routing decisions, and other
    cross-request state that outlives a single handle() call. Namespace+key
    uniquely identifies each entry; upsert semantics mean remember() is idempotent.

    Supports actions: remember, recall, forget.
    """

    name = "permanent_memory"
    description = "Store or recall durable memory entries in the platform database."
    inputs = {
        "action": {"type": "string", "description": "One of remember, recall, or forget."},
        "namespace": {"type": "string", "description": "Memory namespace."},
        "key": {"type": "string", "description": "Memory key."},
        "payload": {"type": "object", "description": "Payload to store when remembering.", "nullable": True},
    }
    output_type = "object"

    def __init__(self, settings: PlatformSettings, store: PermanentMemoryStore | None = None):
        self.settings = settings
        self.store = store or PermanentMemoryStore()

    async def forward(self, action: str, namespace: str, key: str, payload: dict | None = None) -> dict:
        async with async_session_scope(self.settings) as session:
            if action == "remember":
                await self.store.remember(session, namespace, key, payload or {})
                return {"message": f"Stored memory '{namespace}:{key}'."}
            if action == "forget":
                deleted = await self.store.forget(session, namespace, key)
                return {"message": f"Removed memory '{namespace}:{key}'." if deleted else f"No memory '{namespace}:{key}' was stored."}
            return {"message": f"Loaded memory '{namespace}:{key}'.", "payload": await self.store.recall(session, namespace, key)}

