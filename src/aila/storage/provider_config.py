"""Raw provider configuration store backed by ProviderConfigRecord.

ProviderConfigStore manages flat string key-value pairs such as openai_api_base
and openai_model_id.  These differ from typed module configs managed by
ConfigRegistry — they have no schema, no env-var fallback chain, and no type
casting.  They are read by AilaLLMClient's LLMConfigProvider to build the LLM
client.

The fallback chain for LLM config resolution is:
1. ProviderConfigStore.get_config(key)  — user-set DB value
2. None  — caller supplies a default (e.g. empty string for model_id)

Module-level typed configs (e.g. VulnerabilityConfigSchema fields) are read via
ConfigRegistry.get(), not this store.
"""

from __future__ import annotations

from typing import Protocol

from sqlmodel import select

from ..config import get_settings
from ..platform.contracts._common import utc_now
from .database import async_session_scope
from .db_models import ProviderConfigRecord


class ProviderConfigSettings(Protocol):
    """Structural protocol for settings objects passed to ProviderConfigStore."""

    database_url: str


class ProviderConfigStore:
    """CRUD store for raw provider configuration values in ProviderConfigRecord.

    Callers must call await init_db() before using this store.  All operations
    use async_session_scope() for consistent transaction handling.
    """

    def __init__(self, settings: ProviderConfigSettings | None = None):
        self.settings = settings or get_settings()

    async def get_config(self, config_key: str) -> str | None:
        """Retrieve the stored value for config_key, or None if not set.

        Args:
            config_key: The configuration key to look up (e.g. "openai_api_base").

        Returns:
            The stored string value, or None if the key has not been set.
        """
        async with async_session_scope(self.settings) as session:
            record = (await session.exec(
                select(ProviderConfigRecord).where(ProviderConfigRecord.config_key == config_key)
            )).first()
            return record.value if record else None

    async def upsert_config(self, config_key: str, value: str) -> dict[str, object]:
        """Create or update a provider config entry.

        Strips whitespace from both key and value.  Raises ValueError on blank
        input to fail fast rather than silently storing an unusable config.

        Args:
            config_key: The configuration key to set.
            value: The raw string value to store.

        Returns:
            Dict with id, config_key, value, and updated_at of the upserted record.

        Raises:
            ValueError: If config_key or value is blank after stripping.
        """
        normalized_key = config_key.strip()
        if not normalized_key:
            raise ValueError("Provider config key must not be blank.")
        normalized_value = value.strip()
        if not normalized_value:
            raise ValueError(f"Provider config '{normalized_key}' must not be blank.")

        async with async_session_scope(self.settings) as session:
            record = (await session.exec(
                select(ProviderConfigRecord).where(ProviderConfigRecord.config_key == normalized_key)
            )).first()
            if record is None:
                record = ProviderConfigRecord(config_key=normalized_key, value=normalized_value)
            else:
                record.value = normalized_value
                record.updated_at = utc_now()
            session.add(record)
            await session.commit()
            await session.refresh(record)
            return {
                "id": record.id,
                "config_key": record.config_key,
                "value": record.value,
                "updated_at": record.updated_at,
            }

    async def delete_config(self, config_key: str) -> bool:
        """Delete the config entry for config_key.

        Returns:
            True if the entry was found and deleted; False if it did not exist.
        """
        normalized_key = config_key.strip()
        async with async_session_scope(self.settings) as session:
            record = (await session.exec(
                select(ProviderConfigRecord).where(ProviderConfigRecord.config_key == normalized_key)
            )).first()
            if record is None:
                return False
            await session.delete(record)
            await session.commit()
            return True

    async def list_configs(self) -> list[dict[str, object]]:
        """Return all provider config entries ordered alphabetically by key.

        Returns:
            List of dicts with id, config_key, value, and updated_at.
        """
        async with async_session_scope(self.settings) as session:
            records = list(await session.exec(select(ProviderConfigRecord).order_by(ProviderConfigRecord.config_key)))
            return [
                {
                    "id": record.id,
                    "config_key": record.config_key,
                    "value": record.value,
                    "updated_at": record.updated_at,
                }
                for record in records
            ]

