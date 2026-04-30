from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from ...storage.database import async_session_scope
from ...storage.memory import PermanentMemoryStore
from ..config import PlatformSettings
from ..routing.cache import decision_cache_key
from ._common import Tool, require_text


class DecisionCacheTool(Tool):
    """Platform tool for TTL-governed decision caching in permanent memory.

    Agents use this to cache expensive decisions (e.g. scoring verdicts, routing
    choices) and avoid redundant model calls on subsequent identical inputs.
    Each namespace is independently TTL-governed so different decision types can
    have different expiry windows. The key_for action lets callers compute a
    deterministic cache key from a structured payload without storing anything.

    Supports actions: key_for, load, store, forget.
    """

    name = "decision_cache"
    description = "Build cache keys and store or load TTL-governed decision payloads from permanent memory."
    inputs = {
        "action": {"type": "string", "description": "One of key_for, load, store, or forget."},
        "namespace": {"type": "string", "description": "Cache namespace."},
        "key": {
            "type": "string",
            "description": "Cache key for load, store, or forget.",
            "nullable": True,
        },
        "scope": {
            "type": "string",
            "description": "Scope label used when building a key from a payload.",
            "nullable": True,
        },
        "payload": {
            "type": "object",
            "description": "Structured payload for key_for or store.",
            "nullable": True,
        },
        "ttl_hours": {
            "type": "integer",
            "description": "Cache time-to-live in hours for load.",
            "nullable": True,
        },
    }
    output_type = "object"

    def __init__(self, settings: PlatformSettings, memory_store: PermanentMemoryStore | None = None):
        self.settings = settings
        self.memory_store = memory_store or PermanentMemoryStore()

    async def forward(
        self,
        action: str,
        namespace: str,
        key: str | None = None,
        scope: str | None = None,
        payload: dict | None = None,
        ttl_hours: int | None = None,
    ) -> dict:
        normalized_action = require_text(action, tool_name="cache.decision", field_name="action").lower()
        normalized_namespace = require_text(namespace, tool_name="cache.decision", field_name="namespace")
        if normalized_action == "key_for":
            if key is not None or ttl_hours is not None:
                raise ValueError("cache.decision key_for accepts namespace, scope, and payload only.")
            if payload is None:
                raise ValueError("cache.decision key_for requires payload.")
            normalized_scope = require_text(scope, tool_name="cache.decision", field_name="scope")
            return {"key": decision_cache_key(scope=normalized_scope, payload=normalize_payload(payload))}
        async with async_session_scope(self.settings) as session:
            if normalized_action == "store":
                if scope is not None or ttl_hours is not None:
                    raise ValueError("cache.decision store accepts namespace, key, and payload only.")
                if payload is None:
                    raise ValueError("cache.decision store requires payload.")
                normalized_key = require_text(key, tool_name="cache.decision", field_name="key")
                normalized_payload = normalize_payload(payload)
                await self.memory_store.remember(
                    session,
                    normalized_namespace,
                    normalized_key,
                    normalized_payload,
                    commit=True,
                )
                stored_entry = await self.memory_store.recall_entry(session, normalized_namespace, normalized_key)
                if stored_entry is None:
                    raise RuntimeError("cache.decision store could not reload the stored entry.")
                return {
                    "stored": True,
                    "key": normalized_key,
                    "updated_at": stored_entry.updated_at.isoformat(),
                }
            if normalized_action == "load":
                if scope is not None or payload is not None:
                    raise ValueError("cache.decision load accepts namespace, key, and ttl_hours only.")
                normalized_key = require_text(key, tool_name="cache.decision", field_name="key")
                effective_ttl_hours = normalize_ttl_hours(ttl_hours)
                entry = await self.memory_store.recall_entry(session, normalized_namespace, normalized_key)
                if entry is None:
                    return {"hit": False, "key": normalized_key, "expired": False, "payload": None}
                expired = _is_expired(entry.updated_at, ttl_hours=effective_ttl_hours)
                if expired:
                    return {
                        "hit": False,
                        "key": normalized_key,
                        "expired": True,
                        "updated_at": entry.updated_at.isoformat(),
                        "payload": None,
                    }
                return {
                    "hit": True,
                    "key": normalized_key,
                    "expired": False,
                    "updated_at": entry.updated_at.isoformat(),
                    "payload": dict(entry.payload),
                }
            if normalized_action == "forget":
                if scope is not None or payload is not None or ttl_hours is not None:
                    raise ValueError("cache.decision forget accepts namespace and key only.")
                normalized_key = require_text(key, tool_name="cache.decision", field_name="key")
                return {
                    "deleted": await self.memory_store.forget(session, normalized_namespace, normalized_key),
                    "key": normalized_key,
                }
        raise ValueError(f"Unsupported cache.decision action '{action}'.")


def _is_expired(updated_at: datetime, *, ttl_hours: int) -> bool:
    if ttl_hours <= 0:
        return True
    age = datetime.now(timezone.utc) - updated_at.astimezone(timezone.utc)
    return age > timedelta(hours=ttl_hours)


def normalize_payload(payload: dict) -> dict:
    normalized = dict(payload)
    try:
        json.dumps(normalized, sort_keys=True)
    except TypeError as exc:
        raise ValueError("cache.decision payload must be JSON-serializable.") from exc
    return normalized


def normalize_ttl_hours(value: str | int | float | None) -> int:
    if value is None:
        raise ValueError("cache.decision load requires ttl_hours.")
    if isinstance(value, bool):
        raise ValueError("cache.decision ttl_hours must be an integer.")
    normalized = int(value)
    if normalized < 1:
        raise ValueError("cache.decision load requires ttl_hours >= 1.")
    return normalized
