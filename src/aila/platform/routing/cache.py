from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from aila.storage.memory import PermanentMemoryStore


@dataclass(frozen=True, slots=True)
class CachedDecision:
    """A routing decision loaded from or stored in the permanent memory cache.

    source is 'cache' when loaded from a valid unexpired entry, 'model' when
    freshly produced by the routing agent. Callers propagate source into
    RouteDecision.decision_source for transparency.
    """

    payload: dict[str, Any]
    source: str
    updated_at: datetime | None


class DecisionCache:
    """TTL-governed cache for routing decisions stored in PermanentMemoryStore.

    LLM routing calls are expensive (latency + tokens). For stable queries
    where the registered module set has not changed, routing decisions can be
    reused across requests. TTL is set via config and defaults to 0 (disabled).
    When disabled (ttl_hours=0), load() always returns None so the router
    always calls the model.
    """

    def __init__(self, memory_store: PermanentMemoryStore, namespace: str, ttl_hours: int):
        self.memory_store = memory_store
        self.namespace = namespace
        self.ttl_hours = max(int(ttl_hours), 0)

    async def load(self, session: Any, *, key: str) -> CachedDecision | None:
        """Load a cached routing decision if it exists and has not expired.

        Returns None when the cache is disabled (ttl_hours=0), the entry is
        missing, or the entry's age exceeds ttl_hours. Callers fall through to
        model routing on None.
        """
        if self.ttl_hours == 0:
            return None
        entry = await self.memory_store.recall_entry(session, self.namespace, key)
        if entry is None or self._is_expired(entry.updated_at):
            return None
        return CachedDecision(
            payload=dict(entry.payload),
            source="cache",
            updated_at=entry.updated_at,
        )

    async def store(self, session: Any, *, key: str, payload: dict[str, Any], commit: bool = False) -> CachedDecision:
        """Persist a routing decision payload under the given key.

        The caller controls commit to allow batching with other session writes.
        Returns a CachedDecision with source='model' reflecting the just-stored state.
        """
        await self.memory_store.remember(session, self.namespace, key, payload, commit=commit)
        return CachedDecision(
            payload=dict(payload),
            source="model",
            updated_at=datetime.now(timezone.utc),
        )

    def _is_expired(self, updated_at: datetime) -> bool:
        if self.ttl_hours <= 0:
            return True
        age = datetime.now(timezone.utc) - updated_at.astimezone(timezone.utc)
        return age > timedelta(hours=self.ttl_hours)


def decision_cache_key(*, scope: str, payload: dict[str, Any]) -> str:
    """Build a deterministic cache key from a scope label and a JSON-serializable payload.

    The key is "{scope}:{sha256_hex}" where sha256 covers the canonical
    sorted-key JSON encoding of payload. Used by both DecisionCache and
    DecisionCacheTool to ensure cache key stability across call sites.
    """
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return f"{scope}:{digest}"
