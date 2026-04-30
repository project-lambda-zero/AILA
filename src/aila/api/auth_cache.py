"""Auth revocation cache with 30s TTL for reducing DB queries on auth checks (D-06/TEAM-09).

Every authenticated request currently queries the DB to check if a key/user is revoked.
This cache stores the validation result keyed on (token_type, entity_id) with a short TTL.

Trade-off: Up to 30s delay between key revocation and enforcement.
Acceptable for the current security posture per requirements.

This is a module-level singleton -- shared across all concurrent requests.
"""
from __future__ import annotations

import asyncio
import time

_CACHE_TTL_DEFAULT: float = 30.0
_CACHE_MAX_SIZE_DEFAULT: int = 10_000


class AuthRevocationCache:
    """In-memory LRU-ish cache for auth revocation checks.

    Thread-safe via asyncio.Lock (single async event loop).
    Bounded at max_size entries with oldest-10% eviction on overflow.
    """

    def __init__(
        self,
        ttl_seconds: float = _CACHE_TTL_DEFAULT,
        max_size: int = _CACHE_MAX_SIZE_DEFAULT,
    ) -> None:
        self._cache: dict[str, tuple[bool, float]] = {}
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> bool | None:
        """Check if a cached validation result exists and is fresh.

        Args:
            key: Cache key in format "{token_type}:{entity_id}".

        Returns:
            True if valid, False if revoked, None if not cached or expired.
        """
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            is_valid, cached_at = entry
            if (time.monotonic() - cached_at) >= self._ttl:
                # Expired -- remove stale entry
                del self._cache[key]
                return None
            return is_valid

    async def store(self, key: str, is_valid: bool) -> None:
        """Store a validation result in the cache.

        Args:
            key: Cache key in format "{token_type}:{entity_id}".
            is_valid: True if the entity is valid, False if revoked.
        """
        async with self._lock:
            if len(self._cache) >= self._max_size:
                # Evict oldest 10%
                evict_count = max(1, self._max_size // 10)
                sorted_keys = sorted(
                    self._cache,
                    key=lambda k: self._cache[k][1],
                )
                for k in sorted_keys[:evict_count]:
                    del self._cache[k]
            self._cache[key] = (is_valid, time.monotonic())

    async def invalidate(self, key: str) -> None:
        """Remove a specific entry from the cache (called on revocation).

        Args:
            key: Cache key to invalidate.
        """
        async with self._lock:
            self._cache.pop(key, None)

    async def clear(self) -> None:
        """Clear all cached entries (useful for testing)."""
        async with self._lock:
            self._cache.clear()

    @property
    def size(self) -> int:
        """Current number of cached entries (for monitoring)."""
        return len(self._cache)


# Module-level singleton -- shared across all concurrent requests
_auth_cache: AuthRevocationCache | None = None


def get_auth_cache() -> AuthRevocationCache:
    """Return the module-level singleton cache instance.

    Lazily created on first access so import-time side effects are avoided.
    """
    global _auth_cache
    if _auth_cache is None:
        _auth_cache = AuthRevocationCache()
    return _auth_cache


def reset_auth_cache() -> None:
    """Reset the singleton (for testing only)."""
    global _auth_cache
    _auth_cache = None
