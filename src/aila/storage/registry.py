"""Module-config and DB-schema registries for the AILA platform.

Two registries are provided:

ConfigRegistry -- typed module configuration.
    Modules call register() during register_tools() to declare their config
    schema (a Pydantic BaseModel subclass).  Default values are written to
    ConfigEntryRecord on first registration.  Callers resolve values via
    get(namespace, key) which follows the chain: env var > DB row > schema default.
    build_platform_settings() reads from this registry; Settings only carries
    the infrastructure fields that are NOT managed here.

SchemaRegistry -- SQLModel table registration.
    Modules call push() during register_tools() to register their SQLModel table
    classes.  init_db() calls create_all(engine) to create only those tables.
    No filesystem crawl -- all registration is explicit and happens at startup.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import time
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass as _dc_dataclass
from typing import Any, Protocol

from pydantic import BaseModel
from pydantic_core import PydanticUndefined
from sqlmodel import select

from ..platform.contracts._common import utc_now
from .database import async_session_scope, session_scope
from .db_models import ConfigEntryRecord

__all__ = [
    "ConfigRegistry",
    "ConfigResolution",
    "DynamicKeyFamily",
    "SchemaRegistry",
    "is_secret_config_key",
]

_log = logging.getLogger(__name__)


# Cross-process invalidation defaults (#56). Any process that ``set``s a
# config value INCRs ``_INVALIDATION_VERSION_KEY`` on Redis; peer processes
# poll that counter (throttled to ``_VERSION_POLL_INTERVAL_S``) and drop
# cache entries populated below the current version. Redis absence collapses
# to the pre-existing TTL-only cache -- no crash, no regression.
_INVALIDATION_VERSION_KEY: str = "aila:config:invalidation_version"
_VERSION_POLL_INTERVAL_S: float = 1.0

# Infra failure modes the invalidation path degrades on. Redis client errors
# subclass RedisError; socket connect/timeout failures are OSError subclasses.
# redis is an optional dependency, so its base is folded in only when present.
try:  # pragma: no cover - optional dependency probe
    from redis.exceptions import RedisError as _RedisError

    _REDIS_ERRORS: tuple[type[BaseException], ...] = (OSError, _RedisError)
except ImportError:  # pragma: no cover
    _REDIS_ERRORS = (OSError,)


class _Missing:
    """Sentinel distinguishing "never resolved" from "resolved to None".

    Used for the lazy sync Redis client: the first ``get_sync`` call attempts
    to build a client from ``AILA_PLATFORM_REDIS_URL``; both success (a
    client) and failure (None) are cached so subsequent calls don't re-import
    ``redis`` or re-resolve the env var.
    """

    __slots__ = ()


_MISSING = _Missing()


class _AsyncRedisLike(Protocol):
    """Minimal async Redis surface the invalidation path uses.

    Both ``redis.asyncio.Redis`` and lightweight test fakes satisfy it. Kept
    narrow so tests can inject an in-memory client without pulling redis-py.
    """

    async def get(self, key: str) -> Any: ...
    async def incr(self, key: str) -> int: ...


class _SyncRedisLike(Protocol):
    """Sync twin of :class:`_AsyncRedisLike` for :meth:`ConfigRegistry.get_sync`."""

    def get(self, key: str) -> Any: ...
    def incr(self, key: str) -> int: ...


@_dc_dataclass
class _CacheEntry:
    """Single cached config value with monotonic expiry + invalidation version.

    ``version_at_populate`` is the cross-process invalidation counter observed
    the moment this entry was cached. When the current Redis-stored version
    exceeds it, a peer process has ``set()``-ted a config since we cached, so
    the entry is treated as expired regardless of ``expires_at`` (#56).
    """

    value: Any
    expires_at: float
    version_at_populate: int = 0


@_dc_dataclass(frozen=True)
class DynamicKeyFamily:
    """A typed family of config keys sharing a prefix.

    Extends a namespace's schema contract to an open key space: any key of the
    form ``{prefix}{suffix}`` -- for example the per-task-type override
    ``llm_model_{task_type}`` -- is a valid, settable, type-cast config key that
    resolves through the same env > cache > DB > default chain as a static
    field. ``value_type`` drives set()-time validation and get()-time casting;
    ``default`` is returned when no env/DB value exists. A schema declares its
    families in a ``__dynamic_families__`` class attribute; the longest matching
    prefix wins when families overlap.
    """

    prefix: str
    value_type: type = str
    default: Any = None
    description: str = ""

    def matches(self, key: str) -> bool:
        return len(key) > len(self.prefix) and key.startswith(self.prefix)


@_dc_dataclass(frozen=True)
class _ResolvedField:
    """Minimal field descriptor for a dynamic-key family match, exposing the
    same ``annotation``/``default`` surface that casting and the default
    resolution read off a Pydantic ``FieldInfo``."""

    annotation: type
    default: Any


@_dc_dataclass(frozen=True)
class ConfigResolution:
    """Snapshot of how a config key resolves right now.

    Mirrors the ``get``/``get_sync`` precedence (env var > DB row > schema
    default) without hitting the DB itself -- the caller supplies ``db_value``
    from the ``ConfigEntryRecord`` row it already holds. Consumers use this to
    render the effective value plus the raw env/DB/default contributions so an
    operator can see WHICH source is live and what the stored fallback is.
    """

    env_key: str
    env_value: str | None
    db_value: str | None
    default_value: str | None
    effective_value: str
    source: str  # 'env' | 'db' | 'default'


# Security-relevant config key prefixes that trigger audit logging on change (D-11).
_SECURITY_KEY_PREFIXES: tuple[str, ...] = (
    "llm_kill_switch",
    "llm_model_",
    "llm_pipeline_classify_",
    "llm_pipeline_gate_",
    "llm_seal_hmac_key",
)

# Config keys whose stored value is a secret and must be redacted on read for
# non-admin callers (C6). Substring match: any key containing one of these
# tokens is treated as secret regardless of namespace.
_SECRET_KEY_TOKENS: tuple[str, ...] = (
    "api_key",
    "secret",
    "password",
    "hmac_key",
    "signing_key",
    "encryption_key",
    "private_key",
    "client_secret",
    "bearer",
    "token",
)


def is_secret_config_key(key: str) -> bool:
    """Return True when the value at this config key must be redacted (C6)."""
    lower = key.lower()
    return any(token in lower for token in _SECRET_KEY_TOKENS)


_REDACTED = "[REDACTED]"


def _hash_config_change(old_value: object, new_value: str) -> str:
    """Return a sha256 of the old -> new transition so a secret rotation stays
    auditable (did the value change?) without persisting the secret itself."""
    import hashlib

    old_str = str(old_value) if old_value is not None else ""
    return hashlib.sha256(f"{old_str}\n{new_value}".encode()).hexdigest()


class ConfigRegistry:
    """Central registry for module config schemas. Thread-safe for reads; callers
    are responsible for not calling register() concurrently (registration happens
    at startup, single-threaded).

    Cross-process cache invalidation (#56): a ``set()`` in one worker
    ``INCR``s a Redis-backed version counter; peer workers poll that counter
    (throttled to ``version_poll_interval``) on the next ``get()`` /
    ``get_sync()`` and treat entries populated below the current version as
    stale, refetching from the DB. When Redis is unreachable or unconfigured
    the mechanism degrades silently to the pre-existing TTL-only cache --
    freshness bounded by ``cache_ttl`` seconds, same as before.

    Tests inject fake Redis clients via ``redis_async_ctx_factory`` /
    ``redis_sync_client_factory`` to drive the invalidation deterministically
    without a live broker.
    """

    def __init__(
        self,
        emitter: Any = None,
        cache_ttl: float = 60.0,
        *,
        redis_async_ctx_factory: (
            Callable[[], AbstractAsyncContextManager[_AsyncRedisLike]] | None
        ) = None,
        redis_sync_client_factory: Callable[[], _SyncRedisLike | None] | None = None,
        invalidation_key: str = _INVALIDATION_VERSION_KEY,
        version_poll_interval: float = _VERSION_POLL_INTERVAL_S,
    ) -> None:
        self._schemas: dict[str, type[BaseModel]] = {}
        self._emitter = emitter
        self._cache_ttl = cache_ttl
        self._cache: dict[tuple[str, str], _CacheEntry] = {}
        self._cache_lock = asyncio.Lock()
        # Cross-process invalidation state (#56). ``_known_version`` is what
        # this process last observed for the shared Redis counter;
        # ``_known_version_polled_at`` throttles the Redis GET so a hot get
        # loop doesn't fan out one Redis round-trip per call.
        self._redis_async_ctx_factory = redis_async_ctx_factory
        self._redis_sync_client_factory = redis_sync_client_factory
        self._invalidation_key = invalidation_key
        self._version_poll_interval = version_poll_interval
        self._known_version: int = 0
        # -inf forces the first get to fetch the current version (no stale
        # window before the first poll).
        self._known_version_polled_at: float = -math.inf
        # Lazily-built sync redis.Redis client (from AILA_PLATFORM_REDIS_URL);
        # cached per-instance so repeated get_sync() calls reuse the socket.
        self._sync_redis_client: _SyncRedisLike | None | _Missing = _MISSING

    def _is_security_relevant(self, key: str) -> bool:
        """Check if a config key is security-relevant for audit logging (D-11, D-13).

        Uses prefix matching for D-11 prefixes and a substring check for
        fail_mode patterns (avoids overly broad llm_pipeline_ prefix).
        """
        if any(key.startswith(p) for p in _SECURITY_KEY_PREFIXES):
            return True
        return "_fail_mode_" in key

    # ------------------------------------------------------------------
    # Cross-process invalidation helpers (#56)
    # ------------------------------------------------------------------

    def _resolve_async_redis_ctx(
        self,
    ) -> AbstractAsyncContextManager[_AsyncRedisLike] | None:
        """Return an async CM yielding a Redis client, or None if unavailable.

        Preference order: constructor-injected factory (used by tests) >
        platform ``get_redis()`` pool. Any exception during resolution is
        swallowed -- Redis absence must NOT crash a config read.
        """
        if self._redis_async_ctx_factory is not None:
            try:
                return self._redis_async_ctx_factory()
            except (OSError, RuntimeError):
                _log.debug(
                    "ConfigRegistry: injected async redis factory raised",
                    exc_info=True,
                )
                return None
        try:
            from ..platform.services.redis_pool import get_redis, pool_available
        except ImportError:
            _log.debug(
                "ConfigRegistry: redis_pool not importable", exc_info=True
            )
            return None
        if not pool_available():
            return None
        try:
            return get_redis()
        except (OSError, RuntimeError):
            _log.debug("ConfigRegistry: get_redis() raised", exc_info=True)
            return None

    def _resolve_sync_redis_client(self) -> _SyncRedisLike | None:
        """Return a sync Redis client, or None if unavailable. Cached per instance.

        Preference: constructor-injected factory > ``redis.Redis.from_url`` on
        ``AILA_PLATFORM_REDIS_URL``. A resolved None is cached so the second
        get_sync doesn't re-attempt the import + env read on every call.
        """
        if self._redis_sync_client_factory is not None:
            try:
                return self._redis_sync_client_factory()
            except (OSError, RuntimeError):
                _log.debug(
                    "ConfigRegistry: injected sync redis factory raised",
                    exc_info=True,
                )
                return None
        if not isinstance(self._sync_redis_client, _Missing):
            return self._sync_redis_client
        url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
        if not url:
            self._sync_redis_client = None
            return None
        try:
            import redis

            client = redis.Redis.from_url(
                url,
                socket_connect_timeout=2.0,
                socket_timeout=2.0,
                decode_responses=False,
            )
        except (ImportError, OSError, RuntimeError, ValueError):
            _log.debug(
                "ConfigRegistry: sync redis client build failed", exc_info=True
            )
            self._sync_redis_client = None
            return None
        self._sync_redis_client = client
        return client

    @staticmethod
    def _coerce_version(raw: Any) -> int | None:
        """Parse Redis GET result into an int. Handles bytes/str/None uniformly.

        Returns None on any parse failure -- callers keep last-known version.
        """
        if raw is None:
            return 0
        if isinstance(raw, (bytes, bytearray)):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError:
                _log.debug(
                    "ConfigRegistry: version key bytes are not valid utf-8",
                    exc_info=True,
                )
                return None
        try:
            return int(raw)
        except (TypeError, ValueError):
            _log.debug("ConfigRegistry: version key value %r is not an int", raw)
            return None

    async def _current_version_async(self) -> int:
        """Return the current cross-process invalidation counter, throttled.

        Skips the Redis GET when the last poll is within
        ``version_poll_interval`` seconds. On Redis absence / failure returns
        the last-known version (never raises).
        """
        now = time.monotonic()
        if (now - self._known_version_polled_at) < self._version_poll_interval:
            return self._known_version
        ctx = self._resolve_async_redis_ctx()
        if ctx is None:
            # Nothing to poll; mark polled so we don't spin trying to resolve.
            self._known_version_polled_at = now
            return self._known_version
        try:
            async with ctx as client:
                raw = await client.get(self._invalidation_key)
        except _REDIS_ERRORS:
            _log.debug(
                "ConfigRegistry: async version poll failed", exc_info=True
            )
            self._known_version_polled_at = now
            return self._known_version
        version = self._coerce_version(raw)
        if version is not None:
            self._known_version = version
        self._known_version_polled_at = now
        return self._known_version

    def _current_version_sync(self) -> int:
        """Sync twin of :meth:`_current_version_async`."""
        now = time.monotonic()
        if (now - self._known_version_polled_at) < self._version_poll_interval:
            return self._known_version
        client = self._resolve_sync_redis_client()
        if client is None:
            self._known_version_polled_at = now
            return self._known_version
        try:
            raw = client.get(self._invalidation_key)
        except _REDIS_ERRORS:
            _log.debug(
                "ConfigRegistry: sync version poll failed", exc_info=True
            )
            self._known_version_polled_at = now
            return self._known_version
        version = self._coerce_version(raw)
        if version is not None:
            self._known_version = version
        self._known_version_polled_at = now
        return self._known_version

    async def _bump_version_async(self) -> int:
        """Publish an invalidation signal via ``INCR`` on the shared key.

        Called from :meth:`set` after a successful DB write. Redis absence /
        failure is logged and swallowed -- the local ``set`` still succeeded
        and peer processes will drop stale entries when their TTL elapses,
        matching the pre-#56 behavior.
        """
        ctx = self._resolve_async_redis_ctx()
        if ctx is None:
            return self._known_version
        try:
            async with ctx as client:
                new_version_raw = await client.incr(self._invalidation_key)
        except _REDIS_ERRORS:
            _log.debug(
                "ConfigRegistry: async version bump failed", exc_info=True
            )
            return self._known_version
        parsed = self._coerce_version(new_version_raw)
        if parsed is not None:
            self._known_version = parsed
            self._known_version_polled_at = time.monotonic()
        return self._known_version

    def _resolve_field(self, namespace: str, key: str) -> Any:
        """Resolve a key to a field descriptor for casting/validation.

        Returns the static schema ``FieldInfo`` when the key is a declared
        field, else the longest-matching dynamic-key family's descriptor, else
        None. None means the key is unknown to the namespace -- ``set`` rejects
        it and ``get`` yields no schema default.
        """
        schema = self._schemas.get(namespace)
        if schema is None:
            return None
        field_info = schema.model_fields.get(key)
        if field_info is not None:
            return field_info
        best: DynamicKeyFamily | None = None
        for family in getattr(schema, "__dynamic_families__", ()):
            if family.matches(key) and (best is None or len(family.prefix) > len(best.prefix)):
                best = family
        if best is None:
            return None
        return _ResolvedField(annotation=best.value_type, default=best.default)

    async def register(self, namespace: str, schema_class: type[BaseModel]) -> None:
        """Register a Pydantic schema for namespace. Persists defaults to DB on
        first registration -- existing DB rows are left unchanged (user overrides
        survive re-registration)."""
        self._schemas[namespace] = schema_class
        defaults = schema_class()
        async with async_session_scope() as session:
            for field_name, field_info in schema_class.model_fields.items():
                existing = (await session.exec(
                    select(ConfigEntryRecord).where(
                        ConfigEntryRecord.namespace == namespace,
                        ConfigEntryRecord.key == field_name,
                    )
                )).first()
                if existing is None:
                    raw_value = getattr(defaults, field_name)
                    session.add(
                        ConfigEntryRecord(
                            namespace=namespace,
                            key=field_name,
                            value=str(raw_value),
                            value_type=type(raw_value).__name__,
                        )
                    )
            await session.commit()

    async def get(self, namespace: str, key: str) -> Any:
        """Resolve: env var > cache > DB value > schema default.
        Env var format: AILA_{NAMESPACE}_{KEY} uppercased.
        Returns the value cast to the schema field's type, or raw string if
        no schema is registered for namespace.

        Cross-process invalidation (#56): the throttled Redis version poll
        happens BEFORE the cache read; a fresher version drops the entry
        (treated as a cache miss) forcing a DB refetch.
        """
        env_name = f"AILA_{namespace.upper()}_{key.upper()}"
        env_val = os.environ.get(env_name)

        field_info = self._resolve_field(namespace, key)

        if env_val is not None:
            return _cast_value(env_val, field_info)

        # #56: fetch current cross-process version (throttled). A newer
        # version than what our entry was tagged with means a peer worker
        # set() the key since we cached -- treat the entry as expired.
        current_version = await self._current_version_async()

        # Check cache (D-06: LRU with TTL)
        cache_key = (namespace, key)
        async with self._cache_lock:
            entry = self._cache.get(cache_key)
            if entry is not None:
                if entry.version_at_populate < current_version:
                    # Cross-process invalidation: peer wrote after we cached.
                    self._cache.pop(cache_key, None)
                elif time.monotonic() < entry.expires_at:
                    return entry.value

        # Cache miss or expired -- fetch from DB
        async with async_session_scope() as session:
            row = (await session.exec(
                select(ConfigEntryRecord).where(
                    ConfigEntryRecord.namespace == namespace,
                    ConfigEntryRecord.key == key,
                )
            )).first()
            if row is not None:
                value = _cast_value(row.value, field_info)
                # Populate cache
                async with self._cache_lock:
                    self._cache[cache_key] = _CacheEntry(
                        value=value,
                        expires_at=time.monotonic() + self._cache_ttl,
                        version_at_populate=current_version,
                    )
                return value

        if field_info is not None:
            default_val = field_info.default
            # Cache the default too
            async with self._cache_lock:
                self._cache[cache_key] = _CacheEntry(
                    value=default_val,
                    expires_at=time.monotonic() + self._cache_ttl,
                    version_at_populate=current_version,
                )
            return default_val
        return None

    def get_sync(self, namespace: str, key: str) -> Any:
        """Synchronous twin of :meth:`get` for sync call sites.

        Same resolution order (env var > cache > DB value > schema default) as
        the async ``get``, but usable from a plain ``def`` without producing an
        un-awaited coroutine. Sync call sites (proxy resolution, budget ceiling,
        worker bootstrap) previously called ``get`` without ``await`` and either
        guarded with ``hasattr(x, "__await__")`` or -- when they forgot --
        operated on the coroutine object itself (issue #65/#38).

        The DB read uses the sync engine via ``session_scope`` (psycopg). Cache
        access is lock-free by design: dict get/set are atomic under the GIL and
        the check-then-populate race is benign -- at worst a redundant DB read
        and an idempotent overwrite with the same value. The async ``_cache_lock``
        cannot be acquired from a sync context, so it is intentionally not used
        here.
        """
        env_name = f"AILA_{namespace.upper()}_{key.upper()}"
        env_val = os.environ.get(env_name)

        field_info = self._resolve_field(namespace, key)

        if env_val is not None:
            return _cast_value(env_val, field_info)

        # #56: cross-process invalidation check. Sync path uses a lazy
        # ``redis.Redis`` client from AILA_PLATFORM_REDIS_URL; failure or
        # absence keeps the last-known version (TTL fallback).
        current_version = self._current_version_sync()

        cache_key = (namespace, key)
        entry = self._cache.get(cache_key)
        if entry is not None:
            if entry.version_at_populate < current_version:
                # Cross-process invalidation: peer wrote after we cached.
                self._cache.pop(cache_key, None)
            elif time.monotonic() < entry.expires_at:
                return entry.value

        with session_scope() as session:
            row = session.exec(
                select(ConfigEntryRecord).where(
                    ConfigEntryRecord.namespace == namespace,
                    ConfigEntryRecord.key == key,
                )
            ).first()
            if row is not None:
                value = _cast_value(row.value, field_info)
                self._cache[cache_key] = _CacheEntry(
                    value=value,
                    expires_at=time.monotonic() + self._cache_ttl,
                    version_at_populate=current_version,
                )
                return value

        if field_info is not None:
            default_val = field_info.default
            self._cache[cache_key] = _CacheEntry(
                value=default_val,
                expires_at=time.monotonic() + self._cache_ttl,
                version_at_populate=current_version,
            )
            return default_val
        return None

    def describe_resolution(
        self, namespace: str, key: str, *, db_value: str | None
    ) -> ConfigResolution:
        """Return the raw env/DB/default contributions and the effective value.

        Mirrors ``get``/``get_sync`` precedence exactly (env var > DB row >
        schema default) but performs NO DB read: the caller passes ``db_value``
        (the ``ConfigEntryRecord.value`` it already holds, or None when there
        is no row). Response builders use this to surface WHICH source is live
        alongside the stored fallback -- the transparency that ``get`` hides.
        """
        env_key = f"AILA_{namespace.upper()}_{key.upper()}"
        env_value = os.environ.get(env_key)

        field_info = self._resolve_field(namespace, key)
        default_value: str | None = None
        if field_info is not None:
            raw_default = getattr(field_info, "default", None)
            if raw_default is not None and raw_default is not PydanticUndefined:
                default_value = str(raw_default)

        if env_value is not None:
            return ConfigResolution(
                env_key=env_key,
                env_value=env_value,
                db_value=db_value,
                default_value=default_value,
                effective_value=env_value,
                source="env",
            )
        if db_value is not None:
            return ConfigResolution(
                env_key=env_key,
                env_value=None,
                db_value=db_value,
                default_value=default_value,
                effective_value=db_value,
                source="db",
            )
        if default_value is not None:
            return ConfigResolution(
                env_key=env_key,
                env_value=None,
                db_value=None,
                default_value=default_value,
                effective_value=default_value,
                source="default",
            )
        return ConfigResolution(
            env_key=env_key,
            env_value=None,
            db_value=None,
            default_value=None,
            effective_value="",
            source="default",
        )

    async def set(self, namespace: str, key: str, value: str) -> None:
        """Persist value to DB after type-validating against registered schema.
        Raises ValueError if namespace/key is not in any registered schema.
        Raises ValueError if value cannot be cast to the field's declared type.

        For security-relevant keys (D-11), emits a config_security_change
        PlatformEvent with old and new values after a successful write (D-12).
        """
        schema = self._schemas.get(namespace)
        if schema is None:
            raise ValueError(f"No schema registered for namespace '{namespace}'.")
        field_info = self._resolve_field(namespace, key)
        if field_info is None:
            raise ValueError(f"Key '{key}' not found in schema for namespace '{namespace}'.")

        # Validate by casting -- raises ValueError on bad input
        _cast_value(value, field_info)

        # Capture old value BEFORE write for audit (D-12: read old before write)
        old_value = await self.get(namespace, key)

        # OPS-07: Skip write if value is unchanged (config idempotency)
        cast_new = _cast_value(value, field_info)
        if old_value == cast_new:
            _log.debug("Config %s/%s unchanged, skipping write", namespace, key)
            return

        value_type = _field_type_name(field_info)
        async with async_session_scope() as session:
            row = (await session.exec(
                select(ConfigEntryRecord).where(
                    ConfigEntryRecord.namespace == namespace,
                    ConfigEntryRecord.key == key,
                )
            )).first()
            if row is None:
                session.add(ConfigEntryRecord(
                    namespace=namespace,
                    key=key,
                    value=value,
                    value_type=value_type,
                ))
            else:
                row.value = value
                row.value_type = value_type
                row.updated_at = utc_now()
                session.add(row)
            await session.commit()

        # Invalidate cache on write (D-06)
        async with self._cache_lock:
            self._cache.pop((namespace, key), None)

        # #56: broadcast the invalidation to peer processes. Redis absence
        # falls back to the pre-#56 behavior: local set() succeeded, peers
        # will pick up the change when their per-key TTL (cache_ttl) elapses.
        await self._bump_version_async()

        # Emit audit event AFTER successful write (D-12, D-14). Security
        # keys carry the redacted values; every write additionally publishes
        # a typed ConfigChanged domain event on the shared bus (RFC #134) so
        # the process-wide journal + Redis cross-process fanout subscribers
        # see the config change without any per-caller wiring. The typed
        # publish is fail-open: a broken bus never blocks the write.
        if self._is_security_relevant(key):
            from ..platform.events.event import PlatformEvent

            secret = is_secret_config_key(key)
            old_display = (
                _REDACTED if secret else (str(old_value) if old_value is not None else "")
            )
            new_display = _REDACTED if secret else value
            if self._emitter is not None:
                self._emitter.emit(PlatformEvent(
                    stage="config_security_change",
                    action="update",
                    key=f"config.{namespace}.{key}",
                    message=f"Security config changed: {namespace}/{key}",
                    details={
                        "namespace": namespace,
                        "key": key,
                        "old_value": old_display,
                        "new_value": new_display,
                        "value_hash_sha256": (
                            _hash_config_change(old_value, value) if secret else None
                        ),
                        "user_id": "system",
                    },
                ))
            try:
                from ..platform.events import (
                    ConfigChanged,
                    ConfigChangedPayload,
                    publish,
                )

                publish(ConfigChanged(
                    source_module="platform.config",
                    payload=ConfigChangedPayload(
                        namespace=namespace,
                        key=key,
                        old_value=old_display,
                        new_value=new_display,
                    ),
                ))
            except (RuntimeError, OSError, TimeoutError, ValueError, TypeError) as exc:
                _log.warning(
                    "config domain-event publish failed for %s/%s: %s",
                    namespace, key, exc,
                )

    async def all_entries_by_namespace(self) -> dict[str, dict[str, object]]:
        """Resolve all config values grouped by namespace.

        Returns {namespace: {key: resolved_value}}. Used by
        build_platform_runtime() to pre-resolve config for sync build_runtime() calls.
        """
        result: dict[str, dict[str, object]] = {}
        for namespace, schema in self._schemas.items():
            ns_dict: dict[str, object] = {}
            for key in schema.model_fields:
                ns_dict[key] = await self.get(namespace, key)
            result[namespace] = ns_dict
        return result

    async def warm_cache(self) -> None:
        """Pre-populate cache from all registered config values. Call at startup per D-06.

        Tags every entry with the current cross-process invalidation version
        (#56) so a warmed cache is subject to the same peer-write drop as
        entries populated by :meth:`get`.
        """
        all_values = await self.all_entries_by_namespace()
        current_version = await self._current_version_async()
        expires_at = time.monotonic() + self._cache_ttl
        async with self._cache_lock:
            for namespace_name, entries in all_values.items():
                for key_name, value in entries.items():
                    self._cache[(namespace_name, key_name)] = _CacheEntry(
                        value=value,
                        expires_at=expires_at,
                        version_at_populate=current_version,
                    )

    async def all_entries(self) -> list[dict[str, Any]]:
        """Return all registered entries for CLI display.
        Each dict: {namespace, key, value, value_type, updated_at, source}.
        source is 'env' if an env var override is active, else 'db'."""
        result = []
        async with async_session_scope() as session:
            rows = (await session.exec(select(ConfigEntryRecord))).all()
            for row in sorted(rows, key=lambda r: (r.namespace, r.key)):
                env_name = f"AILA_{row.namespace.upper()}_{row.key.upper()}"
                source = "env" if os.environ.get(env_name) is not None else "db"
                resolved = await self.get(row.namespace, row.key)
                result.append({
                    "namespace": row.namespace,
                    "key": row.key,
                    "value": str(resolved),
                    "value_type": row.value_type,
                    "updated_at": row.updated_at.isoformat(),
                    "source": source,
                })
        return result


class SchemaRegistry:
    """Push-based registry for SQLModel table classes.

    Modules call push() during register_tools(); the platform calls
    create_all(engine) once during init_db(). No filesystem crawl.
    """

    def __init__(self) -> None:
        self._models: list[type] = []

    def push(self, *model_classes: type) -> None:
        """Register one or more SQLModel table classes. Duplicates are ignored."""
        for cls in model_classes:
            if cls not in self._models:
                self._models.append(cls)

    def create_all(self, engine: object) -> None:
        """Call SQLModel.metadata.create_all(engine) restricted to registered tables.

        Only tables whose metadata is touched by push() are created. Platform
        tables (storage/db_models.py) are registered separately via
        _push_platform_models() in init_db().
        """
        from sqlalchemy.exc import OperationalError
        from sqlmodel import SQLModel

        tables = []
        for cls in self._models:
            table = getattr(cls, "__table__", None)
            if table is not None:
                tables.append(table)
        try:
            SQLModel.metadata.create_all(engine, tables=tables if tables else None)
        except OperationalError as exc:
            if "already exists" not in str(exc).lower():
                raise

    def create_all_with_connection(self, connection: object) -> None:
        """Create registered tables bound to a live sync Connection.

        Used by ``init_db`` inside ``conn.run_sync(...)`` on the async engine.
        ``SQLModel.metadata.create_all`` accepts either an Engine or a
        Connection as its bind, so this delegates to :meth:`create_all`.
        ``checkfirst`` is on by default, so it is idempotent against an
        already-migrated database -- existing tables are left untouched.
        """
        self.create_all(connection)


def _cast_value(raw: str, field_info: Any) -> Any:
    """Cast a string value to the field's declared type.
    Supports str, int, float, bool. Raises ValueError on failure."""
    type_name = _field_type_name(field_info)
    if type_name == "int":
        return int(raw)
    if type_name == "float":
        return float(raw)
    if type_name == "bool":
        normalized = raw.strip().lower()
        if normalized in ("true", "1", "yes"):
            return True
        if normalized in ("false", "0", "no"):
            return False
        raise ValueError(f"Cannot parse {raw!r} as bool.")
    return str(raw)


def _field_type_name(field_info: Any) -> str:
    """Extract the simple type name from a Pydantic FieldInfo."""
    if field_info is None:
        return "str"
    annotation = getattr(field_info, "annotation", None)
    if annotation is int:
        return "int"
    if annotation is float:
        return "float"
    if annotation is bool:
        return "bool"
    return "str"
