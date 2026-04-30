"""Module-config and DB-schema registries for the AILA platform.

Two registries are provided:

ConfigRegistry — typed module configuration.
    Modules call register() during register_tools() to declare their config
    schema (a Pydantic BaseModel subclass).  Default values are written to
    ConfigEntryRecord on first registration.  Callers resolve values via
    get(namespace, key) which follows the chain: env var > DB row > schema default.
    build_platform_settings() reads from this registry; Settings only carries
    the infrastructure fields that are NOT managed here.

SchemaRegistry — SQLModel table registration.
    Modules call push() during register_tools() to register their SQLModel table
    classes.  init_db() calls create_all(engine) to create only those tables.
    No filesystem crawl — all registration is explicit and happens at startup.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass as _dc_dataclass
from typing import Any

from pydantic import BaseModel
from sqlmodel import select

from ..platform.contracts._common import utc_now
from .database import async_session_scope
from .db_models import ConfigEntryRecord

__all__ = ["ConfigRegistry", "SchemaRegistry"]

_log = logging.getLogger(__name__)


@_dc_dataclass
class _CacheEntry:
    """Single cached config value with monotonic expiry timestamp."""

    value: Any
    expires_at: float


# Security-relevant config key prefixes that trigger audit logging on change (D-11).
_SECURITY_KEY_PREFIXES: tuple[str, ...] = (
    "llm_kill_switch",
    "llm_model_",
    "llm_pipeline_classify_",
    "llm_pipeline_gate_",
    "llm_seal_hmac_key",
)


class ConfigRegistry:
    """Central registry for module config schemas. Thread-safe for reads; callers
    are responsible for not calling register() concurrently (registration happens
    at startup, single-threaded)."""

    def __init__(self, emitter: Any = None, cache_ttl: float = 60.0) -> None:
        self._schemas: dict[str, type[BaseModel]] = {}
        self._emitter = emitter
        self._cache_ttl = cache_ttl
        self._cache: dict[tuple[str, str], _CacheEntry] = {}
        self._cache_lock = asyncio.Lock()

    def _is_security_relevant(self, key: str) -> bool:
        """Check if a config key is security-relevant for audit logging (D-11, D-13).

        Uses prefix matching for D-11 prefixes and a substring check for
        fail_mode patterns (avoids overly broad llm_pipeline_ prefix).
        """
        if any(key.startswith(p) for p in _SECURITY_KEY_PREFIXES):
            return True
        return "_fail_mode_" in key

    async def register(self, namespace: str, schema_class: type[BaseModel]) -> None:
        """Register a Pydantic schema for namespace. Persists defaults to DB on
        first registration — existing DB rows are left unchanged (user overrides
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
        no schema is registered for namespace."""
        env_name = f"AILA_{namespace.upper()}_{key.upper()}"
        env_val = os.environ.get(env_name)

        schema = self._schemas.get(namespace)
        field_info = schema.model_fields.get(key) if schema else None

        if env_val is not None:
            return _cast_value(env_val, field_info)

        # Check cache (D-06: LRU with TTL)
        cache_key = (namespace, key)
        async with self._cache_lock:
            entry = self._cache.get(cache_key)
            if entry is not None and time.monotonic() < entry.expires_at:
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
                    )
                return value

        if schema and field_info is not None:
            default_val = schema().model_fields[key].default
            # Cache the default too
            async with self._cache_lock:
                self._cache[cache_key] = _CacheEntry(
                    value=default_val,
                    expires_at=time.monotonic() + self._cache_ttl,
                )
            return default_val
        return None

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
        field_info = schema.model_fields.get(key)
        if field_info is None:
            raise ValueError(f"Key '{key}' not found in schema for namespace '{namespace}'.")

        # Validate by casting — raises ValueError on bad input
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

        # Emit audit event AFTER successful write (D-12, D-14)
        if self._emitter is not None and self._is_security_relevant(key):
            from ..platform.events.event import PlatformEvent

            self._emitter.emit(PlatformEvent(
                stage="config_security_change",
                action="update",
                key=f"config.{namespace}.{key}",
                message=f"Security config changed: {namespace}/{key}",
                details={
                    "namespace": namespace,
                    "key": key,
                    "old_value": str(old_value) if old_value is not None else "",
                    "new_value": value,
                    "user_id": "system",
                },
            ))

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
        """Pre-populate cache from all registered config values. Call at startup per D-06."""
        all_values = await self.all_entries_by_namespace()
        expires_at = time.monotonic() + self._cache_ttl
        async with self._cache_lock:
            for namespace_name, entries in all_values.items():
                for key_name, value in entries.items():
                    self._cache[(namespace_name, key_name)] = _CacheEntry(
                        value=value,
                        expires_at=expires_at,
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
