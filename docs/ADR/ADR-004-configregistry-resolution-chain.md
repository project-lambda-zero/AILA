# ADR-004: ConfigRegistry Three-Layer Resolution Chain

**Status:** Accepted
**Date:** 2025 (v1.5)
**Supersedes:** None

## Context

AILA needs runtime-configurable settings that can be changed without restarting the server.
The platform has two categories of configuration:

1. **Infrastructure settings** -- Database URL, JWT secret, API host/port. These are process-level
   and read once at startup. Managed by `Settings` dataclass in `config.py`.
2. **Runtime settings** -- Heartbeat intervals, Redis URL, HTTP proxy, routing confidence thresholds.
   These should be changeable via API without restart. Managed by `ConfigRegistry`.

The challenge: runtime config must support three deployment patterns:

- **Development**: Schema defaults are fine, no config needed
- **Production (env vars)**: Inject config via environment variables (container orchestrators)
- **Runtime tuning**: Change values via `PUT /config/{namespace}/{key}` while running

## Decision

Implement a **three-layer resolution chain** in `ConfigRegistry.get()`:

```
1. Environment variable:  AILA_{NAMESPACE}_{KEY}  (uppercased)
2. Database row:          ConfigEntryRecord(namespace, key)
3. Schema default:        Pydantic BaseModel field default
```

### How it works

**Registration:**

Modules call `registry.register(namespace, schema_class)` at startup. For each field in
the Pydantic schema, if no `ConfigEntryRecord` row exists, one is created with the schema
default value. Existing rows are never overwritten (operator overrides survive re-registration).

**Resolution (`get`):**

```python
def get(namespace, key):
    # 1. Check env var
    env_val = os.environ.get(f"AILA_{namespace.upper()}_{key.upper()}")
    if env_val is not None:
        return cast(env_val, field_type)

    # 2. Check DB row
    row = query(ConfigEntryRecord, namespace=namespace, key=key)
    if row is not None:
        return cast(row.value, field_type)

    # 3. Fall back to schema default
    return schema_class().field_default
```

**Mutation (`set`):**

`registry.set(namespace, key, value)` validates the value against the schema field type,
then persists to `ConfigEntryRecord`. Raises `ValueError` for unknown namespace/key or
type mismatch. The API router catches `ValueError` and returns 422.

**Type casting:**

Values are stored as strings in the DB. `_cast_value()` converts to the field's declared
type: `str`, `int`, `float`, or `bool`. Bool accepts `true/1/yes` and `false/0/no`.

### Separation from Settings

`Settings` (8 fields) is the infrastructure layer -- read once, cached via `lru_cache`.
`ConfigRegistry` is the runtime layer -- read per-request, mutable via API.

Settings fields are NOT in ConfigRegistry. ConfigRegistry fields are NOT in Settings.
This prevents confusion about which layer owns a value.

## Consequences

### Positive

- Environment variables always win (container orchestrators can override anything)
- DB values are mutable at runtime without restart
- Schema defaults mean zero config needed for development
- Type safety: values are validated against schema field types on write and cast on read
- Modules declare their own schemas without touching platform code

### Negative

- Three layers can be confusing ("where does this value come from?")
  -- Mitigated by `all_entries()` which reports the active source (`env` or `db`)
- String storage in DB requires type casting on every read
- No schema evolution mechanism (adding a field to a schema auto-seeds, but removing one leaves orphaned DB rows)

### Neutral

- `PlatformConfigSchema` is the platform's own config (Redis URL, heartbeat, JWT expiry, etc.)
- Modules register under their own namespace (e.g., `vulnerability`)
- `GET /config` lists all entries with their resolved values and sources

## References

- `src/aila/storage/registry.py` -- ConfigRegistry implementation
- `src/aila/storage/db_models.py` -- ConfigEntryRecord table
- `src/aila/platform/config.py` -- PlatformConfigSchema, build_platform_settings
- `src/aila/api/routers/config.py` -- Config API router (GET, PUT)
- Phase 66: Config router deep review
- Phase 84: get_task_tuning reads ConfigEntryRecord directly
- Phase 101: Config read-through verification (interleaved write/read)
