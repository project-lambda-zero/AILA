# ConfigRegistry Guide

Runtime-configurable settings for AILA. Values can be changed without restarting
the server, inspected via API, and overridden by environment variables.

---

## What Is ConfigRegistry

ConfigRegistry is a typed key-value store backed by SQLite (`ConfigEntryRecord` table).
It stores runtime-tunable settings that modules and the platform declare via Pydantic
schemas. Unlike `Settings` (8 infrastructure fields, read once at startup),
ConfigRegistry values are resolved on every access and can be changed at runtime
via the `/config` API.

**Source:** `src/aila/storage/registry.py`

---

## Resolution Chain

When `ConfigRegistry.get(namespace, key)` is called, the value is resolved in this order:

```
1. Environment variable   AILA_{NAMESPACE}_{KEY}  (uppercased)
2. Database row           ConfigEntryRecord(namespace, key)
3. Schema field default   Pydantic model field default
```

**Environment variables always win.** This enables container orchestrators (Docker,
Kubernetes) to inject config without touching the database.

**Database values** are set via `PUT /config/{namespace}/{key}` and take effect
immediately on the next read. No server restart needed.

**Schema defaults** are the fallback when neither env var nor DB row exists.

### Type casting

All values are stored as strings in the database. On read, `_cast_value()` converts
to the field's declared type:

| Python Type | Accepted Values | Example |
|-------------|-----------------|---------|
| `str` | Any string | `"AILA/1.5.0"` |
| `int` | Numeric string | `"30"` -> `30` |
| `float` | Numeric string | `"0.2"` -> `0.2` |
| `bool` | `true/1/yes` or `false/0/no` | `"true"` -> `True` |

Invalid casts raise `ValueError`, which the config router converts to HTTP 422.

---

## How To Read Config Values

### From application code

```python
# Direct ConfigRegistry access (requires a registry instance)
value = config_registry.get("platform", "redis_url")

# Via get_task_tuning (convenience for platform namespace int values)
from aila.platform.tasks import get_task_tuning
interval = get_task_tuning("heartbeat_interval_s", 30)
```

`get_task_tuning` queries `ConfigEntryRecord` directly for the `platform` namespace.
It falls back to the provided default if the DB is unavailable (tests, startup, sync fallback).

### From the API

```
GET /config
```

Returns all registered config entries with their resolved values and sources:

```json
[
  {
    "namespace": "platform",
    "key": "redis_url",
    "value": "redis://localhost:6379",
    "value_type": "str",
    "updated_at": "2025-01-15T10:30:00",
    "source": "db"
  },
  {
    "namespace": "platform",
    "key": "heartbeat_interval_s",
    "value": "30",
    "value_type": "int",
    "updated_at": "2025-01-15T10:30:00",
    "source": "env"
  }
]
```

The `source` field shows whether the active value comes from an env var (`env`) or the
database (`db`). When `source` is `env`, the DB value is shadowed.

### From environment variables

Set `AILA_{NAMESPACE}_{KEY}` (uppercased) to override any ConfigRegistry value:

```bash
export AILA_PLATFORM_REDIS_URL=redis://localhost:6379
export AILA_PLATFORM_HEARTBEAT_INTERVAL_S=60
```

---

## How To Change Config At Runtime

### Via API

```
PUT /config/{namespace}/{key}
Content-Type: application/json

{"value": "60"}
```

Requires `admin` role. The value is validated against the registered schema field type.
Invalid values return 422. Unknown namespace or key returns 422 (ValueError from
`ConfigRegistry.set()`).

### Via environment variable

Set the env var and restart the process. The env var takes precedence over DB values,
so the runtime API change is effectively masked.

---

## How To Add a New Configurable Value

End-to-end walkthrough: adding a `max_retries` integer field to the platform config.

### Step 1: Add the field to the schema

Edit `src/aila/platform/config.py`:

```python
class PlatformConfigSchema(BaseModel):
    # ... existing fields ...
    max_retries: int = 5  # New field with default
```

### Step 2: Registration happens automatically

`PlatformConfigSchema` is registered under namespace `"platform"` during platform
startup via `register_tools()`. When the platform starts, `ConfigRegistry.register()`
iterates all fields and creates a `ConfigEntryRecord` row for `max_retries` with
value `"5"` and `value_type="int"`.

If the row already exists (from a previous start), it is left unchanged -- operator
overrides survive schema re-registration.

### Step 3: Read the value

```python
# Option A: Via ConfigRegistry instance
max_retries = config_registry.get("platform", "max_retries")  # Returns int

# Option B: Via get_task_tuning (convenience for platform int fields)
from aila.platform.tasks import get_task_tuning
max_retries = get_task_tuning("max_retries", 5)
```

### Step 4: Override via env var (optional)

```bash
export AILA_PLATFORM_MAX_RETRIES=10
```

This takes precedence over any DB-stored value.

### Step 5: Override via API (optional)

```
PUT /config/platform/max_retries
{"value": "10"}
```

Requires admin role. Takes effect immediately on next read.

---

## Platform Config Fields

The `platform` namespace is registered with `PlatformConfigSchema`. All fields:

| Key | Type | Default | Purpose |
|-----|------|---------|---------|
| `request_timeout_seconds` | float | `20.0` | HTTP timeout for provider requests |
| `user_agent` | str | `AILA/{version}` | User-Agent header for outbound HTTP |
| `routing_min_confidence` | float | `0.2` | Minimum routing confidence threshold |
| `routing_decision_cache_ttl_hours` | int | `72` | Routing decision cache TTL (hours) |
| `http_proxy` | str | `""` | HTTP proxy URL (empty = no proxy) |
| `https_proxy` | str | `""` | HTTPS proxy URL (empty = no proxy) |
| `redis_url` | str | `""` | Redis connection URL (empty = sync fallback) |
| `jwt_access_expiry_s` | int | `2592000` | JWT access token lifetime (seconds) |
| `jwt_refresh_expiry_s` | int | `7776000` | JWT refresh token lifetime (seconds) |
| `heartbeat_interval_s` | int | `30` | Worker heartbeat write interval |
| `reaper_zombie_threshold_s` | int | `120` | Zombie task detection threshold |
| `arq_job_timeout_s` | int | `3600` | Maximum ARQ job execution time |
| `arq_max_tries` | int | `3` | Maximum retry attempts for failed jobs |
| `arq_keep_result_s` | int | `3600` | Job result retention in Redis |
| `progress_stream_maxlen` | int | `1000` | Max events per Redis progress stream |

---

## Module Config Schemas

Modules register their own config schemas under their own namespace. For example,
the vulnerability module might register a `VulnerabilityConfigSchema` under
namespace `"vulnerability"`.

### How modules register

In the module's `register_tools()` method:

```python
def register_tools(self, tool_registry, config_registry, schema_registry):
    config_registry.register("vulnerability", VulnerabilityConfigSchema)
```

This creates `ConfigEntryRecord` rows for each field in `VulnerabilityConfigSchema`
under the `vulnerability` namespace.

### Accessing module config

```python
value = config_registry.get("vulnerability", "some_field")
```

Or via env var:

```bash
export AILA_VULNERABILITY_SOME_FIELD=new_value
```

---

## ConfigRegistry vs Settings

| Aspect | Settings | ConfigRegistry |
|--------|----------|----------------|
| **Purpose** | Infrastructure (DB, JWT secret, API bind) | Runtime tuning (timeouts, intervals, URLs) |
| **Fields** | 8 fixed fields | Extensible via schemas |
| **Read pattern** | Once at startup, cached via `lru_cache` | Per access, resolved each time |
| **Mutation** | Process restart required | API or env var, no restart |
| **Source** | `src/aila/config.py` | `src/aila/storage/registry.py` |
| **Env var pattern** | `AILA_{FIELD}` (e.g., `AILA_API_PORT`) | `AILA_{NS}_{KEY}` (e.g., `AILA_PLATFORM_REDIS_URL`) |

Do not add module-specific fields to Settings. Do not add infrastructure fields to ConfigRegistry.

---

## Diagnostics

### Check current config values

```
GET /config
```

The response includes `source` (`env` or `db`) for each entry, showing where
the active value originates.

### Check if env var is overriding

If `source` is `"env"`, the database value is being shadowed by an environment variable.
Remove the env var to let the DB value take effect.

### Orphaned DB rows

If a schema field is removed from the Pydantic model, its `ConfigEntryRecord` row
remains in the database. These orphaned rows are harmless but can be cleaned up manually:

```sql
DELETE FROM configentryrecord
WHERE namespace = 'platform' AND key = 'removed_field';
```

---

*Source: `src/aila/storage/registry.py`, `src/aila/platform/config.py`*
*Last updated: 2026-04-05*
