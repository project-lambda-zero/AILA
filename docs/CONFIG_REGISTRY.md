# ConfigRegistry Guide

Runtime-configurable settings for AILA. Values can be changed without restarting
the server, inspected via API, and overridden by environment variables.

---

## What Is ConfigRegistry

ConfigRegistry is a typed key-value store backed by PostgreSQL (`ConfigEntryRecord` table).
It stores runtime-tunable settings that modules and the platform declare via Pydantic
schemas. Unlike `Settings` (8 infrastructure fields, read once at startup),
ConfigRegistry values are resolved on every access and can be changed at runtime
via the `/config` API.

Module code MUST read its own settings through `ConfigRegistry.get()`, not direct
`os.getenv` calls — `os.getenv` bypasses the DB row and the schema default, and
the honesty audit flags new occurrences.

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

`ConfigRegistry.get()` is async — every caller must `await` it from inside an
event loop (FastAPI handlers, ARQ task wrappers, `async def` services):

```python
# Direct ConfigRegistry access (requires a registry instance)
value = await config_registry.get("platform", "redis_url")
```

Worker bootstrap paths that run before an event loop is available can use the
`get_task_tuning(key, default)` shim, which returns the compiled default for a
platform-namespace integer key:

```python
from aila.platform.tasks import get_task_tuning
interval = get_task_tuning("heartbeat_interval_s", 30)
```

`get_task_tuning` deliberately skips the DB lookup so it can run during worker
startup on Windows where `asyncio.run()` from a worker bootstrap creates stale
asyncpg connections that crash ARQ. Use it only for tuning knobs that worker
startup needs before the event loop exists.

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

# Option A: Via ConfigRegistry instance (await it — get() is async)
max_retries = await config_registry.get("platform", "max_retries")

# Option B: Via get_task_tuning when no event loop is available
from aila.platform.tasks import get_task_tuning
max_retries = get_task_tuning("max_retries", 5)  # returns the compiled default

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
| `reaper_zombie_threshold_s` | int | `3300` | Worker-side zombie detection threshold |
| `reaper_heartbeat_threshold_s` | int | `86400` | DB-side stale-heartbeat threshold |
| `arq_job_timeout_s` | int | `3600` | Maximum ARQ job execution time |
| `arq_max_tries` | int | `3` | Maximum retry attempts for failed jobs |
| `arq_keep_result_s` | int | `3600` | Job result retention in Redis |
| `progress_stream_maxlen` | int | `1000` | Max events per Redis progress stream |
| `llm_pipeline_classify_default` | bool | `True` | LLM pipeline classify stage default-on |
| `llm_pipeline_validate_default` | bool | `True` | LLM pipeline validate stage default-on |
| `llm_pipeline_gate_default` | bool | `True` | LLM pipeline gate stage default-on |
| `llm_pipeline_seal_default` | bool | `True` | LLM pipeline seal stage default-on |
| `llm_pipeline_verify_default` | bool | `False` | Cross-model verification default-off |
| `llm_pipeline_verify_threshold_default` | float | `0.7` | Verification agreement threshold |
| `llm_pipeline_verify_model_default` | str | `""` | Verifier model id (empty = same as task model) |
| `llm_seal_hmac_key` | str | `""` | Audit-seal HMAC key (auto-generated when empty) |
| `llm_seal_retention_days` | int | `90` | Audit-seal retention period |
| `llm_budget_max_total_tokens_default` | int | `0` | Per-task-type token ceiling (0 = unlimited) |
| `llm_cost_estimate_fallback_max_tokens` | int | `4096` | Fallback max-token assumption for cost estimation |
| `llm_cost_estimate_fallback_price_per_1k` | float | `0.03` | Fallback per-1k token price for cost estimation |
| `llm_human_consultant_hourly_rate` | float | `150.0` | USD/hr used for human-equivalent cost projections |
| `data_posture_mode` | str | `"standard"` | `transparent` / `standard` / `paranoid` |
| `data_direction_default` | str | `"bidirectional"` | `inbound` / `local_only` / `bidirectional` |

Per-task-type overrides land under namespaced keys (e.g.
`llm_pipeline_classify_<task_type>`, `llm_pipeline_classify_fail_mode_<task_type>`,
`llm_budget_max_total_tokens_<task_type>`) and are read through the same
`platform` namespace.

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
| **Read pattern** | Once at startup, cached via `lru_cache` | Per access, resolved each time, in-process TTL cache |
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
*Last updated: 2026-06-07*