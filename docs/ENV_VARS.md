# Environment Variables Reference

Complete reference for all environment variables used by AILA.
Every `AILA_*` variable is documented with its default, type, location, and production guidance.

---

## Quick Reference

| Variable | Default | Type | Used In |
|----------|---------|------|---------|
| `AILA_DATABASE_URL` | `postgresql+asyncpg://postgres:changeme@localhost:5432/aila` | SQLAlchemy URL | `config.py` |
| `AILA_REPORT_DIR` | `<project>/reports` | directory path | `config.py` |
| `AILA_SECRET_KEYRING_PATH` | `<project>/data/secrets/keyring.json` | file path | `config.py` |
| `AILA_SECRET_ACTIVE_KEY_VERSION` | `v1` | string | `config.py` |
| `AILA_TIMEOUT` | `20` | float (seconds) | `config.py` |
| `AILA_JWT_SECRET_KEY` | random 32-byte hex | hex string | `config.py` |
| `AILA_API_HOST` | `127.0.0.1` | IP address | `config.py` |
| `AILA_API_PORT` | `8000` | integer | `config.py` |
| `AILA_PLATFORM_JWT_ACCESS_EXPIRY_S` | `2592000` (30 days) | integer (seconds) | ConfigRegistry override |
| `AILA_PLATFORM_JWT_REFRESH_EXPIRY_S` | `7776000` (90 days) | integer (seconds) | ConfigRegistry override |
| `AILA_BOOTSTRAP_KEY` | *(none)* | string | `api/app.py` |
| `AILA_CORS_ORIGINS` | `http://localhost:3000` | comma-separated URLs | `api/app.py` |
| `AILA_JSON_LOGS` | *(unset)* | boolean flag | `cli.py` |
| `AILA_{NAMESPACE}_{KEY}` | *(per schema)* | varies | `storage/registry.py` |

---

## Detailed Reference

### AILA_DATABASE_URL

- **Default:** `postgresql+asyncpg://postgres:changeme@localhost:5432/aila`
- **Type:** SQLAlchemy async database URL string
- **Used in:** `src/aila/config.py` (`Settings.database_url`)
- **Production guidance:** Use a full PostgreSQL connection URL (e.g., `postgresql+asyncpg://user:pass@host:5432/aila`). The `+asyncpg` driver suffix is required for the async engine used by the platform runtime.

### AILA_REPORT_DIR

- **Default:** `<project_root>/reports`
- **Type:** Directory path (absolute or project-relative)
- **Used in:** `src/aila/config.py` (`Settings.report_dir`)
- **Production guidance:** Set to a persistent directory on durable storage. Reports are the primary output artifact of vulnerability scans. Tilde (`~`) paths are rejected; use absolute paths.

### AILA_SECRET_KEYRING_PATH

- **Default:** `<project_root>/data/secrets/keyring.json`
- **Type:** File path (absolute or project-relative)
- **Used in:** `src/aila/config.py` (`Settings.secret_keyring_path`)
- **Production guidance:** Point to a secure, access-controlled location. The keyring stores AES-256-GCM encryption keys for provider secrets (SSH credentials, API keys). Restrict filesystem permissions to the AILA process user. Back up this file -- loss means re-entering all provider secrets.

### AILA_SECRET_ACTIVE_KEY_VERSION

- **Default:** `v1`
- **Type:** String (key version identifier)
- **Used in:** `src/aila/config.py` (`Settings.secret_active_key_version`)
- **Production guidance:** Leave as `v1` unless performing key rotation. When rotating, add a new key version to the keyring file first, then update this variable to the new version. Old secrets remain decryptable with their original key version.

### AILA_TIMEOUT

- **Default:** `20`
- **Type:** Float (seconds)
- **Used in:** `src/aila/config.py` (`Settings.request_timeout_seconds`)
- **Production guidance:** Controls the default HTTP timeout for outbound requests (NVD, EPSS, advisory fetches). Increase to 30-60 seconds on high-latency networks. Do not set below 10 seconds -- advisory APIs may be slow under load.

### AILA_JWT_SECRET_KEY

- **Default:** Random 32-byte hex string (regenerated each process start)
- **Type:** Hex string (64 characters)
- **Used in:** `src/aila/config.py` (`Settings.jwt_secret_key`)
- **Production guidance:** **MUST be set in production.** Without this variable, every process restart invalidates all existing JWT tokens. Generate with `python -c "import secrets; print(secrets.token_hex(32))"` and store securely. All API server instances must share the same secret for token validation.

### AILA_API_HOST

- **Default:** `127.0.0.1`
- **Type:** IP address or hostname
- **Used in:** `src/aila/config.py` (`Settings.api_host`)
- **Production guidance:** Set to `0.0.0.0` to listen on all interfaces behind a reverse proxy. Keep as `127.0.0.1` when running behind a local proxy or in development.

### AILA_API_PORT

- **Default:** `8000`
- **Type:** Integer (port number)
- **Used in:** `src/aila/config.py` (`Settings.api_port`)
- **Production guidance:** Change to match your deployment's port allocation. Common choices: `8000` (direct), `80`/`443` (if not behind a reverse proxy).

### AILA_PLATFORM_JWT_ACCESS_EXPIRY_S

- **Default:** `2592000` (30 days)
- **Type:** Integer (seconds)
- **Used in:** ConfigRegistry override for `platform.jwt_access_expiry_s`
- **Resolution:** This is a ConfigRegistry env var override. The actual value is resolved via `get_task_tuning("jwt_access_expiry_s", 2592000)` which checks the `platform` namespace in ConfigRegistry (env var > DB row > schema default). See `docs/CONFIG_REGISTRY.md` for the resolution chain.
- **Production guidance:** 30 days is the default for v1.5 single-operator deployments. For multi-user or higher-security environments, reduce to `3600` (1 hour) or `86400` (1 day) and rely on refresh tokens for session continuity. Can also be changed at runtime via `PUT /config/platform/jwt_access_expiry_s`.

### AILA_PLATFORM_JWT_REFRESH_EXPIRY_S

- **Default:** `7776000` (90 days)
- **Type:** Integer (seconds)
- **Used in:** ConfigRegistry override for `platform.jwt_refresh_expiry_s`
- **Resolution:** Same ConfigRegistry resolution chain as the access expiry. See above.
- **Production guidance:** Controls how long a refresh token remains valid. Set shorter than access token expiry only if you want forced re-authentication. Revoking the originating API key invalidates all its refresh tokens immediately via the key_id blacklist. Can also be changed at runtime via `PUT /config/platform/jwt_refresh_expiry_s`.

### AILA_BOOTSTRAP_KEY

- **Default:** *(none -- feature disabled when unset)*
- **Type:** String (raw API key value)
- **Used in:** `src/aila/api/app.py` (lifespan startup)
- **Production guidance:** Set on first deployment to create an initial admin API key. The key is hashed and stored in the database with role `admin`. **Remove this variable after first start** -- it only creates a key when the database has zero existing API keys (idempotent). Example: `AILA_BOOTSTRAP_KEY=your-long-random-key-here`.

### AILA_CORS_ORIGINS

- **Default:** `http://localhost:3000`
- **Type:** Comma-separated list of URLs
- **Used in:** `src/aila/api/app.py` (`create_app()`)
- **Production guidance:** Set to the exact origin(s) of your frontend. Example: `AILA_CORS_ORIGINS=https://aila.example.com,https://admin.example.com`. Never use `*` in production -- it disables credential-based CORS security.

### AILA_JSON_LOGS

- **Default:** *(unset -- human-readable logs)*
- **Type:** Boolean flag (any truthy value enables)
- **Used in:** `src/aila/cli.py` (CLI `--json-logs` option envvar)
- **Production guidance:** Set to `1` or `true` for structured JSON log output suitable for log aggregation systems (ELK, Datadog, CloudWatch). Leave unset for human-readable console output during development.

### AILA_{NAMESPACE}_{KEY} (ConfigRegistry Override)

- **Default:** *(per-schema field defaults)*
- **Type:** Varies by field (auto-cast to schema type)
- **Used in:** `src/aila/storage/registry.py` (`ConfigRegistry.get()`)
- **Production guidance:** Any ConfigRegistry value can be overridden by setting `AILA_{NAMESPACE}_{KEY}` as an environment variable (uppercased). For example, `AILA_PLATFORM_REDIS_URL=redis://localhost:6379` overrides the `redis_url` key in the `platform` namespace. Environment variables take precedence over database-stored values, which take precedence over schema defaults. Use this for containerized deployments where config injection via env is preferred.

### AILA_LLM_MODELS_REJECTING_TEMPERATURE

- **Default:** *(unset -- falls back to config DB entry `platform.llm_models_rejecting_temperature`, then hardcoded list)*
- **Type:** Comma-separated model name substrings
- **Used in:** `src/aila/platform/llm/client.py` (`_get_rejection_markers()`)
- **Production guidance:** Some models (o1, o3, gpt-5, etc.) reject the `temperature` parameter with HTTP 400. This env var lists substring markers matched against the routed model_id. Example: `AILA_LLM_MODELS_REJECTING_TEMPERATURE=o1,o3,o4,gpt-5,claude-opus-4`. Also editable from the Config page at `/admin/config` (key: `llm_models_rejecting_temperature`). Env var takes priority over config DB.

#### Platform Namespace (`AILA_PLATFORM_*`)

All fields from `PlatformConfigSchema` (registered under namespace `platform`):

| Env Var | Default | Type | Purpose |
|---------|---------|------|---------|
| `AILA_PLATFORM_REQUEST_TIMEOUT_SECONDS` | `20.0` | float | Default HTTP timeout for provider requests |
| `AILA_PLATFORM_USER_AGENT` | `AILA/{version}` | str | User-Agent header for outbound HTTP |
| `AILA_PLATFORM_ROUTING_MIN_CONFIDENCE` | `0.2` | float | Minimum routing confidence threshold |
| `AILA_PLATFORM_ROUTING_DECISION_CACHE_TTL_HOURS` | `72` | int | Routing decision cache TTL in hours |
| `AILA_PLATFORM_HTTP_PROXY` | *(empty)* | str | HTTP proxy for outbound requests |
| `AILA_PLATFORM_HTTPS_PROXY` | *(empty)* | str | HTTPS proxy for outbound requests |
| `AILA_PLATFORM_REDIS_URL` | *(empty)* | str | Redis connection URL for task queue |
| `AILA_PLATFORM_JWT_ACCESS_EXPIRY_S` | `2592000` | int | JWT access token expiry (seconds) |
| `AILA_PLATFORM_JWT_REFRESH_EXPIRY_S` | `7776000` | int | JWT refresh token expiry (seconds) |
| `AILA_PLATFORM_HEARTBEAT_INTERVAL_S` | `30` | int | Worker heartbeat interval (seconds) |
| `AILA_PLATFORM_REAPER_ZOMBIE_THRESHOLD_S` | `120` | int | Zombie task detection threshold (seconds) |
| `AILA_PLATFORM_ARQ_JOB_TIMEOUT_S` | `3600` | int | Max ARQ job execution time (seconds) |
| `AILA_PLATFORM_ARQ_MAX_TRIES` | `3` | int | Max retry attempts for failed jobs |
| `AILA_PLATFORM_ARQ_KEEP_RESULT_S` | `3600` | int | How long to keep job results in Redis |
| `AILA_PLATFORM_PROGRESS_STREAM_MAXLEN` | `1000` | int | Max events per Redis progress stream |

---

## Internal Constants (Not Environment Variables)

These Python constants match the `AILA_*` pattern but are **not** environment variables:

| Constant | Location | Purpose |
|----------|----------|---------|
| `_AILA_VERSION` | `api/routers/health.py`, `platform/config.py`, `modules/vulnerability/config_schema.py` | Package version read from `importlib.metadata.version("aila")` at import time |

## Non-AILA Environment Variables

These standard environment variables are also read by AILA:

| Variable | Used In | Purpose |
|----------|---------|---------|
| `HTTPS_PROXY` | `modules/vulnerability/providers/_http.py` | HTTP proxy for outbound advisory/NVD requests |
| `HTTP_PROXY` | `modules/vulnerability/providers/_http.py` | HTTP proxy fallback |

---

## Production Checklist

Before deploying to production, verify these are set:

- [ ] `AILA_JWT_SECRET_KEY` -- **required**, prevents token invalidation on restart
- [ ] `AILA_DATABASE_URL` -- set to a persistent volume path
- [ ] `AILA_CORS_ORIGINS` -- set to your frontend origin(s)
- [ ] `AILA_BOOTSTRAP_KEY` -- set for first start, then remove
- [ ] `AILA_API_HOST=0.0.0.0` -- if exposing beyond localhost
- [ ] `AILA_SECRET_KEYRING_PATH` -- set to a secure, backed-up location

---

*Generated from source code grep of all `AILA_*` and `os.getenv`/`os.environ` calls.*
*Last updated: 2026-04-29 (v7.0 -- PostgreSQL default, LLM temperature rejection env var)*
