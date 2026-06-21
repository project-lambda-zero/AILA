# Environment Variables Reference

Complete reference for all environment variables used by AILA.
Every `AILA_*` variable is documented with its default, type, location, and production guidance.

---

## Quick Reference

The `.env.example` at the repo root carries the minimum set every deployment must
have. Required keys block boot when missing.

| Variable | Default | Type | Used In |
|----------|---------|------|---------|
| `AILA_DATABASE_URL` | `postgresql+asyncpg://postgres:changeme@localhost:5432/aila` | SQLAlchemy URL | `config.py` |
| `AILA_PLATFORM_REDIS_URL` | `redis://127.0.0.1:6379/0` | Redis URL | ConfigRegistry override (`platform.redis_url`) |
| `AILA_JWT_SECRET_KEY` | random 32-byte hex (regenerated per process if unset) | hex string | `config.py` |
| `AILA_ADMIN_PASSWORD` | *(unset — required on first boot)* | string | `api/app.py` |
| `AILA_CORS_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000,http://localhost:4173,http://127.0.0.1:4173,http://localhost:5173,http://127.0.0.1:5173` | comma-separated URLs | `api/app.py` |
| `OPENAI_API_KEY` | *(unset)* | string | LLM client |
| `AILA_PLATFORM_LLM_DEFAULT_MODEL` | `openai/gpt-4o-mini` (fallback) | string | ConfigRegistry override (`platform.llm_default_model`) |
| `AILA_PLATFORM_LLM_BASE_URL` | `https://openrouter.ai/api/v1` (fallback) | URL | ConfigRegistry override (`platform.llm_base_url`) |
| `AILA_PLATFORM_LLM_DEFAULT_MAX_TOKENS` | `4096` (fallback) | int | ConfigRegistry override (`platform.llm_default_max_tokens`) |
| `AILA_LLM_TIMEOUT_SECONDS` | `180` | float | `platform/llm/client.py` |
| `AILA_LLM_MODELS_REJECTING_TEMPERATURE` | *(unset)* | csv substrings | `platform/llm/client.py` |
| `AILA_PLATFORM_LLM_PIPELINE_CLASSIFY_RESTRICTED_BEHAVIOR_SCORING` | *(unset)* | string mode | ConfigRegistry override |
| `AILA_PLATFORM_LLM_PIPELINE_CLASSIFY_RESTRICTED_BEHAVIOR_SYNTHESIS` | *(unset)* | string mode | ConfigRegistry override |
| `AILA_PLATFORM_DATA_POSTURE_MODE` | `standard` | enum | ConfigRegistry override (`platform.data_posture_mode`) |
| `AILA_REPORT_DIR` | `<project>/reports` | directory path | `config.py` |
| `AILA_SECRET_KEYRING_PATH` | `<project>/data/secrets/keyring.json` | file path | `config.py` |
| `AILA_SECRET_ACTIVE_KEY_VERSION` | `v1` | string | `config.py` |
| `AILA_TIMEOUT` | `20` | float (seconds) | `config.py` |
| `AILA_API_HOST` | `127.0.0.1` (or `0.0.0.0` via `.env.example`) | IP address | `config.py` |
| `AILA_API_PORT` | `8000` | integer | `config.py` |
| `AILA_BOOTSTRAP_KEY` | *(unset, optional)* | string | `api/app.py` |
| `AILA_JSON_LOGS` | *(unset)* | boolean flag | `cli.py` |
| `AILA_{NAMESPACE}_{KEY}` | *(per schema)* | varies | `storage/registry.py` |

**Optional / commented in `.env.example`:**
- Forensics per-pipeline overrides: `AILA_PLATFORM_LLM_MODEL_FORENSICS_{FREEFLOW,RESOLVER,WRITEUP}`, `AILA_PLATFORM_LLM_MAX_TOKENS_FORENSICS_{FREEFLOW,RESOLVER,WRITEUP}`, `AILA_FORENSICS_CAPA_RULES`, `AILA_FORENSICS_CAPA_SIGS`.
- `AILA_LLM_MODELS_REJECTING_TEMPERATURE`.

**Dev-stack knobs read by `start.sh` (not Python config):**
- `WORKER_COUNT_VR`, `WORKER_COUNT_VULNERABILITY`, `WORKER_COUNT_FORENSICS`, `WORKER_COUNT_DEFAULT` (per-queue worker concurrency)
- `BACKEND_PORT`, `FRONTEND_PORT`, `AUDIT_MCP_PORT`, `IDA_HEADLESS_PORT`
- `AILA_START_FRONTEND`, `AILA_START_AUDIT_MCP`, `AILA_START_IDA_HEADLESS` (toggle 1/0)
- `AUDIT_MCP_DIR`, `IDA_HEADLESS_DIR`, `AUDIT_MCP_WORKERS`

**VR-specific runtime knobs:**
- `VR_INVESTIGATION_WALL_CLOCK_HOURS` (default `6`) — investigation lifetime; the emit-side cap and the reaper both consult this.
- `VR_INVESTIGATION_MESSAGE_CAP` (default `1000`) — message ceiling per investigation, reaper-enforced.

**audit-mcp dev knobs (separate repo, dev only):**
- `AUDIT_MCP_THREAD_POOL_LIMIT` (default `64`), `AUDIT_MCP_TOOL_CAP_<TOOLNAME>`, `AUDIT_MCP_TIMEOUT_<TOOLNAME>`, `AUDIT_MCP_SEMBLE_BUILD_TIMEOUT_S` (default `7200`).

On Windows, `start.sh` spawns workers via PowerShell `Start-Process`, which strips
the bash environment. The `spawn()` helper reads `.env` line-by-line and prepends
each `KEY=VAL` as `set KEY=VAL && ` in the cmd block so detached workers inherit
the configured environment. `AUDIT_MCP_WORKERS` is the exception — it MUST stay on
the CLI line passed to `audit_mcp` because the env-prefix path does not reach
through PowerShell.

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

### AILA_ADMIN_PASSWORD

- **Default:** *(unset)*
- **Type:** String (plaintext password — argon2id-hashed before storage)
- **Used in:** `src/aila/api/app.py` (lifespan startup, admin-user bootstrap)
- **Production guidance:** Required on first boot when no `UserRecord` row exists; startup raises `RuntimeError` otherwise so an unprotected admin user is never created automatically. Creates the `admin` user with this password (argon2id-hashed), then logs a notice. **Remove this variable after the first boot succeeds.** Never commit a real value.

### AILA_PLATFORM_JWT_ACCESS_EXPIRY_S

- **Default:** `2592000` (30 days, from `PlatformConfigSchema`)
- **Type:** Integer (seconds)
- **Used in:** ConfigRegistry override for `platform.jwt_access_expiry_s`
- **Resolution:** Standard ConfigRegistry chain (env > DB row > schema default). See `docs/CONFIG_REGISTRY.md`.
- **Production guidance:** 30 days is the default for single-operator deployments. For multi-user or higher-security environments, reduce to `3600` (1 hour) or `86400` (1 day) and rely on refresh tokens for session continuity. Can also be changed at runtime via `PUT /config/platform/jwt_access_expiry_s`.

### AILA_PLATFORM_JWT_REFRESH_EXPIRY_S

- **Default:** `7776000` (90 days, from `PlatformConfigSchema`)
- **Type:** Integer (seconds)
- **Used in:** ConfigRegistry override for `platform.jwt_refresh_expiry_s`
- **Resolution:** Same chain as the access expiry.
- **Production guidance:** Controls how long a refresh token remains valid. Revoking the originating API key invalidates all its refresh tokens immediately via the key_id blacklist. Can also be changed at runtime via `PUT /config/platform/jwt_refresh_expiry_s`.

### AILA_PLATFORM_REDIS_URL

- **Default:** *(empty)* — `.env.example` sets `redis://127.0.0.1:6379/0`
- **Type:** Redis connection URL
- **Used in:** ConfigRegistry override for `platform.redis_url`
- **Production guidance:** Required for the ARQ task queue and the SSE event bus. Empty falls back to in-process synchronous execution (development only). Point at a real Redis 6+ / Memurai instance for any deployment with workers.

### AILA_PLATFORM_LLM_DEFAULT_MODEL / _BASE_URL / _DEFAULT_MAX_TOKENS

- **Used in:** `src/aila/platform/llm/config.py` (`LLMConfigResolver`)
- **Resolution:** ConfigRegistry env-var override path. These keys live under the `platform` namespace but are NOT in `PlatformConfigSchema` — the env var sets the value, the DB row carries persistent overrides, and the resolver bakes in its own fallbacks (`openai/gpt-4o-mini`, `https://openrouter.ai/api/v1`, `4096`) when nothing matches.
- **Production guidance:** Set per deployment to pin the default model/provider for every task type. Per-task-type overrides land under `AILA_PLATFORM_LLM_MODEL_<TASK_TYPE>` and `AILA_PLATFORM_LLM_MAX_TOKENS_<TASK_TYPE>`.

### AILA_LLM_TIMEOUT_SECONDS

- **Default:** `180`
- **Type:** Float (seconds)
- **Used in:** `src/aila/platform/llm/client.py`
- **Production guidance:** Wall-clock ceiling for each LLM API call. Bump for thinking models that stream slowly (e.g. `claude-opus-thinking` can take 90+ seconds). Lower in environments with strict request budgets.

### AILA_BOOTSTRAP_KEY

- **Default:** *(none -- feature disabled when unset)*
- **Type:** String (raw API key value)
- **Used in:** `src/aila/api/app.py` (lifespan startup)
- **Production guidance:** Set on first deployment to create an initial admin API key. The key is hashed and stored in the database with role `admin`. **Remove this variable after first start** -- it only creates a key when the database has zero existing API keys (idempotent). Example: `AILA_BOOTSTRAP_KEY=your-long-random-key-here`.

### AILA_CORS_ORIGINS

- **Default:** `http://localhost:3000,http://127.0.0.1:3000,http://localhost:4173,http://127.0.0.1:4173,http://localhost:5173,http://127.0.0.1:5173`
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
| `AILA_PLATFORM_HEARTBEAT_INTERVAL_S` | `30` | int | Worker heartbeat write interval |
| `AILA_PLATFORM_REAPER_ZOMBIE_THRESHOLD_S` | `3300` | int | Worker-side zombie detection threshold |
| `AILA_PLATFORM_REAPER_HEARTBEAT_THRESHOLD_S` | `86400` | int | DB-side stale-heartbeat threshold |
| `AILA_PLATFORM_ARQ_JOB_TIMEOUT_S` | `3600` | int | Max ARQ job execution time (seconds) |
| `AILA_PLATFORM_ARQ_MAX_TRIES` | `3` | int | Max retry attempts for failed jobs |
| `AILA_PLATFORM_ARQ_KEEP_RESULT_S` | `3600` | int | How long to keep job results in Redis |
| `AILA_PLATFORM_PROGRESS_STREAM_MAXLEN` | `1000` | int | Max events per Redis progress stream |
| `AILA_PLATFORM_LLM_PIPELINE_CLASSIFY_DEFAULT` | `true` | bool | LLM pipeline classify stage default-on |
| `AILA_PLATFORM_LLM_PIPELINE_VALIDATE_DEFAULT` | `true` | bool | LLM pipeline validate stage default-on |
| `AILA_PLATFORM_LLM_PIPELINE_GATE_DEFAULT` | `true` | bool | LLM pipeline gate stage default-on |
| `AILA_PLATFORM_LLM_PIPELINE_SEAL_DEFAULT` | `true` | bool | LLM pipeline seal stage default-on |
| `AILA_PLATFORM_LLM_PIPELINE_VERIFY_DEFAULT` | `false` | bool | Cross-model verification default-off |
| `AILA_PLATFORM_LLM_PIPELINE_VERIFY_THRESHOLD_DEFAULT` | `0.7` | float | Verification agreement threshold |
| `AILA_PLATFORM_LLM_PIPELINE_VERIFY_MODEL_DEFAULT` | *(empty)* | str | Verifier model id (empty = same as task model) |
| `AILA_PLATFORM_LLM_SEAL_HMAC_KEY` | *(empty)* | str | Audit-seal HMAC key (auto-generated when empty) |
| `AILA_PLATFORM_LLM_SEAL_RETENTION_DAYS` | `90` | int | Audit-seal retention period |
| `AILA_PLATFORM_LLM_BUDGET_MAX_TOTAL_TOKENS_DEFAULT` | `0` | int | Per-task-type token ceiling (0 = unlimited) |
| `AILA_PLATFORM_LLM_COST_ESTIMATE_FALLBACK_MAX_TOKENS` | `4096` | int | Fallback max-token assumption for cost estimation |
| `AILA_PLATFORM_LLM_COST_ESTIMATE_FALLBACK_PRICE_PER_1K` | `0.03` | float | Fallback per-1k token price for cost estimation |
| `AILA_PLATFORM_LLM_HUMAN_CONSULTANT_HOURLY_RATE` | `150.0` | float | USD/hr used for human-equivalent cost projections |
| `AILA_PLATFORM_DATA_POSTURE_MODE` | `standard` | str | `transparent` / `standard` / `paranoid` |
| `AILA_PLATFORM_DATA_DIRECTION_DEFAULT` | `bidirectional` | str | `inbound` / `local_only` / `bidirectional` |

---

## Recently added (2026-06-21)

### `AILA_ENV`

- **Default:** `development`
- **Type:** String
- **Used in:** `src/aila/logging_config.py:34`, `src/aila/api/app.py:625`
- **Production guidance:** Controls log renderer selection and startup mode. Values like `production`, `staging` trigger JSON structlog output; `dev`, `development`, `local`, `test` use human-readable console output.

### `AILA_MAX_REQUEST_BYTES`

- **Default:** `10485760` (10 MB)
- **Type:** Integer (bytes)
- **Used in:** `src/aila/api/app.py:457`
- **Production guidance:** Overrides the `_reject_oversized_requests` middleware body-size limit. Bump for forensics dumps and other large-payload modules; keep at the default unless you measure rejected legitimate traffic.

### `AILA_LLM_MAX_RETRIES`

- **Default:** `3`
- **Type:** Integer
- **Used in:** `src/aila/platform/llm/client.py:290`
- **Production guidance:** Maximum retry attempts for transient LLM API failures (429, 500, 502, 503, 504). Total in-task retry budget ~7 s; sustained provider degradation is handled at the ARQ task level with cursor preservation, not in the in-call retry loop.

### `AILA_LLM_RETRY_BASE_DELAY_S`

- **Default:** `1.0`
- **Type:** Float (seconds)
- **Used in:** `src/aila/platform/llm/client.py:291`
- **Production guidance:** Base delay in seconds for exponential backoff on LLM retries (1 s, 2 s, 4 s, capped at `AILA_LLM_RETRY_MAX_DELAY_S`).

### `AILA_LLM_RETRY_MAX_DELAY_S`

- **Default:** `30.0`
- **Type:** Float (seconds)
- **Used in:** `src/aila/platform/llm/client.py:292`
- **Production guidance:** Maximum per-attempt backoff cap for LLM retries.

### `AILA_FORENSICS_RETRIEVE_MAX_BYTES`

- **Default:** `_DEFAULT_MAX_BYTES` (500 MB)
- **Type:** Integer (bytes)
- **Used in:** `src/aila/modules/forensics/services/file_retriever.py:52`
- **Production guidance:** Maximum file size for forensics evidence file retrieval. Raise when investigating large disk images or memory dumps; lower in shared-tenant deployments to bound per-call memory.

### `PLATFORM_WORKER_HEARTBEAT_GRACE_S`

- **Default:** `600`
- **Type:** Integer (seconds)
- **Used in:** `src/aila/platform/tasks/worker.py:39-43`
- **Production guidance:** Grace window for the cron-tick reaper before considering a heartbeat stale. The boot-path reaper uses a fixed 30 s regardless. Increase only when long single-shot tool calls (e.g. audit-mcp `index_codebase`) routinely park coroutines past 10 minutes without heartbeat.

### `VR_WALL_CLOCK_IDLE_GRACE_S`

- **Default:** `900`
- **Type:** Integer (seconds)
- **Used in:** `src/aila/modules/vr/services/investigation_reaper.py:192`
- **Production guidance:** Idle grace before the VR wall-clock reaper acts on an investigation that has stopped producing turns.

### `VR_INVESTIGATION_TURN_CAP`

- **Default:** `300`
- **Type:** Integer
- **Used in:** `src/aila/modules/vr/services/investigation_reaper.py:188`, `src/aila/modules/vr/workflow/finalize.py:160`
- **Production guidance:** Per-investigation hard turn ceiling enforced by the reaper and per-turn cap. Tune in concert with `VR_INVESTIGATION_WALL_CLOCK_HOURS` and `VR_INVESTIGATION_MESSAGE_CAP`.

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

- [ ] `AILA_JWT_SECRET_KEY` — **required**; prevents token invalidation on restart.
- [ ] `AILA_DATABASE_URL` — points at the production PostgreSQL with pgvector.
- [ ] `AILA_PLATFORM_REDIS_URL` — points at the production Redis / Memurai.
- [ ] `AILA_ADMIN_PASSWORD` — set on first boot, then removed once the admin user exists.
- [ ] `AILA_CORS_ORIGINS` — exact frontend origin(s); never `*`.
- [ ] `AILA_API_HOST=0.0.0.0` — when exposing beyond localhost behind a reverse proxy.
- [ ] `AILA_SECRET_KEYRING_PATH` — secure, backed-up location for the AES keyring.
- [ ] `AILA_PLATFORM_LLM_DEFAULT_MODEL`, `AILA_PLATFORM_LLM_BASE_URL`, and `OPENAI_API_KEY` (or equivalent provider key) — LLM provider wired before first request.
- [ ] `AILA_BOOTSTRAP_KEY` — only when bootstrapping the first API key; remove after the key has been recorded.

---

*Generated from source: `src/aila/config.py`, `src/aila/platform/config.py`, `src/aila/platform/llm/`, `src/aila/api/app.py`, `.env.example`, `start.sh`.*
*Last updated: 2026-06-21 (head: `067_workflow_state_cursor_archived_state`).*
