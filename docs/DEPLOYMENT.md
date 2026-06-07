# Deployment Guide

How to deploy AILA in production with FastAPI, ARQ worker, and Redis.

---

## Architecture Overview

```
                                +-------------------+
                                |   Redis / Memurai |
                                |   (ARQ queues +   |
                                |    SSE streams)   |
                                +---------+---------+
                                          |
         +-----------+           +--------+---------+
 Clients>|  Reverse  |---------->|  FastAPI server  |
         |   proxy   |           |  (aila serve)    |
         +-----------+           +--------+---------+
                                          |
                                +---------+---------+
                                |   PostgreSQL 16   |
                                |    + pgvector     |
                                +---------+---------+
                                          |
                                +---------+---------+
                                |   ARQ workers     |
                                | one per queue:    |
                                |  default, vr,     |
                                |  vulnerability,   |
                                |  forensics,       |
                                |  sbd_nfr          |
                                +-------------------+
```

Three process classes:
1. **FastAPI server** — serves REST API, submits tasks to Redis. One or more replicas.
2. **ARQ workers** — execute background tasks (`platform.handle`, scans, VR investigations). One worker per queue; concurrency scales by spawning N workers per queue (see `WORKER_COUNT_<QUEUE>`).
3. **Redis / Memurai** — ARQ broker, idempotency cache, SSE progress streams. Redis 6+ on Linux; Memurai 3+ on Windows.

The two compose files in `infra/utilities/` cover the deployment shapes:
- `docker-compose.yml` — dev infra only: PostgreSQL (with pgvector) + Redis. Used by `make dev-up` for local development where the operator runs the API, workers, and frontend on the host.
- `docker-compose.full.yml` — full stack: PostgreSQL + Redis + API + one worker container per queue + frontend (Vite dev server). The production-like shape used by `docker compose -f infra/utilities/docker-compose.full.yml up --build`. Credentials and tuning come from the repo-root `.env`.

---

## Prerequisites

- Python 3.11+
- Docker Engine (for `make dev-up` / the compose files) OR a managed PostgreSQL 16 with the pgvector extension
- Redis 6+ (Linux) or Memurai 3+ (Windows)
- pnpm 10.x (`corepack enable && corepack prepare pnpm@10.30.3 --activate`) for the frontend
- SSH access to target systems (for vulnerability scanning)
- OpenAI-compatible LLM provider (OpenRouter / OpenAI / Anthropic via OpenAI-compatible endpoint)

---

## 1. Install AILA

```bash
git clone <repo-url>
cd AILA
pip install -e ".[dev]"          # backend + dev deps
corepack enable && pnpm install  # frontend pnpm workspace
```

---

## 2. Redis Setup

### Linux

```bash
# Install Redis
sudo apt install redis-server  # Debian/Ubuntu
sudo pacman -S redis            # Arch

# Start Redis
sudo systemctl enable redis
sudo systemctl start redis

# Verify
redis-cli ping  # Should return PONG
```

### Windows (Memurai)

Memurai is a Redis-compatible server for Windows.

1. Download from https://www.memurai.com/
2. Install with the MSI installer
3. Memurai runs as a Windows service automatically

```powershell
# Verify
memurai-cli ping  # Should return PONG
```

### Connection URL

Set the Redis URL in ConfigRegistry:

```bash
# Via environment variable
export AILA_PLATFORM_REDIS_URL=redis://localhost:6379

# Or via API
curl -X PUT http://localhost:8000/config/platform/redis_url \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value": "redis://localhost:6379"}'
```

---


## 3. PostgreSQL Setup

`docker-compose.yml` brings up `pgvector/pgvector:pg16` with the `vector` extension
pre-installed (`infra/postgres-init/` runs on first volume creation). For managed
PostgreSQL (RDS, Cloud SQL, Aurora, etc.), enable the `vector` extension manually:

```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

Then point `AILA_DATABASE_URL` at the production database (`postgresql+asyncpg://`
scheme — the asyncpg driver is required at runtime; Alembic uses psycopg via the
transparent driver swap in `src/aila/alembic/env.py`).

Bootstrap a brand-new database (creates every table, stamps Alembic head):

```bash
make db-init                 # one-time, fresh database only
```

Apply migrations on subsequent updates:

```bash
make migrate                 # or: cd src/aila && alembic upgrade head
```

---

## 4. Environment Variables

Set these before starting the server. See `docs/ENV_VARS.md` for full reference.

### Required for Production

```bash
# JWT signing secret -- MUST be set, otherwise tokens invalidate on restart
export AILA_JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Database on persistent storage
export AILA_DATABASE_URL=postgresql+asyncpg://aila:STRONG_PW@db.internal:5432/aila

# Redis for task queue + SSE
export AILA_PLATFORM_REDIS_URL=redis://redis.internal:6379/0

# Report output directory + secret keyring (persistent volume)
export AILA_REPORT_DIR=/data/aila/reports
export AILA_SECRET_KEYRING_PATH=/data/aila/secrets/keyring.json

# CORS origins (your frontend URL — exact match, never `*`)
export AILA_CORS_ORIGINS=https://aila.example.com

# First-boot admin user (remove from env after the admin user exists)
export AILA_ADMIN_PASSWORD=$(openssl rand -base64 24)

# LLM provider
export OPENAI_API_KEY=sk-...
export AILA_PLATFORM_LLM_BASE_URL=https://api.openai.com/v1
export AILA_PLATFORM_LLM_DEFAULT_MODEL=gpt-4o
```

### Optional

```bash
# Listen on all interfaces (default 127.0.0.1)
export AILA_API_HOST=0.0.0.0
export AILA_API_PORT=8000

# Per-queue worker concurrency (start.sh / non-docker only — docker-compose.full.yml
# scales by replicating the worker-<queue> service)
export WORKER_COUNT_VR=5
export WORKER_COUNT_VULNERABILITY=1
export WORKER_COUNT_FORENSICS=1
export WORKER_COUNT_SBD_NFR=1

# Structured JSON logs (ELK / Datadog / CloudWatch)
export AILA_JSON_LOGS=1
```

The full env reference — including the platform `ConfigRegistry` namespace and the
VR / audit-mcp dev knobs — lives in [`docs/ENV_VARS.md`](ENV_VARS.md).

---

## 5. Start the FastAPI Server

### Using the CLI

```bash
aila serve
```

This runs `uvicorn aila.api.app:app` with the host and port from Settings.

### Using uvicorn directly

```bash
uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --loop asyncio
```

On Windows the `--loop asyncio` flag is required: uvicorn's default Proactor loop
leaks IOCP socket handles on abnormal exit and the port appears owned by a
phantom PID until reboot. The selector loop closes sockets cleanly. On Linux the
default loop is already fine; the flag is harmless either way.

For multi-replica deployments (or multi-worker uvicorn), point every replica at
the same Redis and PostgreSQL and share `AILA_JWT_SECRET_KEY`. PostgreSQL
absorbs concurrent writes from many backend processes without per-row
contention.

### First Start

On first start:
1. `make db-init` (or the container entrypoint when using `docker-compose.full.yml`) creates every SQLModel-registered table and stamps Alembic at the current head (`062_vr_outcome_review`).
2. If `AILA_ADMIN_PASSWORD` is set and no `UserRecord` row exists, the lifespan hook creates the `admin` user with that password (argon2id-hashed). When neither condition is met, startup raises `RuntimeError` to refuse an unprotected admin account.
3. If `AILA_BOOTSTRAP_KEY` is set and no `ApiKeyRecord` row exists, an admin API key is created from the bootstrap value.
4. The platform discovers and loads every installed module (`default`, `vr`, `vulnerability`, `forensics`, `sbd_nfr`, plus `hello_world` as the reference).

After first start, remove `AILA_ADMIN_PASSWORD` (and `AILA_BOOTSTRAP_KEY` if set) from the environment.

---

## 6. Start the ARQ Workers

Each module owns a queue; one worker process drains one queue. The CLI takes a
`-q` flag:

```bash
python -m aila worker -q default
python -m aila worker -q vr
python -m aila worker -q vulnerability
python -m aila worker -q forensics
python -m aila worker -q sbd_nfr
```

The Make targets (`make worker`, `make worker-vr`, `make worker-vuln`,
`make worker-forensics`, `make worker-sbd`) wrap the same calls and also bring
up the dev infra (`make dev-up`) + run `make db-init` if needed.

Workers process:
- Vulnerability scans submitted via `POST /vulnerability/analyze`
- Forensics investigations submitted via `POST /forensics/...`
- VR investigations dispatched from the VR module
- Cross-cutting platform tasks on the `default` queue (cron automation, report explanations, etc.)

Worker behavior:
- Heartbeat every 30s (`AILA_PLATFORM_HEARTBEAT_INTERVAL_S`)
- Worker-side zombie reaper at 3300s (`AILA_PLATFORM_REAPER_ZOMBIE_THRESHOLD_S`); DB-side stale-heartbeat reaper at 86400s (`AILA_PLATFORM_REAPER_HEARTBEAT_THRESHOLD_S`)
- Checkpoint / resume for long-running tasks
- Per-call LLM idempotency cache (`llm_idempotency_cache` table) — retries replay the cached response instead of paying for Claude again

### Scaling

Spawn more workers per queue when one is not enough:

```bash
WORKER_COUNT_VR=5 bash start.sh        # 5 vr workers, plus 1 each on default / vuln / forensics / sbd
```

`start.sh` reads `WORKER_COUNT_<QUEUE>` for every entry in `WORKERS` and spawns
that many workers, recording each under `.run/worker-<queue>-<i>.pid` so `stop`
can tree-kill them. The `docker-compose.full.yml` deployment scales by
replicating the per-queue worker service via `docker compose up --scale worker-vr=5`.

### Without Redis

Setting `AILA_PLATFORM_REDIS_URL` to an empty value drops AILA into a synchronous
in-process fallback: `POST /vulnerability/analyze` and module dispatch run on the
API thread, SSE endpoints return an informational message, no background workers
are needed. This is for single-operator local development only — every
production deployment runs Redis.

---

## 7. Authenticate

Two paths to a JWT — pick whichever fits your environment.

### Username + password

The first-boot bootstrap creates the `admin` user from `AILA_ADMIN_PASSWORD`.
Trade those credentials for a JWT:

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "..."}'
# -> { "data": { "access_token": "eyJ...", "refresh_token": "eyJ..." } }
```

Dev credentials on a fresh checkout are `admin` / `admin` (see `.env.example`).
Change the password (and rotate the refresh tokens) before exposing the
deployment to the network.

### API key (machine clients, CI)

Mint an API key — once via the CLI for the first admin key, then via the API
for everything else:

```bash
# First key, from the host
aila create-api-key --role admin --label "ops-team"

# Subsequent keys via the API (requires admin JWT)
curl -X POST http://localhost:8000/auth/keys \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"role": "operator", "label": "ci-pipeline"}'
```

Exchange the raw key for a JWT:

```bash
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "aila_sk_..."}'
```

The raw key is displayed once and never stored. Save it securely.

---

## 8. Reverse Proxy

### nginx

```nginx
server {
    listen 443 ssl;
    server_name aila.example.com;

    ssl_certificate     /etc/ssl/aila.crt;
    ssl_certificate_key /etc/ssl/aila.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE support
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
    }
}
```

Key SSE settings:
- `proxy_buffering off` -- prevents nginx from buffering SSE events
- `proxy_read_timeout 3600s` -- long timeout for SSE connections
- `X-Accel-Buffering: no` is set by AILA on SSE responses

---

## 9. Production Checklist

- [ ] `AILA_JWT_SECRET_KEY` set to a stable 64-char hex string
- [ ] `AILA_DATABASE_URL` points to managed PostgreSQL 16 with pgvector
- [ ] `AILA_PLATFORM_REDIS_URL` points to managed Redis 6+ / Memurai 3+
- [ ] `AILA_ADMIN_PASSWORD` set on first boot, removed afterwards
- [ ] `AILA_CORS_ORIGINS` matches the exact frontend origin(s); never `*`
- [ ] `AILA_BOOTSTRAP_KEY` only set during initial API-key bootstrap, then removed
- [ ] `AILA_SECRET_KEYRING_PATH` on secure, backed-up storage
- [ ] `AILA_API_HOST=0.0.0.0` (when exposing beyond localhost via a reverse proxy)
- [ ] All required workers running (one per queue, scaled via `WORKER_COUNT_<QUEUE>` or compose replicas)
- [ ] Reverse proxy configured with SSE-friendly settings (`proxy_buffering off`, long read timeout)
- [ ] Postgres backup + WAL archiving in place
- [ ] Log aggregation configured (`AILA_JSON_LOGS=1`)

---

## 10. Monitoring

### Health Checks

```bash
curl http://localhost:8000/health
curl -H "Authorization: Bearer $ADMIN_JWT" \
     http://localhost:8000/health/comprehensive
```

Per-check status is `up` / `down` / `degraded`. The top-level `status` field rolls
them up to `healthy` / `degraded` / `unhealthy`. `unhealthy` fires when any
critical check (database, primary subsystems) is `down`. Use `/health/comprehensive`
for the admin-only deep probe across every module.

### Task Queue Status

```bash
# List tasks
curl -H "Authorization: Bearer $JWT" http://localhost:8000/tasks

# Filter by status
curl -H "Authorization: Bearer $JWT" "http://localhost:8000/tasks?status=failed"
```

### Audit Trail

```bash
curl -H "Authorization: Bearer $JWT" http://localhost:8000/audit/events
```

`AuditEventRecord` is append-only; no UPDATE statements run against it. Use the
audit trail to reconstruct who triggered what across modules.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Tokens invalid after restart | `AILA_JWT_SECRET_KEY` not set | Set a stable 64-char hex secret |
| SSE / task endpoints return "Redis not configured" | `AILA_PLATFORM_REDIS_URL` empty | Point at a real Redis URL |
| Tasks stay in `queued` | No worker draining the queue | Start the matching `python -m aila worker -q <queue>` (or scale the compose service) |
| 503 on module endpoints | Platform init failed | Check server logs for `RuntimeError`; usually missing `AILA_ADMIN_PASSWORD` on first boot |
| `relation "X" does not exist` | Module's tables never created | Run `make db-init` (one-time) so SQLModel creates the missing tables; `make migrate` does not back-fill module DDL |
| `AILA_ADMIN_PASSWORD is required` at startup | First boot with no admin user and no env var | Set `AILA_ADMIN_PASSWORD`, start once, remove the env var |
| Phantom port owner on Windows after a crash | uvicorn ran without `--loop asyncio` | Restart with `--loop asyncio` (or `bash start.sh restart-backend`) |

---

*Last updated: 2026-06-07 (head: `062_vr_outcome_review`).*
