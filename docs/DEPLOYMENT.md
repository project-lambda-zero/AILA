# Deployment Guide

How to deploy AILA in production with FastAPI, ARQ worker, and Redis.

---

## Architecture Overview

```
                                    +------------------+
                                    |   Redis / Memurai |
                                    |   (task queue +   |
                                    |    SSE streams)   |
                                    +--------+---------+
                                             |
            +-----------+           +--------+---------+
 Clients -->| Reverse   |---------->|   FastAPI Server  |
            |  Proxy    |           |  (aila serve)     |
            +-----------+           +--------+---------+
                                             |
                                    +--------+---------+
                                    |   SQLite (WAL)    |
                                    +------------------+
                                             |
                                    +--------+---------+
                                    |   ARQ Worker      |
                                    |  (aila worker)    |
                                    +------------------+
```

Three processes:
1. **FastAPI server** -- serves REST API, submits tasks to Redis
2. **ARQ worker** -- executes background tasks (scans, platform.handle)
3. **Redis/Memurai** -- task queue broker and SSE progress streams

---

## Prerequisites

- Python 3.10+
- Redis 6+ (Linux) or Memurai 3+ (Windows)
- SSH access to target systems (for vulnerability scanning)
- OpenAI-compatible LLM provider

---

## 1. Install AILA

```bash
git clone <repo-url>
cd Playground
pip install -e .
```

For development dependencies:

```bash
pip install -e ".[dev]"
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


---

## 4. Environment Variables

Set these before starting the server. See `docs/ENV_VARS.md` for full reference.

### Required for Production

```bash
# JWT signing secret -- MUST be set, otherwise tokens invalidate on restart
export AILA_JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Database on persistent storage
export AILA_DATABASE_URL=sqlite:////data/aila/aila.db

# Report output directory
export AILA_REPORT_DIR=/data/aila/reports

# Secret keyring
export AILA_SECRET_KEYRING_PATH=/data/aila/secrets/keyring.json

# CORS origins (your frontend URL)
export AILA_CORS_ORIGINS=https://aila.example.com

# Redis for task queue
export AILA_PLATFORM_REDIS_URL=redis://localhost:6379
```

### Optional

```bash
# Listen on all interfaces
export AILA_API_HOST=0.0.0.0
export AILA_API_PORT=8000

# Bootstrap admin key on first start
export AILA_BOOTSTRAP_KEY=your-initial-admin-key

# Structured JSON logs
export AILA_JSON_LOGS=1
```

---

## 5. Start the FastAPI Server

### Using the CLI

```bash
aila serve
```

This runs `uvicorn aila.api.app:app` with the host and port from Settings.

### Using uvicorn directly

```bash
uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --workers 1
```

Note: Use `--workers 1` with SQLite. SQLite handles concurrency via WAL mode, but multiple worker processes require careful session management. For multi-worker deployments, switch to PostgreSQL.

### First Start

On first start with `AILA_BOOTSTRAP_KEY` set:
1. The database is created and all tables are initialized
2. An admin API key is created from the bootstrap key value
3. The platform discovers and loads all installed modules

After first start, remove `AILA_BOOTSTRAP_KEY` from the environment.

---

## 6. Start the ARQ Worker

```bash
aila worker
```

The worker connects to Redis (from `AILA_PLATFORM_REDIS_URL`) and processes background tasks:
- Vulnerability scans submitted via `POST /analyze`
- Freeform tasks submitted via `POST /task`
- Report explanation tasks

Worker features:
- Heartbeat every 30s (configurable via `AILA_PLATFORM_HEARTBEAT_INTERVAL_S`)
- Zombie task reaper detects crashed workers after 120s (configurable)
- Checkpoint/resume for long-running scans

### Without Redis

AILA operates without Redis in sync fallback mode:
- `POST /analyze` and `POST /task` execute synchronously in-process
- No SSE progress streaming (endpoints return informational message)
- No background workers needed

This is suitable for development and single-user deployments.

---

## 7. Create API Keys

### Via CLI (recommended for first key)

```bash
aila create-api-key --role admin --label "ops-team"
```

The raw key is displayed once and never stored. Save it securely.

### Via API (subsequent keys)

```bash
curl -X POST http://localhost:8000/auth/keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "operator", "label": "ci-pipeline"}'
```

### Get a JWT Token

```bash
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "aila_sk_..."}'
```

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
- [ ] `AILA_DATABASE_URL` points to persistent storage
- [ ] `AILA_CORS_ORIGINS` set to exact frontend origin(s)
- [ ] `AILA_PLATFORM_REDIS_URL` set for task queue
- [ ] `AILA_BOOTSTRAP_KEY` removed after first start
- [ ] `AILA_SECRET_KEYRING_PATH` on secure, backed-up storage
- [ ] `AILA_API_HOST=0.0.0.0` if exposing beyond localhost
- [ ] ARQ worker running (`aila worker`)
- [ ] Reverse proxy configured with SSE support
- [ ] Database backup schedule in place
- [ ] Log aggregation configured (`AILA_JSON_LOGS=1`)

---

## 10. Monitoring

### Health Check

```bash
curl http://localhost:8000/health
```

Returns:
- `healthy` -- all checks pass
- `degraded` -- some modules report issues
- `unhealthy` -- database is down

### Task Queue Status

```bash
# List all tasks
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/tasks

# Filter by status
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8000/tasks?status=failed"
```

### Audit Trail

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/audit/events
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Tokens invalid after restart | `AILA_JWT_SECRET_KEY` not set | Set a stable secret |
| SSE returns "Redis not configured" | `AILA_PLATFORM_REDIS_URL` not set | Configure Redis URL |
| Tasks stay in "queued" | ARQ worker not running | Start `aila worker` |
| 503 on POST /analyze | Platform init failed | Check server logs |
| Database locked errors | Multiple writers without WAL | WAL should be auto-enabled; check for NFS |

---

*Last updated: 2026-04-05 (v1.7)*
