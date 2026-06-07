# VR Module — Installation & Operations Guide

Complete setup guide for the AILA Vulnerability Research module. Covers infrastructure, MCP servers, LLM configuration, target onboarding, investigation lifecycle, and troubleshooting.

---

## Prerequisites

| Component | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Backend runtime |
| Node.js | 20+ | Frontend build |
| pnpm | 10.30+ | Package manager (via corepack) |
| Docker | 24+ | Postgres + Redis |
| Git | 2.40+ | Source cloning for targets |

**External services (at least one required):**

| Service | Role | Default URL |
|---|---|---|
| **audit-mcp** | Source code indexing, semantic search, function reading | `http://127.0.0.1:18822` |
| **ida-headless-mcp** | Binary decompilation, function analysis (optional — only for binary targets) | `http://127.0.0.1:18821` |

**LLM provider (at least one required):**
- OpenAI API (GPT-4o, GPT-4o-mini)
- Anthropic API (Claude Opus 4, Claude Sonnet 4)
- Any OpenAI-compatible endpoint (local models via Ollama, vLLM, LiteLLM, etc.)

---

## Step 1: Infrastructure

### 1.1 Start Postgres + Redis

```bash
# From the AILA repo root
make dev-up
```

This runs `docker compose -f infra/utilities/docker-compose.yml up -d`, starting:
- **Postgres 16** with pgvector extension on `localhost:5432`
- **Redis 7** on `localhost:6379`

Verify:
```bash
make dev-status
# Both services should show "healthy"
```

### 1.2 Create the database

**First time only** (fresh database):
```bash
make db-init
```

This creates all tables and stamps the Alembic migration head. Do NOT run this on an existing database — use `make migrate` for subsequent schema updates.

**Existing database** (after pulling new code):
```bash
make migrate
# Applies any new Alembic migrations
```

### 1.3 Configure environment

Copy `.env.example` to `.env` and edit:

```bash
cp .env.example .env
```

**Required variables:**

```env
# Database
AILA_DATABASE_URL=postgresql+asyncpg://postgres:changeme@localhost:5432/aila

# Redis
AILA_PLATFORM_REDIS_URL=redis://127.0.0.1:6379/0

# Auth — generate a random secret
AILA_JWT_SECRET_KEY=<run: openssl rand -hex 32>

# Admin password — used on first boot only, remove after
AILA_ADMIN_PASSWORD=YourSecurePassword

# CORS
AILA_CORS_ORIGINS=http://localhost:3000

# LLM — pick your provider
OPENAI_API_KEY=sk-...
AILA_PLATFORM_LLM_DEFAULT_MODEL=gpt-4o
AILA_PLATFORM_LLM_BASE_URL=https://api.openai.com/v1
AILA_PLATFORM_LLM_DEFAULT_MAX_TOKENS=32000
AILA_LLM_TIMEOUT_SECONDS=300
```

**For local models (e.g., via LiteLLM proxy):**
```env
OPENAI_API_KEY=sk-fake
AILA_PLATFORM_LLM_DEFAULT_MODEL=your-model-name
AILA_PLATFORM_LLM_BASE_URL=http://localhost:4000/v1
```

---

## Step 2: Install dependencies

```bash
# Python backend
pip install -e ".[dev]"

# Frontend (pnpm workspace)
corepack enable
pnpm install
```

---

## Step 3: MCP Servers

The VR module needs at least **audit-mcp** to analyze source code targets.

### 3.1 audit-mcp (required)

Clone and install the audit-mcp server:

```bash
cd ..
git clone <your-audit-mcp-repo-url> audit-mcp
cd audit-mcp
pip install -e ".[dev]"
```

The audit-mcp server provides:
- Git repo cloning and indexing
- Semantic search across source code
- Function reading (by name or file:line range)
- Cross-reference analysis

### 3.2 ida-headless-mcp (optional — for binary targets)

Only needed if you analyze compiled binaries (ELF, PE, Mach-O):

```bash
cd ..
git clone <your-ida-headless-mcp-repo-url> ida-headless-mcp-exp
cd ida-headless-mcp-exp
pip install -e .
```

Requires a licensed IDA Pro installation.

### 3.3 MCP environment variables

```env
# audit-mcp (HTTP server, default :18822)
AUDIT_MCP_URL=http://127.0.0.1:18822
AUDIT_MCP_TIMEOUT=300
# Multi-worker uvicorn fan-out. Set via env OR via `--workers N` on the
# audit-mcp launch line. Linux / macOS only — Windows uvicorn multi-worker
# is broken (proactor IOCP handle leak), keep `AUDIT_MCP_WORKERS=1` there.
AUDIT_MCP_WORKERS=1
# anyio worker-thread pool (default 64). Raise when you see "all threads
# busy" symptoms despite the dedup hit-rate being high.
AUDIT_MCP_THREAD_POOL_LIMIT=64
# Per-tool concurrency cap. Name is uppercased. e.g.
# AUDIT_MCP_TOOL_CAP_SEMANTIC_SEARCH=8 doubles the default for semantic_search.
# See `GET http://127.0.0.1:18822/runtime` for live caps + availability.
# AUDIT_MCP_TOOL_CAP_<TOOLNAME>=<int>
# Per-tool wall-clock timeout. e.g. AUDIT_MCP_TIMEOUT_DEEP_AUDIT=1200.
# AUDIT_MCP_TIMEOUT_<TOOLNAME>=<seconds>
# Bounded timeout for the semble cold-build child process (default 7200s = 2h).
# Was unbounded historically; a stuck child would hold semble_status='building'
# forever and starve every query that touches the index.
AUDIT_MCP_SEMBLE_BUILD_TIMEOUT_S=7200

# ida-headless-mcp (optional, HTTP server, default :18821)
IDA_HEADLESS_URL=http://127.0.0.1:18821
IDA_HEADLESS_TIMEOUT=120
```

The audit-mcp `/runtime` endpoint returns live `{dedup: {inflight, hits, misses}, semaphores: {<tool>: {cap, available}}, thread_pool_limit}`. When agents complain "audit_mcp slow", read it first — `available: 0` on a tool is the bottleneck; bump its `AUDIT_MCP_TOOL_CAP_<TOOL>` cap. High `hits` with low `misses` means sibling branches are deduping the same call, which is the design.

Semble (the embedded code-chunk retriever inside audit-mcp) caches per-index pickles at `~/.audit-mcp/semble-cache/<index_id>.pkl`. After a clean restart, semble pickle reloads in ~9 s for repos audit-mcp has previously built; cold builds are minutes to hours depending on repo size, gated by `AUDIT_MCP_SEMBLE_BUILD_TIMEOUT_S`.

---

## Step 4: Start everything

### Option A: All-in-one launcher

```bash
bash start.sh
```

This starts all services:
- audit-mcp server (port 18822)
- ida-headless-mcp server (port 18821, if available)
- AILA backend (uvicorn, port 8000)
- AILA workers (one per queue: default, vr, vulnerability, forensics, sbd_nfr)
- AILA frontend (Vite dev server, port 3000)

### Option B: Manual (separate terminals)

```bash
# Terminal 1: audit-mcp
cd ../audit-mcp
python -m audit_mcp.http_api --port 18822

# Terminal 2: Backend
uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload --loop asyncio

# Terminal 3: VR worker
python -m aila worker -q vr

# Terminal 4: Frontend
pnpm dev
```

### Verify services

```bash
bash start.sh status
# Should show all services running with health check results
```

Or manually:
```bash
curl http://localhost:8000/health          # Backend
curl http://localhost:18822/health         # audit-mcp
curl http://localhost:3000                 # Frontend
```

---

## Step 5: First investigation

### 5.1 Login

Open `http://localhost:3000` in your browser. Login with `admin` / `<your AILA_ADMIN_PASSWORD>`.

### 5.2 Create a workspace

Navigate to **VR > Workspaces** and create one:
- Name: "LLM Infrastructure" (or any grouping you want)
- Theme: custom

### 5.3 Create a target

Navigate to **VR > Targets** and create one:
- Workspace: select your workspace
- Display name: "Ollama (ollama/ollama)"
- Kind: `source_repo`
- Descriptor: `{"input_source": "git_repo", "repo_url": "https://github.com/ollama/ollama"}`
- Primary language: `go`

The system will auto-clone the repo and index it via audit-mcp. Watch the target's analysis state transition: `pending` → `ingesting` → `ready`.

### 5.4 Create an investigation

Navigate to **VR > Investigations** and click **+ New investigation**:
- Title: "Ollama HTTP API SSRF Analysis"
- Target: select your Ollama target
- Kind: `discovery`
- Initial question: "Investigate whether Ollama's /api/pull endpoint is vulnerable to SSRF. The model name contains a hostname that is used to construct registry URLs. Check if internal IPs like 169.254.169.254 are reachable."
- Auto-pilot: ON
- Cost budget: $50 (or $0 for unlimited with local models)

Click **Start**. The investigation will:
1. Spawn 6 researcher branches (Halvar, Noor, Maddie, Yuki, Renzo, Wei)
2. Each branch reasons independently with its persona prompt
3. Branches use audit-mcp tools to read source code, search functions, trace data flow
4. After convergence, branches submit outcomes (findings, assessments)
5. A synthesis agent consolidates all branch verdicts
6. A claim verifier adversarially probes the consolidated finding

### 5.5 Monitor progress

The investigation detail page shows:
- **Status ribbon**: running/paused/completed with cost tracking
- **Outcomes**: findings with confidence levels and verifier verdicts
- **Hypotheses**: live/rejected hypothesis tracking
- **Turn stream**: per-turn reasoning with voice-section parsing
- **Branches**: persona cards with turn counts and status

---

## VR-Specific Configuration

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `VR_MAX_TURNS_PER_TASK` | `70` | Max reasoning turns per branch before forced submit |
| `VR_AUTO_PERSONA_DELIBERATION` | `1` | Set to `0` to disable auto-spawning of 5 sibling personas |
| `VR_VARIANT_HUNT_REJECT_CAP` | `3` | Exhaustion threshold for variant hunt branches |
| `AUDIT_MCP_URL` | `http://127.0.0.1:18822` | audit-mcp server URL |
| `AUDIT_MCP_TIMEOUT` | `300` | Per-tool-call default timeout (seconds), bridge side |
| `AUDIT_MCP_WORKERS` | `1` | Uvicorn workers (Linux/macOS only). Bridge pre-warms each worker on first index access when `>1` |
| `AUDIT_MCP_THREAD_POOL_LIMIT` | `64` | audit-mcp anyio worker-thread pool size |
| `AUDIT_MCP_TOOL_CAP_<NAME>` | per-tool default | Per-tool concurrency cap; name uppercased |
| `AUDIT_MCP_TIMEOUT_<NAME>` | per-tool default | Per-tool wall-clock cap (seconds); name uppercased |
| `AUDIT_MCP_SEMBLE_BUILD_TIMEOUT_S` | `7200` | Hard ceiling for semble cold-build subprocess |
| `IDA_HEADLESS_URL` | `http://127.0.0.1:18821` | ida-headless-mcp server URL |
| `IDA_HEADLESS_TIMEOUT` | `120` | Timeout for IDA tool calls (seconds) |
| `AILA_LLM_MAX_RETRIES` | `100` | LLM call retries on 429 / 502 / 503 errors |
| `AILA_LLM_RETRY_BASE_DELAY_S` | `1.0` | First retry backoff (seconds) |
| `AILA_LLM_RETRY_MAX_DELAY_S` | `30.0` | Max retry backoff cap (seconds) |

### LLM model routing

The VR module routes different persona roles to different LLM task types. Configure per-task-type models in the platform LLM routing config:

| Task Type | Used By | Recommended Model |
|---|---|---|
| `vulnerability_research.researcher` | Halvar, Noor (researchers) | Claude Opus 4 / GPT-4o |
| `vulnerability_research.critic` | Maddie, Yuki (critics) | Claude Opus 4 / GPT-4o |
| `vulnerability_research.implementer` | Renzo, Wei (implementers) | Claude Opus 4 / GPT-4o |
| `vulnerability_research.synthesizer` | Synthesis agent | Claude Sonnet 4 / GPT-4o-mini |
| `vulnerability_research.poc_writer` | PoC writer | Claude Sonnet 4 / GPT-4o |
| `vulnerability_research.discovery_research` | Single-branch fallback | Claude Opus 4 / GPT-4o |

All task types default to `AILA_PLATFORM_LLM_DEFAULT_MODEL` unless explicitly overridden.

---

## Service Management

### Restart individual services

```bash
bash start.sh restart-backend      # Backend only
bash start.sh restart-frontend     # Frontend only
bash start.sh restart-workers      # All workers
bash start.sh restart-worker vr    # VR worker only
bash start.sh restart-audit-mcp    # audit-mcp only
```

### Scale VR workers

For faster investigation throughput, start additional VR workers:

```bash
# Each in a separate terminal
python -m aila worker -q vr
python -m aila worker -q vr
```

Each worker processes tasks concurrently. With 6 personas per investigation, 2-3 workers prevent queue buildup.

### Check queue health

```bash
# Quick status
python -c "
import psycopg2
conn = psycopg2.connect('postgresql://postgres:changeme@localhost:5432/aila')
cur = conn.cursor()
cur.execute(\"SELECT status, count(*) FROM taskrecord WHERE track='vr' GROUP BY status\")
for r in cur.fetchall(): print(f'  {r[0]:12} {r[1]}')
conn.close()
"
```

---

## Investigation Lifecycle

```
                    ┌──────────────────────────────────────────────┐
                    │              INVESTIGATION                   │
                    │                                              │
  ┌─────────┐      │  ┌─────────┐    ┌──────────┐    ┌─────────┐│
  │ Operator │─────>│  │  Setup  │───>│   Loop   │───>│  Emit   ││
  │ creates  │      │  │ (spawn  │    │ (reason  │    │(outcome │││
  │          │      │  │ branches│    │  + tools) │    │+synth)  ││
  └─────────┘      │  └─────────┘    └──────────┘    └─────────┘│
                    │       │              │               │      │
                    │       ▼              ▼               ▼      │
                    │  6 branches    tool calls      findings     │
                    │  (H/N/M/Y/R/W) (audit-mcp)    patterns     │
                    │                (ida-headless)  disclosures  │
                    └──────────────────────────────────────────────┘
```

### States

| State | Description |
|---|---|
| `created` | Investigation created, waiting to be started |
| `running` | Engine is actively reasoning |
| `paused` | Paused by operator, low confidence, or cost budget |
| `completed` | All branches submitted, synthesis done |
| `failed` | Engine error (LLM timeout, MCP failure, etc.) |
| `abandoned` | Operator decided to stop |

### Personas

| Persona | Role | Style |
|---|---|---|
| **Halvar** | Researcher | Hypothesis-forward, "the bug exists" prior |
| **Noor** | Researcher | Structural/pattern analysis, bug-class reasoning |
| **Maddie** | Critic | Aggressive falsifier, "researcher is wrong" prior |
| **Yuki** | Critic | Methodical falsifier, invariant/regression testing focus |
| **Renzo** | Implementer | PoC builder, dispute settler, structured output |
| **Wei** | Implementer | Cost-efficient prioritizer, max info-gain per budget-unit |

---

## Auto-Recovery

The platform worker runs three recovery sweeps every 60 seconds:

| Sweep | What it fixes |
|---|---|
| **Orphan investigations** | `running` status with no active task → `completed` or `failed` |
| **Crashed cursors** | `__crashed__` workflow cursor with terminal task → deleted |
| **Stale branches** | 0-turn active branch with no task after 2h → `abandoned` |

### Manual recovery

```bash
# Re-enqueue a failed investigation via API
curl -X POST http://localhost:8000/vr/investigations/<id>/re-enqueue \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{}'

# Clear all crashed workflow cursors
python -c "
import psycopg2
conn = psycopg2.connect('postgresql://postgres:changeme@localhost:5432/aila')
cur = conn.cursor()
cur.execute(\"DELETE FROM workflow_state_cursor WHERE current_state = '__crashed__'\")
print(f'Cleared {cur.rowcount} cursors')
conn.commit()
conn.close()
"
```

---

## Troubleshooting

### Investigation stuck at "running" with no turns

**Cause**: Worker died mid-task, reaper marked task as failed, but investigation status wasn't updated.

**Fix**: The auto-reaper handles this. Or manually:
```bash
# Check if any task exists for this investigation
python -c "
import psycopg2
conn = psycopg2.connect('postgresql://postgres:changeme@localhost:5432/aila')
cur = conn.cursor()
cur.execute(\"SELECT status, count(*) FROM taskrecord WHERE kwargs_json LIKE '%%<investigation_id>%%' GROUP BY status\")
for r in cur.fetchall(): print(r)
conn.close()
"
```

### "Malformed tool_run command" loop

**Cause**: LLM produces empty `command` field. After 3 consecutive malformed commands, the circuit breaker injects a hard redirect.

**Fix**: Usually self-corrects after the circuit breaker fires. If not, re-enqueue the investigation.

### audit-mcp "index not found"

**Cause**: Target's audit-mcp index expired or the audit-mcp server restarted.

**Fix**: Re-analyze the target:
```bash
curl -X POST http://localhost:8000/vr/targets/<target_id>/analyze \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Workers not processing queue

**Cause**: Worker crashed or Redis connection lost.

**Fix**:
```bash
bash start.sh restart-workers
# Or start additional workers:
python -m aila worker -q vr
```

### Frontend shows "Something went wrong"

**Cause**: Usually a missing field in the API response or a JavaScript error.

**Fix**: Check the browser console for the error. Common causes:
- Unknown `status` value from backend (fixed by adding fallback defaults)
- Missing `ogl` dependency (run `pnpm install`)
- Stale Vite cache (delete `frontend/node_modules/.vite/` and restart)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                     AILA Platform                        │
│  ┌─────────┐  ┌──────────┐  ┌────────┐  ┌───────────┐  │
│  │ FastAPI  │  │  Workers │  │ Redis  │  │ Postgres  │  │
│  │ (uvicorn)│  │ (ARQ)    │  │ (queue)│  │ (pgvector)│  │
│  └────┬─────┘  └────┬─────┘  └────┬───┘  └─────┬─────┘  │
│       │              │             │            │        │
│  ┌────┴──────────────┴─────────────┴────────────┴────┐  │
│  │                  VR Module                         │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │  │
│  │  │ Agents   │  │ Workflow │  │ Services         │ │  │
│  │  │ (6 pers.)│  │ (states) │  │ (pattern, fuzz,  │ │  │
│  │  │          │  │          │  │  disclosure, CVE) │ │  │
│  │  └────┬─────┘  └──────────┘  └──────────────────┘ │  │
│  │       │                                            │  │
│  │  ┌────┴─────────────────────────┐                  │  │
│  │  │ MCP Bridges (tool dispatch)  │                  │  │
│  │  └────┬──────────────┬──────────┘                  │  │
│  └───────┼──────────────┼────────────────────────────┘  │
└──────────┼──────────────┼────────────────────────────────┘
           │              │
     ┌─────┴─────┐  ┌─────┴──────────┐
     │ audit-mcp │  │ ida-headless   │
     │ (source)  │  │ (binary, opt.) │
     └───────────┘  └────────────────┘
```

---

## Quick Reference

```bash
# Start everything
bash start.sh

# Stop everything
bash start.sh stop

# Restart just workers
bash start.sh restart-workers

# Check status
bash start.sh status

# Apply database migrations
make migrate

# Run backend tests
make test

# Run frontend type-check
pnpm -r run type-check

# View worker logs
tail -f .run/worker-vr.log
```
