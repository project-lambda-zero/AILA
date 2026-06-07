# Task Queue Operator Guide

How to run, monitor, tune, and troubleshoot the AILA ARQ task queue.

---

## Architecture

AILA uses [ARQ](https://arq-docs.helpmanual.io/) (Async Redis Queue) for background task
execution. The architecture has three components:

```
API Server (uvicorn)              ARQ Worker (aila worker)
  |                                  |
  |  POST /analyze                   |
  |  -> TaskQueue.submit()           |
  |     -> TaskRecord (Postgres)     |
  |     -> arq:queue:vulnerability   |
  |        (Redis enqueue)           |
  |                                  |
  |                          execute_task_job()
  |                            -> mark RUNNING
  |                            -> start heartbeat
  |                            -> call module fn
  |                            -> mark DONE/FAILED
  |                                  |
  |  GET /tasks/{id}                 |
  |  -> TaskRecord (Postgres)        |
  |                                  |
  SSE /scans/{id}/progress    Redis Streams (progress)
```

**PostgreSQL** stores the durable task lifecycle (`TaskRecord` table).
**Redis** handles the job queue and progress streams.
**When Redis is unreachable**, `TaskQueue.submit()` deletes the ghost `TaskRecord` and raises `WorkerUnreachableError` (HTTP 503 through the standard envelope pipeline). There is no in-process fallback (D-19, Phase 178). Source: `src/aila/platform/tasks/queue.py:148-153, 210-222`.

---

## Starting the Worker

### Make targets (canonical)

```bash
make worker            # python -m aila worker            (queue: default)
make worker-vuln       # python -m aila worker -q vulnerability
make worker-forensics  # python -m aila worker -q forensics
make worker-sbd        # python -m aila worker -q sbd_nfr
make worker-vr         # python -m aila worker -q vr
```

Each `make worker-*` target depends on `dev-up` and `db-init` so the worker only starts once Postgres and Redis are up and the schema is at head.

### CLI

```bash
# Default queue
python -m aila worker

# Explicit queue track (-q or --queue)
python -m aila worker -q vulnerability
```

Source: `src/aila/cli.py:269-358`. The CLI also accepts `--redis-url` to override `AILA_PLATFORM_REDIS_URL`.

### ARQ queue tracks

`default` (PlatformModule and cross-cutting tasks), `vulnerability`, `forensics`, `sbd_nfr`, `vr`. One ARQ queue per track. Workers subscribe to exactly one queue.

### Direct ARQ (legacy callers)

```bash
arq aila.platform.tasks.worker.WorkerSettings
```

### Worker configuration

`WorkerSettings` in `src/aila/platform/tasks/worker.py:766-789`:

| Setting | Value | Purpose |
|---------|-------|---------|
| `job_timeout` | `3600` (1 hour) | Max time per job before ARQ kills it |
| `keep_result` | `3600` (1 hour) | How long job results stay in Redis |
| `max_tries` | `3` | Max retry attempts on failure |
| `retry_jobs` | `True` | Enable ARQ retry machinery |
| `allow_abort_jobs` | `True` | Cooperative abort via `TaskCancelled` |
| `health_check_interval` | `60` | ARQ health-key refresh interval (seconds) |
| `cron_jobs` | `[cron(reaper, second=0)]` | Zombie detection runs every minute |

`max_jobs` is not hard-coded; the ARQ default applies. INFRA-03 (one in-flight scan per system) is enforced at the service layer, not by worker count.

---

## start.sh + pidfile interplay

`start.sh` is the canonical Windows-host launcher. It spawns each worker via PowerShell `Start-Process` and records the spawned PID in `${RUN_DIR_ABS}/${slug}.pid` via the `record_pid` helper (`start.sh:163-176`). The worker slug is `worker-<queue>-<i>`, so PID files land in `.run/worker-<queue>-<i>.pid`.

Per-queue worker count is set by `WORKER_COUNT_<UPPER_QUEUE>` env vars. Defaults in `start.sh:50-56`:

| Queue | Default count |
|-------|---------------|
| `vr` | `5` |
| `default` | `1` |
| `vulnerability` | `1` |
| `forensics` | `1` |
| `sbd_nfr` | `1` |

`bash start.sh restart-worker <queue>` (`start.sh:465-469`) calls `restart_pool`, which kills the legacy single pidfile `worker-<q>.pid` AND every indexed pidfile `worker-<q>-*.pid`, then spawns `WORKER_COUNT_<q>` fresh workers via `spawn worker-<q>-<i> -m aila worker -q <q>`.

### Recovery when a stuck worker has no pidfile

Per CLAUDE.md D-253: `restart-worker` kills via pidfile. If the pidfile is absent but a stuck worker is still alive, the restart spawns ON TOP of it. The recovery sequence is:

1. Find rogue PIDs first. On Windows, Task Manager or PowerShell:
   ```powershell
   Get-Process | Where-Object { $_.CommandLine -match 'aila worker' }
   ```
   Stop-Process each match.
2. Then run `bash start.sh restart-worker <queue>`.

Skipping step 1 spawns the new pool alongside the stuck worker; both will then race for jobs on the same queue.

---

## Task Lifecycle

A task transitions through these states:

```
QUEUED -> RUNNING -> DONE
                  -> FAILED
                  -> CANCELLED

QUEUED -> WAITING (has depends_on)
WAITING -> QUEUED (all dependencies DONE)

RUNNING -> PAUSED (checkpoint requested)

FAILED  -> QUEUED (reaper crash recovery with checkpoint)
```

### State details

| Status | Meaning | Set by |
|--------|---------|--------|
| `QUEUED` | Ready for execution | `TaskQueue.submit()` |
| `WAITING` | Blocked on dependencies | `TaskQueue.submit()` (when `depends_on` specified) |
| `RUNNING` | Worker is executing | `execute_task_job()` |
| `PAUSED` | Checkpointed, awaiting resume | Cooperative pause |
| `DONE` | Completed successfully | `execute_task_job()` |
| `FAILED` | Unhandled exception or zombie detection | `execute_task_job()` or reaper |
| `CANCELLED` | Cooperative cancellation via `TaskCancelled` | Module code |

---

## Heartbeat Monitoring

### How it works

While a task is RUNNING, a heartbeat loop writes the current timestamp to
`TaskRecord.heartbeat_at` every N seconds:

```
heartbeat_interval_s = 30 (default, configurable)
```

The heartbeat runs as an `asyncio.Task` alongside the actual job execution.
It is cancelled in the `finally` block when the job completes (success, failure, or cancellation).

### What to check

**Healthy task:** `heartbeat_at` is within `heartbeat_interval_s` of now.

**Stale task:** `heartbeat_at` is older than `reaper_heartbeat_threshold_s` (default 86400s) — or, when `heartbeat_at` is NULL, `started_at` is older than `reaper_zombie_threshold_s` (default 3300s).
This indicates the worker crashed without cleanup.

### Query for stale tasks

```sql
SELECT id, fn_module, status, heartbeat_at, started_at
FROM taskrecord
WHERE status = 'running'
  AND heartbeat_at < NOW() - INTERVAL '3300 seconds';
```

Or via the API:

```
GET /tasks?status=running
```

Then check `heartbeat_at` in the response.

---

## Reaper (Zombie Detection)

### What it does

The reaper is an ARQ cron job that runs every minute (`second=0`). It detects
zombie tasks -- tasks stuck in RUNNING state because the worker crashed.

### Detection criteria

A task is a zombie if:
1. `status == RUNNING`
2. Its heartbeat is stale beyond the configured threshold. The reaper prefers `heartbeat_at` when present; if `heartbeat_at` is NULL it falls back to `started_at`.

Thresholds (`src/aila/platform/tasks/constants.py:55-56`):

- `REAPER_ZOMBIE_THRESHOLD_S = 3300` (55 minutes; applied when `heartbeat_at` is NULL)
- `REAPER_HEARTBEAT_THRESHOLD_S = 86400` (24 hours; applied when the worker is actively updating `heartbeat_at`)

The 55-minute floor sits deliberately below the 3600 s `job_timeout` so the reaper never races ARQ's own timeout for a still-running job.

### Actions

**Without checkpoint:** The task is marked FAILED with error:
```
Worker heartbeat timeout -- task presumed dead (TASK-10 reaper)
```

**With checkpoint:** The task is:
1. Marked FAILED (commits to DB)
2. Then re-enqueued as QUEUED with `error=None` and `completed_at=None`
3. When the worker picks it up, it finds `checkpoint_json` on the `TaskRecord`
4. The checkpoint data is passed as `resume_from` in the task kwargs
5. The module function resumes from the checkpoint

### Crash recovery flow

1. Worker crashes during scan (items 0-49 processed, checkpoint saved)
2. Reaper detects zombie (heartbeat stale beyond threshold)
3. Reaper marks FAILED, then re-queues
4. Worker picks up re-queued task
5. Task reads checkpoint: resume from item 50
6. Task processes items 50-99
7. Task completes as DONE

---

## Redis Dependency

### Required for

- ARQ job queue (async task execution)
- Redis Streams (SSE progress events)
- `XREAD` blocking for real-time SSE consumers

### Configuration

Set Redis URL via ConfigRegistry:

```
PUT /config/platform/redis_url
{"value": "redis://localhost:6379"}
```

Or via environment variable:

```bash
export AILA_PLATFORM_REDIS_URL=redis://localhost:6379
```

### Redis-unreachable behavior (D-19)

When Redis is unreachable, `TaskQueue.submit()` deletes the ghost `TaskRecord` and raises
`WorkerUnreachableError`, surfaced as HTTP 503 through the standard envelope pipeline. The
previous in-process fallback was removed in Phase 178 (D-19) because it ran the task inside
the API process and bypassed every queue-side safety (`max_tries`, dead-letter, per-track
isolation). Source: `src/aila/platform/tasks/queue.py:148-153, 210-222`.

### Windows: Memurai

Redis does not officially support Windows. Use [Memurai](https://www.memurai.com/)
as a Redis-compatible alternative:

```bash
# Install Memurai, then:
export AILA_PLATFORM_REDIS_URL=redis://localhost:6379
```

---

## Tuning Parameters

All task queue parameters are configurable via ConfigRegistry (namespace: `platform`):

| Parameter | Default | ConfigRegistry Key | What it controls |
|-----------|---------|-------------------|-----------------|
| Heartbeat interval | 30s | `heartbeat_interval_s` | How often worker writes heartbeat |
| Zombie threshold (no heartbeat) | 3300s | `reaper_zombie_threshold_s` | How stale `started_at` may be before the reaper acts when `heartbeat_at` is NULL |
| Heartbeat threshold (with heartbeat) | 86400s | `reaper_heartbeat_threshold_s` | How stale `heartbeat_at` may be before the reaper acts when the worker is updating it |
| Job timeout | 3600s | `arq_job_timeout_s` | Max job execution time |
| Max retries | 3 | `arq_max_tries` | Retry attempts on failure |
| Result retention | 3600s | `arq_keep_result_s` | How long results stay in Redis |
| Stream max length | 1000 | `progress_stream_maxlen` | Max events per progress stream |

### How to change

Via API (requires admin):

```
PUT /config/platform/heartbeat_interval_s
{"value": "60"}
```

Via environment variable:

```bash
export AILA_PLATFORM_HEARTBEAT_INTERVAL_S=60
```

**Note:** Changes to `arq_job_timeout_s`, `arq_max_tries`, and `arq_keep_result_s` are
read from `WorkerSettings` at worker startup. To apply changes to these, restart the
ARQ worker. Other parameters (heartbeat, reaper threshold, stream maxlen) are read
at runtime via `get_task_tuning()` and take effect without restart.

### Tuning guidance

| Scenario | Adjustment |
|----------|------------|
| Long-running scans | Increase `arq_job_timeout_s` (e.g., 7200 for 2 hours) |
| Slow networks | Increase `heartbeat_interval_s` (e.g., 60s); `reaper_heartbeat_threshold_s` defaults to 24h so it already tolerates long pauses |
| Frequent transient failures | Increase `arq_max_tries` (e.g., 5) |
| High progress event volume | Increase `progress_stream_maxlen` (e.g., 5000) |
| Quick zombie detection | Decrease `reaper_zombie_threshold_s` (must stay above `arq_job_timeout_s` so the reaper never preempts a still-running job) |

---

## Troubleshooting

### Task stuck in RUNNING

1. Check `heartbeat_at` -- if stale, the worker likely crashed
2. Wait for reaper (runs every minute) or manually update:
   ```sql
   UPDATE taskrecord SET status = 'failed',
     error = 'Manual intervention -- worker presumed dead'
   WHERE id = '<task_id>';
   ```
3. If the task had a checkpoint, re-queue it:
   ```sql
   UPDATE taskrecord SET status = 'queued', error = NULL, completed_at = NULL
   WHERE id = '<task_id>' AND checkpoint_json IS NOT NULL;
   ```

### Task stuck in QUEUED

1. Verify the ARQ worker is running: check for the `aila worker` process
2. Verify Redis is reachable: `redis-cli ping` should return `PONG`
3. Check the Redis queue has the job: `redis-cli LLEN arq:queue:vulnerability`
4. If the task is QUEUED but Redis is now unreachable, Redis went down after the enqueue. The task will resume once Redis is back and a worker picks it up; there is no in-process fallback.

### Task stuck in WAITING

1. Check `depends_on_json` for the task's dependency list
2. Query the dependency tasks -- all must be DONE for this task to advance to QUEUED
3. If a dependency is FAILED, this task will remain in WAITING indefinitely

### Redis connection errors

1. Check `platform.redis_url` via `GET /config`
2. Verify Redis/Memurai is running: `redis-cli -u <url> ping`
3. If Redis is unreachable, new `TaskQueue.submit()` calls raise `WorkerUnreachableError` (HTTP 503) — the ghost `TaskRecord` is deleted before the call returns. Existing queued jobs in Redis resume once Redis is back and a worker reconnects.

### Worker keeps crashing

1. Check worker logs for stack traces
2. Common causes: module import errors, missing dependencies, DB connection issues
3. Increase `arq_max_tries` for transient failures
4. For persistent crashes, fix the underlying issue -- retries will not help

---

## Redis Key Reference

| Key Pattern | Type | Purpose |
|-------------|------|---------|
| `arq:queue:{track}` | List | ARQ job queue for a track |
| `task:{task_id}:progress` | Stream | Progress events for a task |
| `scan:{run_id}:progress` | Stream | Progress events for a scan run |
| `arq:result:{task_id}` | String | ARQ job result (temporary) |

---

## Dead-letter queue

Tasks that exhaust `max_tries` retries or are explicitly dead-lettered land in the
dead-letter store. Two admin endpoints (both require the `admin` role) drive recovery:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/admin/tasks/dead-letter` | GET | List dead-lettered tasks |
| `/admin/tasks/dead-letter/{task_id}/requeue` | POST | Requeue a task back to its original track |

Source: `src/aila/api/routers/admin_dead_letter.py:159-204`.


*Source: `src/aila/platform/tasks/worker.py`, `src/aila/platform/tasks/queue.py`, `src/aila/platform/tasks/constants.py`*
*Last updated: 2026-06-07*
