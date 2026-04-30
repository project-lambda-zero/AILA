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
  |     -> TaskRecord (SQLite)       |
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
  |  -> TaskRecord (SQLite)          |
  |                                  |
  SSE /scans/{id}/progress    Redis Streams (progress)
```

**SQLite** stores the durable task lifecycle (`TaskRecord` table).
**Redis** handles the job queue and progress streams.
**When Redis is unavailable**, tasks execute synchronously in-process (sync fallback).

---

## Starting the Worker

### CLI

```bash
# Start a single ARQ worker (recommended for SQLite deployments)
aila worker

# With explicit queue track
aila worker --queue vulnerability
```

### Direct ARQ

```bash
arq aila.platform.tasks.worker.WorkerSettings
```

### Worker configuration

`WorkerSettings` in `src/aila/platform/tasks/worker.py`:

| Setting | Value | Purpose |
|---------|-------|---------|
| `max_jobs` | `1` | Single-concurrent-scan (INFRA-03, SQLite single-writer) |
| `job_timeout` | `3600` (1 hour) | Max time per job before ARQ kills it |
| `keep_result` | `3600` (1 hour) | How long job results stay in Redis |
| `max_tries` | `3` | Max retry attempts on failure |
| `retry_jobs` | `True` | Enable ARQ retry machinery |
| `cron_jobs` | `[reaper every minute]` | Zombie task detection |

**Single-worker constraint:** With SQLite, only one worker should run. Multiple workers
cause write-lock contention. See `docs/ADR/ADR-005-single-concurrent-scan.md`.

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

**Stale task:** `heartbeat_at` is older than `reaper_zombie_threshold_s` (default 120s).
This indicates the worker crashed without cleanup.

### Query for stale tasks

```sql
SELECT id, fn_module, status, heartbeat_at, started_at
FROM taskrecord
WHERE status = 'running'
  AND heartbeat_at < datetime('now', '-120 seconds');
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
2. `heartbeat_at < now - reaper_zombie_threshold_s` (default 120 seconds)

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

```
1. Worker crashes during scan (items 0-49 processed, checkpoint saved)
2. Reaper detects zombie (heartbeat stale > 120s)
3. Reaper marks FAILED, then re-queues
4. Worker picks up re-queued task
5. Task reads checkpoint: resume from item 50
6. Task processes items 50-99
7. Task completes as DONE
```

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

### Sync fallback (TASK-11)

When Redis is unavailable (empty URL or connection failure):

1. `TaskQueue.submit()` executes the task function **synchronously in-process**
2. The task runs in the API server process (blocking for that request)
3. `TaskRecord` status transitions directly from QUEUED to DONE/FAILED
4. The fallback **never raises** -- it logs a warning and completes the work
5. SSE progress streams are not available (polling only)

This means AILA works without Redis, just without async execution or real-time progress.

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
| Zombie threshold | 120s | `reaper_zombie_threshold_s` | How stale before reaper acts |
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
| Slow networks | Increase `heartbeat_interval_s` (e.g., 60s) and `reaper_zombie_threshold_s` (e.g., 300s) |
| Frequent transient failures | Increase `arq_max_tries` (e.g., 5) |
| High progress event volume | Increase `progress_stream_maxlen` (e.g., 5000) |
| Quick zombie detection | Decrease `reaper_zombie_threshold_s` (minimum: 2x heartbeat interval) |

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
4. If no worker and no Redis, the task should have used sync fallback -- check logs

### Task stuck in WAITING

1. Check `depends_on_json` for the task's dependency list
2. Query the dependency tasks -- all must be DONE for this task to advance to QUEUED
3. If a dependency is FAILED, this task will remain in WAITING indefinitely

### Redis connection errors

1. Check `platform.redis_url` via `GET /config`
2. Verify Redis/Memurai is running: `redis-cli -u <url> ping`
3. If Redis is down, new tasks will use sync fallback (existing queued tasks in Redis are lost until Redis recovers)

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

*Source: `src/aila/platform/tasks/worker.py`, `src/aila/platform/tasks/queue.py`, `src/aila/platform/tasks/constants.py`*
*Last updated: 2026-04-05*
