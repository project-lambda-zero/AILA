# ADR-002: SQLite + Redis Hybrid Storage Architecture

**Status:** SUPERSEDED (2026; PostgreSQL replaces SQLite, sync fallback removed)
**Date:** 2025 (v1.5)
**Supersedes:** None

> Superseded. Durable persistence is now PostgreSQL 16 (pgvector). The
> in-process synchronous fallback was removed in Phase 178 / D-19;
> `TaskQueue.submit()` raises `WorkerUnreachableError` (HTTP 503) when
> Redis is unreachable. Live infrastructure is captured in
> `docs/ARCHITECTURE.md` and `infra/utilities/docker-compose.yml`. The
> body below is retained as historical context for the v1.5 decision.

## Context

AILA needs two categories of persistence:

1. **Durable state** -- API keys, systems, findings, audit events, config entries, task records.
   These must survive restarts and be queryable with standard SQL.
2. **Ephemeral streams** -- Task progress events, SSE real-time updates, ARQ job queue.
   These are high-throughput, short-lived, and consumed via pub/sub patterns.

Options considered:

1. **PostgreSQL for everything** -- Full ACID, pub/sub via LISTEN/NOTIFY, but operational overhead
   for a single-operator deployment.
2. **SQLite for everything** -- Zero-ops for durable state, but no pub/sub, no job queue.
3. **SQLite + Redis hybrid** -- SQLite for durable state, Redis for streams and job queue.
4. **SQLite + in-process fallback** -- SQLite for durable state, synchronous execution when
   Redis is unavailable.

## Decision

Use **SQLite for all durable persistence** and **Redis for ephemeral streams and ARQ job queue**,
with a **synchronous in-process fallback** when Redis is unavailable.

### SQLite layer

- All SQLModel tables defined in `storage/db_models.py`
- WAL mode for concurrent readers with single writer
- `session_scope()` context manager for transaction boundaries
- No ORM lazy loading -- all queries are explicit

### Redis layer

- ARQ job queue for async task execution (`arq:queue:{track}` keys)
- Redis Streams for progress events (`task:{task_id}:progress`, `scan:{run_id}:progress`)
- XADD with MAXLEN for bounded stream size (default 1000 events)
- XREAD with block for SSE consumers

### Sync fallback (TASK-11/D-19)

When Redis is unavailable (empty `redis_url` or connection failure):

- `TaskQueue.submit()` executes the task function synchronously in-process
- Task status transitions (QUEUED -> DONE/FAILED) are written directly to SQLite
- SSE endpoints degrade gracefully (no real-time progress, polling only)
- The fallback never raises -- it logs a warning and completes the work

## Consequences

### Positive

- Zero external dependencies for basic operation (SQLite only)
- Redis adds async capabilities without being a hard requirement
- Graceful degradation: the platform works without Redis, just synchronously
- SQLite WAL mode provides good read concurrency for the API server

### Negative

- SQLite single-writer constraint limits concurrent scans (see ADR-005)
- No built-in pub/sub on SQLite side (SSE requires Redis for real-time events)
- Two storage systems to understand and configure

### Neutral

- Redis URL configured via ConfigRegistry (`platform.redis_url`) or env var
- Memurai is the recommended Redis-compatible server on Windows
- PostgreSQL migration path exists (SQLModel/SQLAlchemy abstracts the dialect)

## References

- `src/aila/storage/database.py` -- session_scope, engine creation
- `src/aila/storage/registry.py` -- ConfigRegistry (SQLite-backed)
- `src/aila/platform/tasks/queue.py` -- TaskQueue with sync fallback
- `src/aila/platform/tasks/progress.py` -- ProgressStream (Redis Streams)
- `docs/ARCHITECTURE.md` -- INFRA-03, INFRA-06 constraints
