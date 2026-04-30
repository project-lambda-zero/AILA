# ADR-005: Single-Concurrent-Scan Constraint (INFRA-03)

**Status:** Accepted
**Date:** 2025 (v1.5)
**Supersedes:** None

## Context

AILA v1.5 uses SQLite as its primary database. SQLite serializes all writes through a
single WAL (Write-Ahead Log) writer. Running multiple scan tasks concurrently against
the same database causes write-lock contention:

- Multiple ARQ workers writing findings, reports, and audit events simultaneously
- BUSY timeout errors under sustained write load
- Potential hung tasks when one writer blocks another indefinitely

The vulnerability scan workflow is write-heavy: each scan produces hundreds of finding
records, report artifacts, and audit events. Concurrent scans amplify the contention
problem to the point of practical failure.

## Decision

Enforce a **single-concurrent-scan contract**:

- ARQ `WorkerSettings.max_jobs = 1` -- Each worker process handles exactly one task at a time
- `uvicorn` runs with a single worker (default for `aila serve`)
- The `aila worker` CLI command starts ARQ with these settings by default

### Enforcement points

1. **ARQ level**: `max_jobs=1` in `WorkerSettings` prevents the worker from accepting
   a second job while one is running.
2. **Deployment level**: Documentation specifies single-worker uvicorn and single ARQ worker.
3. **No application-level lock**: The constraint is enforced structurally (worker config),
   not with distributed locks or semaphores.

### Task results as file paths (INFRA-06)

To keep SQLite row sizes small under the single-writer model:

- Large task results (scan reports, CSV exports) are written to disk
- `TaskRecord.result_path` stores the filesystem path to the artifact
- The database row only stores metadata, not content

## Consequences

### Positive

- Zero write-lock contention under normal operation
- No distributed locking infrastructure needed
- Simple deployment model (one process, one worker)
- Predictable performance characteristics

### Negative

- Only one scan can run at a time (operators must queue scans sequentially)
- No parallelism for multi-system fleet scans within a single scan run
- Limits throughput for large deployments

### Migration path

- **PostgreSQL**: Switching to PostgreSQL removes the single-writer constraint entirely.
  Set `AILA_DATABASE_URL` to a PostgreSQL connection URL and increase `max_jobs`.
- **Multiple workers**: With PostgreSQL, multiple ARQ workers can run concurrently,
  each handling separate scans against the same database without contention.

### Neutral

- The constraint is operational, not architectural -- the code itself does not enforce it
- Stress tests (Phase 103: STRESS-01, STRESS-03) validated WAL contention behavior
- Task queue supports dependency ordering (depends_on) for sequential multi-step workflows

## References

- `docs/ARCHITECTURE.md` -- INFRA-03 constraint documentation
- `src/aila/platform/tasks/worker.py` -- WorkerSettings.max_jobs = 1
- `src/aila/cli.py` -- `aila worker` command (default single-worker)
- Phase 103: WAL contention stress test (3 writers + 5 readers, zero lock errors)
