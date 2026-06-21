# AILA Test Guide

How to write and run tests for the AILA platform.

---

## Test Stack

| Tool | Purpose |
|------|---------|
| pytest | Test runner and fixture framework |
| pytest-asyncio | Async test support |
| httpx (AsyncClient + ASGITransport) | HTTP client for FastAPI tests |
| unittest.mock (MagicMock, patch) | Mocking and patching |
| tmp_path | Per-test isolated temporary directories |

**Do NOT use `TestClient` from Starlette.** It deadlocks on SSE endpoints and async routes. Always use `httpx.AsyncClient` with `ASGITransport`.

Note: `pytest-asyncio` is required (config sets `asyncio_mode = "auto"` in `pyproject.toml`) but is not currently declared in `pyproject.toml` `[project.optional-dependencies] dev`. Install explicitly with `pip install pytest-asyncio` if it isn't already in your environment.

---

## Conftest Hierarchy

```text
tests/
  conftest.py                           # Root — minimal (just imports)
  api/
    conftest.py                         # API fixtures: session PG engine, test_db,
                                        # tokens, async_client, seeded data
  storage/
    conftest.py                         # `pg_url`, `pg_engine`, `pg_session` for
                                        # PostgreSQL-backed storage tests
  modules/
    vulnerability/
      conftest.py                       # Module fixtures: mirrors test_db + module-specific seeds
```

Each conftest provides fixtures scoped to its directory. API tests use `tests/api/conftest.py`. Module-level tests use `tests/modules/<module_id>/conftest.py`. Storage tests use `tests/storage/conftest.py`.
---

## Core Fixtures

### test_db

The foundation fixture. Every test that touches the database depends on `test_db`.

**What it does:**
1. Targets PostgreSQL via `AILA_TEST_DATABASE_URL` (default `postgresql+asyncpg://postgres:admin@localhost:5432/aila_test`). The session-scoped `_session_async_engine` fixture drops and recreates every table once per pytest session so TSVECTOR and pgvector columns load natively.
2. Overrides `AILA_DATABASE_URL` for the test, clears the Settings `lru_cache`, and registers the session engine in `_ASYNC_ENGINES` / `_INITIALIZED_URLS` so application code resolves to the test DB.
3. Imports every module's `db_models` so `SQLModel.metadata` is complete (platform + vr + vulnerability + forensics).
4. On teardown, truncates every table to isolate the next test, then restores the prior `AILA_DATABASE_URL` value.

**Scope:** `function`. The engine is session-scoped (one connection pool for the whole pytest run); per-test isolation is via `TRUNCATE`, not by reconnecting.

**Prerequisite:** a running PostgreSQL with pgvector. `make dev-up` brings up `aila-postgres` on `127.0.0.1:5432` with the right extensions. Storage tests create the `aila_test` database on first run via `psql` (see `tests/storage/conftest.py` for the connection defaults — `AILA_TEST_PG_HOST/PORT/USER/PASSWORD/DB` override them).

```python
@pytest_asyncio.fixture(scope="function")
async def test_db(_session_async_engine) -> AsyncGenerator[None, None]:
    ...
    yield
    # Cleanup: TRUNCATE every table, restore AILA_DATABASE_URL
```

**Why TRUNCATE over drop+recreate:** drop+recreate per test costs ~3s on Windows. TRUNCATE keeps the schema warm and runs in milliseconds.

### Token Fixtures

Three roles with cascading dependencies:

```
test_db -> admin_key_record -> admin_token
test_db -> admin_key_record -> operator_key_record -> operator_token
test_db -> admin_key_record -> reader_key_record -> reader_token
```

Each `*_key_record` fixture:
1. Generates a raw API key via `generate_api_key()`.
2. Creates an `ApiKeyRecord` with the hashed key.
3. Persists it via `session_scope()`.
4. Stashes the raw key on `record._raw_key` for fixtures that need it.

Each `*_token` fixture calls `issue_jwt_token(record)` to produce a Bearer token string.

```python
@pytest.fixture(scope="function")
def admin_token(admin_key_record) -> str:
    token, _ = issue_jwt_token(admin_key_record)
    return token
```

### async_client

HTTP client for endpoint tests. Uses `ASGITransport`, not `TestClient`.

```python
@pytest_asyncio.fixture(scope="function")
async def async_client(test_db) -> AsyncGenerator[AsyncClient, None]:
    test_app = create_app()
    test_app.state.platform = None
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client
```

**Key details:**
- `app.state.platform = None` because tests do not bootstrap the full platform.
- Health and auth endpoints handle `None` gracefully.
- Lifespan events are NOT triggered by ASGITransport (intentional).

### async_client_with_registries

For tests that need config or tool endpoints:

```python
@pytest_asyncio.fixture(scope="function")
async def async_client_with_registries(test_db) -> AsyncGenerator[AsyncClient, None]:
    config_registry = ConfigRegistry()
    tool_registry = ToolRegistry()

    stub_runtime = MagicMock()
    stub_runtime.config_registry = config_registry
    stub_runtime.tool_registry = tool_registry

    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app = create_app()
    test_app.state.platform = stub_platform
    ...
```

### Seeded Data Fixtures

Pre-populate the test DB with domain data:

| Fixture | Seeds | Depends On |
|---------|-------|------------|
| `seeded_run` | One completed WorkflowRunRecord | `test_db` |
| `seeded_audit_events` | Three AuditEventRecords | `test_db`, `seeded_run` |
| `seeded_config_entry` | One ConfigEntryRecord | `test_db` |
| `seeded_system` | One ManagedSystemRecord | `test_db` |
| `seeded_findings` | Three LatestFindingRecords | `test_db`, `seeded_system` |

---

## Writing Tests

### Endpoint Tests

```python
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_list_systems(async_client: AsyncClient, admin_token: str, seeded_system):
    """GET /systems returns seeded system."""
    response = await async_client.get(
        "/systems",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
```

**Pattern:**
1. Declare fixtures in the function signature (pytest injects them).
2. Use `async def` with the `pytestmark = pytest.mark.asyncio` module marker.
3. Set `Authorization` header with the token fixture.
4. Assert status code first, then response body structure.

### RBAC Tests

Test every endpoint against every role to prove access control:

```python
@pytest.mark.parametrize("role,expected", [
    ("admin", 200),
    ("operator", 200),
    ("reader", 200),
    ("none", 401),
])
async def test_rbac_list_systems(async_client, admin_token, operator_token, reader_token, role, expected):
    tokens = {"admin": admin_token, "operator": operator_token, "reader": reader_token, "none": None}
    headers = {"Authorization": f"Bearer {tokens[role]}"} if tokens[role] else {}
    response = await async_client.get("/systems", headers=headers)
    assert response.status_code == expected
```

### Parametrized Tests

Use `pytest.mark.parametrize` for testing multiple inputs:

```python
@pytest.mark.parametrize("endpoint,method", [
    ("/auth/token", "POST"),
    ("/systems", "POST"),
    ("/config/vulnerability", "PUT"),
])
async def test_empty_body_returns_422(async_client, admin_token, endpoint, method):
    response = await getattr(async_client, method.lower())(
        endpoint,
        headers={"Authorization": f"Bearer {admin_token}"},
        json={},
    )
    assert response.status_code == 422
```

### Unit Tests (Non-HTTP)

For testing functions, utilities, and data transforms without HTTP:

```python
def test_seed_version_type():
    """SEED_VERSION must be a string, not an int."""
    from aila.modules.hello_world.module import SEED_VERSION
    assert isinstance(SEED_VERSION, str)
```

### Stress Tests

Concurrent endpoint testing:

```python
import asyncio

async def test_concurrent_token_issuance(async_client, admin_token):
    """10 concurrent POST /auth/token all produce valid JWTs."""
    async def issue_one():
        resp = await async_client.post(
            "/auth/token",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        return resp.json()["access_token"]

    tokens = await asyncio.gather(*[issue_one() for _ in range(10)])
    assert len(set(tokens)) == 10  # all unique
```

### SSE / Streaming Tests

Mock the ProgressStream and platform.handle to avoid real Redis:

```python
async def test_sse_scan_progress(async_client, admin_token):
    """SSE stream emits stage events."""
    with patch("aila.api.routers.scans.ProgressStream") as mock_stream:
        mock_stream.return_value.stream_events = AsyncMock(
            return_value=async_iter([b"data: {\"stage\": \"scan\"}\n\n"])
        )
        response = await async_client.get(
            "/scans/run-001/progress",
            headers={
                "Authorization": f"Bearer {admin_token}",
                "Accept": "text/event-stream",
            },
        )
        assert response.status_code == 200
```

### Mocking Patterns

**Patch at the import site, not the definition site:**

```python
# Module under test imports: from aila.tasks.progress import ProgressStream
# Patch WHERE it is imported:
with patch("aila.api.routers.tasks.ProgressStream") as mock:
    ...
```

**MagicMock for complex objects:**

```python
stub_platform = MagicMock()
stub_platform.runtime.config_registry = ConfigRegistry()
```

---

## Test File Naming

| File Type | Test File | What to Test |
|-----------|-----------|-------------|
| Router (`routers/auth.py`) | `test_auth.py` | Endpoint status codes, response shapes, RBAC |
| Schema (`schemas/auth.py`) | `test_auth_schemas.py` | Validation rules, extra="forbid", serialization |
| Service (`services/export.py`) | `test_export.py` | Business logic, edge cases |
| Module (`modules/*/module.py`) | `test_module.py` | Contract methods, registration |
| Honesty audit rules | `test_honesty_audit.py` | Rule triggers on crafted AST |
| Cross-cutting | `test_93_rbac_*.py` | Multi-endpoint, multi-role matrices |
| Stress | `test_103_*.py` | Concurrency, failure resilience |

---

## Running Tests

```bash
# All backend tests except e2e + integration (matches `make test`)
pytest tests/ --ignore=tests/test_e2e.py --ignore=tests/test_e2e_live.py -x

# Same gating via Make
make test

# E2E backend tests (require live infrastructure: PG + Redis + workers)
pytest tests/test_e2e.py -v       # or: make test-e2e

# Run one file or one test
pytest tests/api/test_auth.py
pytest tests/api/test_auth.py::test_token_issuance

# Coverage already on by default (see [tool.pytest.ini_options].addopts)
pytest tests/ -k auth
```

`pyproject.toml` sets `addopts = "--cov=src/aila --cov-report=term-missing -m 'not e2e and not integration'"`, so `pytest tests/` skips anything marked `e2e` or `integration` and emits a coverage report at the end. The `e2e` and `integration` markers gate tests that need real API keys or live infrastructure.

Frontend tests run through the pnpm workspace:

```bash
pnpm -r run test                                          # vitest across shell + every module
pnpm --filter @aila/shell run test                        # shell only (same as `make test-frontend`)
pnpm --filter @aila/vulnerability-frontend run test       # one module
```

End-to-end browser tests live under `frontend/tests/e2e/` and run via Playwright (`frontend/playwright.config.ts`). The config has a `webServer` hook that boots `pnpm run dev` on `http://localhost:3000` and reuses an existing server outside CI. Chromium is the default project; Firefox and WebKit run a smoke subset (auth + dashboard + systems list).

## Coverage Targets

- Backend: `[tool.coverage.report].fail_under = 25` in `pyproject.toml`. `pytest tests/` reports against `src/aila/`. New endpoint code should land with enough tests that the project-wide threshold stays clear.
- Frontend: `frontend/vitest.config.ts` enforces `lines: 80`, `branches: 70`, `functions: 80` on the `coverage.include` set (currently `src/hooks/**`, `src/platform/features/radar/topologyUtils.ts`, `src/platform/features/viz/useChartExport.ts`).

Re-run with coverage explicitly:

```bash
pytest tests/ --cov=src/aila --cov-report=term-missing
pnpm --filter @aila/shell run test -- --coverage
```

Focus coverage on:
- Every endpoint returns expected status codes for valid and invalid inputs.
- Every RBAC role combination is tested.
- Every error path returns the correct ErrorResponse shape.
- Schema validation rejects invalid input (extra fields, wrong types, missing required).

---

## Common Testing Mistakes

1. **Using TestClient instead of AsyncClient** — TestClient deadlocks on SSE and async routes.
2. **Sharing engines across tests** — registering an engine that points at a different URL than `_session_async_engine` desyncs the per-test TRUNCATE list.
3. **Forgetting `test_db` dependency** — database operations fail with "no such table" because `AILA_DATABASE_URL` still points at the dev DB.
4. **Patching at definition site** — patches must target the import site in the module under test.
5. **Missing `pytest.mark.asyncio`** — the project sets `asyncio_mode = "auto"`, but bare `def` tests that need an event loop still silently pass; mark them async or use `pytest_asyncio.fixture`.
6. **Asserting response body before status code** — status-code assertion gives a clearer failure message.
7. **Skipping `make dev-up`** — every backend test depends on the PostgreSQL container; without it the session fixture fails on first connect.
