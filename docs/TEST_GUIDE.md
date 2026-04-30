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

---

## Conftest Hierarchy

```text
tests/
  conftest.py                           # Root -- minimal (just imports)
  api/
    conftest.py                         # API fixtures: test_db, tokens, async_client, seeded data
  modules/
    vulnerability/
      conftest.py                       # Module fixtures: mirrors test_db + module-specific seeds
```

Each conftest provides fixtures scoped to its directory. API tests use `tests/api/conftest.py`. Module-level tests use `tests/modules/<module_id>/conftest.py`.

---

## Core Fixtures

### test_db

The foundation fixture. Every test that touches the database depends on `test_db`.

**What it does:**
1. Creates a fresh SQLite database in `tmp_path` (isolated per test).
2. Sets `AILA_DATABASE_URL` to point to the test DB.
3. Clears the Settings `lru_cache` to pick up the new DB URL.
4. Imports vulnerability module tables so `SQLModel.metadata` knows them.
5. Creates a fresh SQLAlchemy engine and calls `create_all()`.
6. Overrides the global `_ENGINES` and `_INITIALIZED_URLS` caches.
7. Restores everything after the test.

**Scope:** `function` -- every test gets a clean database.

```python
@pytest.fixture(scope="function")
def test_db(tmp_path) -> Generator[None, None, None]:
    ...
    yield
    # Cleanup: restore engines, env vars, settings cache
```

**Why `function` scope:** SQLModel metadata collisions occur if tests share engines. Each test must get its own isolated database to prevent state leaks.

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
# Run all tests
pytest tests/

# Run API tests only
pytest tests/api/

# Run with verbose output
pytest tests/ -v

# Run a specific test file
pytest tests/api/test_auth.py

# Run a specific test function
pytest tests/api/test_auth.py::test_token_issuance

# Run with coverage
pytest tests/ --cov=src/aila/api --cov-report=term-missing

# Run async tests only
pytest tests/ -m asyncio
```

## Coverage Target

Minimum 80% on `src/aila/api/`. Check coverage:

```bash
pytest tests/ --cov=src/aila/api --cov-report=term-missing
```

Focus coverage on:
- Every endpoint returns expected status codes for valid and invalid inputs.
- Every RBAC role combination is tested.
- Every error path returns the correct ErrorResponse shape.
- Schema validation rejects invalid input (extra fields, wrong types, missing required).

---

## Common Testing Mistakes

1. **Using TestClient instead of AsyncClient** -- TestClient deadlocks on SSE and async routes.
2. **Sharing engines across tests** -- SQLModel metadata collisions cause phantom failures.
3. **Forgetting `test_db` dependency** -- Database operations fail with "no such table".
4. **Patching at definition site** -- Patches must target the import site in the module under test.
5. **Missing `pytest.mark.asyncio`** -- Async tests silently pass without executing.
6. **Asserting response body before status code** -- Status code assertion gives a clearer failure message.
