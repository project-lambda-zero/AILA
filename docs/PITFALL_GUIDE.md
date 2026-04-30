# AILA Pitfall Guide

The top 20 mistakes discovered during the v1.5/v1.6/v1.7 deep review. Each pitfall was found in production code, fixed, and tested. Learn from them.

---

## 1. Sync session_scope() in async def

**Phase:** 99 (XCUT-10)

**Symptom:** Event loop blocks, other coroutines stall, apparent deadlock under load.

**Mistake:**

```python
async def get_findings(system_id: int):
    with session_scope() as session:  # BLOCKS the event loop
        return session.exec(select(Finding)).all()
```

**Fix:** Wrap in a sync helper and use `asyncio.to_thread()`:

```python
async def get_findings(system_id: int):
    def _query():
        with session_scope() as session:
            return session.exec(select(Finding)).all()
    return await asyncio.to_thread(_query)
```

**Enforcement:** Honesty audit rule `sync_in_async` catches this at CI time.

---

## 2. Redundant Depends() at Endpoint Level

**Phases:** 65, 66, 70, 72

**Symptom:** Double authentication check (harmless but misleading). Code suggests the endpoint has special auth requirements when it does not.

**Mistake:**

```python
router = APIRouter(dependencies=[Depends(require_api_key)])

@router.get("/items", dependencies=[Depends(require_api_key)])  # redundant
async def list_items(): ...
```

**Fix:** Remove endpoint-level `Depends` when the router already applies it:

```python
router = APIRouter(dependencies=[Depends(require_api_key)])

@router.get("/items")  # router-level dependency covers this
async def list_items(): ...
```

---

## 3. TestClient Deadlocks on SSE

**Phase:** conftest.py design decision

**Symptom:** Tests hang indefinitely when hitting SSE endpoints. No timeout, no error.

**Mistake:**

```python
from starlette.testclient import TestClient
client = TestClient(app)
response = client.get("/scans/run-001/progress")  # hangs forever
```

**Fix:** Use `httpx.AsyncClient` with `ASGITransport`:

```python
from httpx import ASGITransport, AsyncClient
async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
    response = await client.get("/scans/run-001/progress")
```

---

## 4. SQLModel Metadata Collision

**Phase:** conftest.py design decision

**Symptom:** Test A creates table X, test B also creates table X but gets the schema from test A's engine. Phantom failures, wrong data, or "table already exists" errors.

**Mistake:** Sharing a single engine across tests or using module-scoped fixtures for the database.

**Fix:** Use `function`-scoped `test_db` fixture. Each test gets a fresh engine with its own `_ENGINES` and `_INITIALIZED_URLS` snapshot:

```python
@pytest.fixture(scope="function")
def test_db(tmp_path):
    # Create fresh engine, override global caches, restore after test
    ...
```

---

## 5. module_id Does Not Match Folder Name

**Phase:** MODULE_STANDARD.md rule

**Symptom:** Platform module loader rejects the module at boot with a descriptive error.

**Mistake:**

```python
# Folder: src/aila/modules/vulnerability/
module_id = "vuln"  # WRONG
```

**Fix:** `module_id` must match the folder name exactly:

```python
MODULE_ID = Path(__file__).parent.name  # "vulnerability"
```

---

## 6. Prefix Duplication in Router Paths

**Phase:** MODULE_STANDARD.md rule

**Symptom:** Routes 404 because the platform mounts at `/vulnerability` and the router defines `/vulnerability/findings`, producing `/vulnerability/vulnerability/findings`.

**Mistake:**

```python
@router.get("/vulnerability/findings")
async def list_findings(): ...
```

**Fix:** Router paths are relative to the mount prefix:

```python
@router.get("/findings")
async def list_findings(): ...
```

---

## 7. Non-Tuple tool_keys in ModuleRouteSpec

**Phase:** MODULE_STANDARD.md rule

**Symptom:** `TypeError` at construction because `ModuleRouteSpec` is a frozen dataclass.

**Mistake:**

```python
ModuleRouteSpec(prefix="/x", router_factory=f, tool_keys=["a", "b"])
```

**Fix:** Use `tuple()`:

```python
ModuleRouteSpec(prefix="/x", router_factory=f, tool_keys=("a", "b"))
```

---

## 8. Top-Level Import in route_specs()

**Phase:** MODULE_STANDARD.md rule

**Symptom:** Importing the API router at the top of `module.py` pulls in FastAPI and all route dependencies at discovery time, slowing boot.

**Mistake:**

```python
from my_module.api_router import create_my_router  # top-level

class MyModule:
    def route_specs(self):
        return [ModuleRouteSpec(prefix="/x", router_factory=create_my_router)]
```

**Fix:** Deferred import inside `route_specs()`:

```python
class MyModule:
    def route_specs(self):
        from my_module.api_router import create_my_router  # deferred
        return [ModuleRouteSpec(prefix="/x", router_factory=create_my_router)]
```

---

## 9. Creating a New Session in seed_data()

**Phase:** MODULE_STANDARD.md rule

**Symptom:** Locked DB or missing writes. The second session's commits are invisible to the caller's transaction.

**Mistake:**

```python
def seed_data(self, session):
    with session_scope() as new_session:  # WRONG: second connection
        new_session.add(MyRecord(...))
        new_session.commit()
```

**Fix:** Use the provided session:

```python
def seed_data(self, session):
    session.add(MyRecord(...))
    session.commit()
```

---

## 10. Table Not Registered in SchemaRegistry

**Phase:** MODULE_STANDARD.md rule

**Symptom:** `sqlalchemy.exc.OperationalError: no such table: my_record` at runtime.

**Mistake:** Forgetting `schema_registry.push(MyRecord)` in `register_tools()`.

**Fix:**

```python
def register_tools(self, tool_registry, settings, registry=None, schema_registry=None):
    if schema_registry is not None:
        schema_registry.push(MyRecord)
    ...
```

---

## 11. Cross-Module Imports

**Phase:** 99 (XCUT-11)

**Symptom:** Honesty audit fails with `import_boundary` violation.

**Mistake:**

```python
# In aila/modules/network_scan/service.py
from aila.modules.vulnerability.db_models import LatestFindingRecord
```

**Fix:** Use platform contracts or services for cross-module data.

**Enforcement:** Honesty audit rules `import_boundary` and `api_imports_module_internals`.

---

## 12. Missing __all__

**Phase:** CLAUDE.md rule, Golden Rule 16

**Symptom:** Public API surface is ambiguous. `from module import *` pulls in everything including internal helpers.

**Mistake:**

```python
# public module with no __all__
def my_function(): ...
def _internal_helper(): ...
```

**Fix:**

```python
__all__ = ["my_function"]

def my_function(): ...
def _internal_helper(): ...
```

---

## 13. HTTPException Inside asyncio.to_thread

**Phase:** 72

**Symptom:** FastAPI cannot catch HTTPException raised in a thread. The exception propagates as an unhandled error (500).

**Mistake:**

```python
async def invoke_tool(key: str):
    def _run():
        tool = registry.get(key)
        if tool is None:
            raise HTTPException(status_code=404, detail="Tool not found")
        return tool.execute()
    return await asyncio.to_thread(_run)
```

**Fix:** Move HTTPException to the router boundary:

```python
async def invoke_tool(key: str):
    def _run():
        tool = registry.get(key)
        if tool is None:
            return None
        return tool.execute()
    result = await asyncio.to_thread(_run)
    if result is None:
        raise HTTPException(status_code=404, detail="Tool not found")
    return result
```

---

## 14. os.getenv for Configurable Values

**Phase:** 64

**Symptom:** Configuration scattered across environment variables instead of centralized in ConfigRegistry.

**Mistake:**

```python
jwt_expiry = int(os.getenv("JWT_EXPIRY_SECONDS", "3600"))
```

**Fix:** Use `get_task_tuning()` or ConfigRegistry:

```python
from aila.tasks.constants import get_task_tuning
jwt_expiry = get_task_tuning("jwt_expiry_seconds")
```

---

## 15. Empty Results: pages=1 Instead of pages=0

**Phase:** 65

**Symptom:** API returns `pages: 1` for empty result sets, misleading clients into thinking there is one page of data.

**Mistake:**

```python
pages = 1  # always at least 1 page
```

**Fix:**

```python
pages = 1 if items else 0
```

---

## 16. ValueError Not Caught at Router Boundary

**Phase:** 66

**Symptom:** `ValueError` from a service method propagates as 500 instead of 422.

**Mistake:**

```python
@router.put("/config/{namespace}")
async def update_config(namespace: str, body: ConfigUpdate):
    registry.set(namespace, body.key, body.value)  # raises ValueError on invalid input
```

**Fix:** Catch ValueError and convert to 422:

```python
@router.put("/config/{namespace}")
async def update_config(namespace: str, body: ConfigUpdate):
    try:
        registry.set(namespace, body.key, body.value)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
```

---

## 17. SEED_VERSION Type Mismatch

**Phase:** 92

**Symptom:** `seed_data()` never recognizes the existing seed version because `1 != "1"` (int vs str comparison). Module re-seeds on every startup.

**Mistake:**

```python
SEED_VERSION = 1  # int
```

**Fix:** `SeedVersionRecord.seed_version` is a string column:

```python
SEED_VERSION = "1"  # str
```

---

## 18. Missing session.refresh() After Commit

**Phase:** 102

**Symptom:** `sqlalchemy.orm.exc.DetachedInstanceError` when accessing record attributes after commit.

**Mistake:**

```python
session.add(record)
session.commit()
# record is now detached -- accessing record.id raises DetachedInstanceError
return record.id
```

**Fix:** Refresh the record after commit:

```python
session.add(record)
session.commit()
session.refresh(record)
return record.id
```

---

## 19. Hardcoded None for Score in system_findings

**Phase:** 87

**Symptom:** System findings always show `score: null` even when `LatestFindingRecord` has a real score.

**Mistake:**

```python
return {"score": None, "cve_id": r.cve_id, ...}
```

**Fix:** Use the actual value:

```python
return {"score": r.score, "cve_id": r.cve_id, ...}
```

---

## 20. Not Cleaning Up Orphaned DB Records

**Phase:** 81

**Symptom:** Rejected task submissions leave WAITING records in the database, polluting queries and counts.

**Mistake:**

```python
def submit_task(task):
    record = TaskRecord(status="WAITING", ...)
    session.add(record)
    session.commit()
    if has_cycle(task):
        raise ValueError("Cycle detected")  # orphaned WAITING record left behind
```

**Fix:** Clean up the record on rejection:

```python
def submit_task(task):
    record = TaskRecord(status="WAITING", ...)
    session.add(record)
    session.commit()
    if has_cycle(task):
        session.delete(record)
        session.commit()
        raise ValueError("Cycle detected")
```
