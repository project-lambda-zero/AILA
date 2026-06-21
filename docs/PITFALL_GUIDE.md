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

---

## 21. Bare `except Exception` Without Justification

**Source:** `.claude/CLAUDE.md` mistake #2; honesty audit rules `bare_exception_wrap`, `silent_exception`, `broad_exception_catch`.

**Symptom:** The honesty audit fails with `broad_exception_catch` or `silent_exception`. Real failures get swallowed; debugging is impossible.

**Mistake:**

```python
try:
    advisory = client.fetch(cve_id)
except Exception:
    advisory = None
```

**Fix:** Catch the exception types you actually expect. For infra paths, group them explicitly:

```python
try:
    advisory = client.fetch(cve_id)
except (OSError, TimeoutError, RuntimeError, httpx.HTTPError):
    _log.exception("advisory fetch failed for %s", cve_id)
    advisory = None
```

If a broad catch is genuinely required (top-level worker loop, callback boundary), leave a comment explaining why and re-raise or `_log.exception(...)` before swallowing.

---

## 22. CSS Variables Inside SVG `fill` / `stroke`

**Source:** `.claude/CLAUDE.md` mistake #4 (frontend).

**Symptom:** Recharts series render with no color, or fall back to the SVG default black/grey. Theme switches do not update the chart.

**Mistake:**

```tsx
<Bar dataKey="count" fill="var(--color-accent)" />  // SVG ignores the var() reference
```

**Fix:** Resolve the variable with `getComputedStyle` via the `useThemeChartColors()` hook and pass the resolved value:

```tsx
const colors = useThemeChartColors();
<Bar dataKey="count" fill={colors.accent} />
```

The hook reads computed values from the document root, so it tracks `data-theme` changes correctly.

---

## 23. Tailwind v4 Arbitrary Values With `h-[…]`, `bg-[#…]`

**Source:** `.claude/CLAUDE.md` mistake #5 (frontend).

**Symptom:** `class="h-[720px] bg-[#131313]"` renders with the default height/background; Tailwind v4 silently emits no CSS for these.

**Mistake:**

```tsx
<div className="h-[720px] bg-[#131313]" />
```

**Fix:** Use an inline `style` for one-off literal values, or add a token:

```tsx
<div className="bg-surface" style={{ height: 720 }} />
```

Arbitrary values that should be reused belong in the design system, not inline.

---

## 24. Schema Changes Without Alembic

**Source:** `.claude/CLAUDE.md` mistake #6.

**Symptom:** Tables created at runtime by `SQLModel.metadata.create_all()` from a tool or service. Production DB drifts from the migration head; rollbacks corrupt state.

**Mistake:**

```python
# In some_service.py
SQLModel.metadata.create_all(engine)
```

**Fix:** All DDL lives in `src/aila/alembic/versions/`. Write a migration:

```bash
alembic revision -m "063_my_module_tables"
alembic upgrade head
```

Runtime `create_all()` is allowed only inside test fixtures that build a throwaway engine.

---

## 25. Worker Bytecode Cache Staleness

**Source:** `.claude/CLAUDE.md` mistake #8.

**Symptom:** ARQ workers run old logic after a Python file edit. Tracebacks point at line numbers that no longer exist. The change works in the API but not the worker.

**Mistake:** Assuming `--reload` semantics from `uvicorn` apply to the worker.

**Fix:** Workers do not auto-reload. After Python file changes:

```bash
# Kill and restart the queue worker
python -m aila worker -q vulnerability
```

If a traceback references stale line numbers, clear `__pycache__` directories under the touched modules and restart.

---

## 26. Pydantic Models Passed As Task Kwargs

**Source:** `.claude/CLAUDE.md` mistake #9.

**Symptom:** `TypeError: Object of type RunState is not JSON serializable` raised when a `@platform_task` function is enqueued or `DurableStateMachine.execute()` runs.

**Mistake:**

```python
await task_queue.submit(track="vr", fn=run_step, kwargs={"state": run_state})
```

**Fix:** Every kwarg to a `@platform_task`-decorated function or to `DurableStateMachine.execute()` MUST be JSON-serializable. Convert `BaseModel` instances:

```python
await task_queue.submit(
    track="vr",
    fn=run_step,
    kwargs={"state": run_state.model_dump(mode="json")},
)
```

The workflow engine validates kwargs at runtime and raises `TypeError` if a non-serializable value reaches the boundary.

---

## 27. `session.add()` on a Possibly-Existing Row

**Source:** `.claude/CLAUDE.md` mistake #10.

**Symptom:** `IntegrityError` for a duplicate primary key when a row created by an earlier helper (e.g. `_ensure_run_record`) is `add()`-ed again later in the same flow.

**Mistake:**

```python
record = WorkflowRunRecord(id=run_id, ...)
session.add(record)   # always INSERT
await session.commit()
```

**Fix:** When the row may already exist (created earlier by another helper, by `_ensure_run_record`, or by a sibling worker), use `session.merge()`:

```python
record = WorkflowRunRecord(id=run_id, ...)
merged = await session.merge(record)   # INSERT or UPDATE on PK
await session.commit()
```

`add()` always issues an INSERT; `merge()` issues INSERT-or-UPDATE based on the primary key.

---

## 28. Module Frontend Bare Import Not Declared in `package.json`

**Source:** `.claude/CLAUDE.md` mistake #11.

**Symptom:** `pnpm install` fails with "missing peer dependencies" or "ERR_PNPM_UNDECLARED_DEPENDENCY". `tsc --noEmit` flags an unresolved import.

**Mistake:** Adding `import { Foo } from "some-pkg"` inside a module frontend file without listing `some-pkg` in that module's `package.json`.

**Fix:** pnpm strict mode rejects undeclared imports at install time. Decide which section the import belongs to (per the dep ownership matrix in `FRONTEND_MODULE_STANDARD.md`) and declare it:

```json
{
  "dependencies": {
    "some-pkg": "catalog:ui"
  }
}
```

Then `pnpm install` to relink.

---

## 29. Importing `react-router-dom`

**Source:** `.claude/CLAUDE.md` mistake #12.

**Symptom:** Module type-check fails with "Cannot find module 'react-router-dom'", or runtime fails because the package isn't installed.

**Mistake:**

```ts
import { useNavigate } from "react-router-dom";
```

**Fix:** React Router v7 unified `react-router-dom` and `react-router` into the single `react-router` package. Every import in this codebase comes from `react-router`:

```ts
import { useNavigate } from "react-router";
```

---

## 30. Literal Versions in Module `package.json`

**Source:** `.claude/CLAUDE.md` mistake #13.

**Symptom:** Two modules pin different versions of the same dep; pnpm hoists both; bundle doubles in size; runtime type mismatches when two `react` copies meet.

**Mistake:**

```json
{ "peerDependencies": { "react": "19.2.4" } }
```

**Fix:** Every shared dep references a pnpm catalog entry from `pnpm-workspace.yaml`:

```json
{ "peerDependencies": { "react": "catalog:react19" } }
```

Only a dep that no other workspace package consumes is allowed a literal version, and even then prefer adding it to a catalog so a future second consumer cannot drift.

---

## 31. Hand-Editing `pnpm-lock.yaml`

**Source:** `.claude/CLAUDE.md` mistake #14.

**Symptom:** `pnpm install` rewrites the file on the next run, undoing the edit. CI fails the lockfile-is-up-to-date check. Reproducible builds break.

**Mistake:** Patching a version or `integrity:` hash directly in `pnpm-lock.yaml`.

**Fix:** Treat the lockfile as generated output. Re-run `pnpm install` after any change to a `package.json` or to `pnpm-workspace.yaml`. The lockfile is regenerated deterministically from those inputs.

---

## 32. Missing `@source` Directive for a New Module's Tailwind Classes

**Source:** `.claude/CLAUDE.md` mistake #15 (frontend).

**Symptom:** Tailwind classes used only inside a module's frontend (e.g. `bottom-6 right-6 z-[60]` on a floating pill) generate no CSS rules. The element renders with no `bottom`/`right` set and anchors at flow position instead of viewport.

**Cause:** Tailwind v4 scans content starting from the directory containing the entry CSS file (`frontend/src/styles/globals.css` → `frontend/src/`). Module frontends live at `src/aila/modules/<id>/frontend/`, reached only via pnpm symlinks under `node_modules/@aila/*` that Tailwind ignores by default.

**Fix:** Add one `@source` line per module to `frontend/src/styles/globals.css`, right after the Tailwind import:

```css
@import "tailwindcss";
@source "../../../src/aila/modules/<your_module>/frontend/**/*.{ts,tsx}";
```

Already wired for: `vr`, `vulnerability`, `forensics`, `hello_world`. When you copy `_template/` to start a new module, add the `@source` line in the same change.

Verify with a curl against the dev server:

```bash
curl -s http://localhost:3000/src/styles/globals.css | grep "\.your-new-class"
```

If the rule is present, Tailwind is scanning the module correctly.

---

## 33. Auto-Steering Messages Look Identical to Operator Messages

**Source:** `src/aila/modules/vr/agents/auto_steering.py`.

**Symptom:** An investigation receives what appears to be an operator chat post correcting a tool result, but no human typed it. The auto-steering subsystem posts corrective notices into the investigation message stream after tool dispatch when a result matches a known dead-end pattern (`read_lines` past EOF, `read_function` returning file-header garbage, hallucinated `index_id`, etc.). These messages take the same DB shape as a real operator chat post and land at PROMPT POSITION 2 on every branch's next turn under a banner that reads `*** OPERATOR STEERING -- MANDATORY OVERRIDE ***`.

- **De-dupe key:** `(rule, target_file, target_symbol)` written to the indexed `auto_steering_key` column (migration 063). A recurring condition can re-fire once all prior matching posts are ACKed via the agent's `observables._acked_operator_messages` list.
- **Failure mode:** if `maybe_post_auto_steering()` raises, the underlying tool result is still returned to the agent -- only the steering is lost.
- **Adding a new rule:** implement `_detect_<X>` + `_derive_<X>_correction` in `auto_steering.py` and branch in `maybe_post_auto_steering`. NEVER filter by message content scanning; the dedup column is authoritative.
