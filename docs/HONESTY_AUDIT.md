# Honesty Audit: AST Rule Reference

The honesty audit is an AST-based structural checker that enforces code honesty across the AILA codebase. It runs as a pre-commit CI gate:

```bash
python -m aila.tools.honesty_audit src/
python -m aila.tools.honesty_audit src/ --whitelist honesty_whitelist.py
```

Exit code 0 means clean. Exit code 1 means findings exist. Exit code 2 means usage error.

All analysis is AST-only -- no runtime inspection, no imports executed. Safe to run on any Python file regardless of dependencies.

---

## Whitelist

Suppress known acceptable violations with a whitelist file. Define `HONESTY_WHITELIST` as a list of 3-element string tuples:

```python
# honesty_whitelist.py
HONESTY_WHITELIST = [
    ("module.py", "my_function", "unused parameter 'settings'"),
]
```

Each tuple is `(filename_suffix, function_name, detail)`. A finding is suppressed only when all three fields match.

---

## Rules (17 total)

### 1. unused_parameter

**Detects:** Function parameter accepted but never referenced in the function body.

**Why it matters:** An unused parameter signals either dead code, a broken refactor, or a misleading signature. Callers prepare values that are silently discarded.

**Excluded:** `self`, `cls`, `_`, `_`-prefixed params, `*args`, `**kwargs`, stub bodies (`...`), `@abstractmethod`, `@overload`, Protocol class methods.

**Violation:**

```python
def process_data(records, logger):
    # logger is never used
    return [r.name for r in records]
```

**Correct:**

```python
def process_data(records):
    return [r.name for r in records]
```

---

### 2. misleading_name

**Detects:** Function name implies intelligent logic (contains "planner", "manager", "helper", "coordinator", "processor", "handler") but body only forwards a single call.

**Why it matters:** Names create expectations. A "manager" that only calls `self.delegate.run()` misleads readers into thinking the function adds value.

**Violation:**

```python
def manage_workflow(self, data):
    return self.delegate.run(data)
```

**Correct:**

```python
# Either: inline at call sites, or rename to reflect what it actually does
def run(self, data):
    return self.delegate.run(data)
```

---

### 3. docstring_mismatch

**Detects:** Docstring claims caching or persistence ("caches the", "memoizes", "persists the result") but the function body contains no caching implementation.

**Why it matters:** A docstring that promises caching when no cache exists is a lie. Callers may rely on caching behavior that does not exist.

**Violation:**

```python
def get_advisory(cve_id: str) -> dict:
    """Caches the advisory response for reuse."""
    return requests.get(f"/api/{cve_id}").json()
```

**Correct:**

```python
@functools.lru_cache(maxsize=128)
def get_advisory(cve_id: str) -> dict:
    """Caches the advisory response for reuse."""
    return requests.get(f"/api/{cve_id}").json()
```

---

### 4. import_boundary

**Detects:** A module under `aila/modules/{module_id}/` imports from a different module's package `aila.modules.{other_id}`.

**Why it matters:** Cross-module imports create hidden coupling. Modules must communicate through platform contracts and services, not by reaching into each other's internals.

**Violation:**

```python
# In aila/modules/network_scan/module.py
from aila.modules.vulnerability.db_models import LatestFindingRecord
```

**Correct:**

```python
# Use platform contracts for cross-module data
from aila.platform.contracts import SharedContract
```

---

### 5. dead_isinstance

**Detects:** `isinstance()` check on a parameter that already has a type annotation matching a builtin type (str, int, float, bool, dict, list, tuple, set, bytes).

**Why it matters:** If the type annotation says `name: str`, then `isinstance(name, str)` is always True. It is dead code that adds noise.

**Violation:**

```python
def format_label(name: str) -> str:
    if isinstance(name, str):  # always True
        return name.upper()
    return str(name)
```

**Correct:**

```python
def format_label(name: str) -> str:
    return name.upper()
```

---

### 6. redundant_conversion

**Detects:** Converting a value to the type it already is based on its annotation: `str(already_str)`, `int(already_int)`, `float(already_float)`, `bool(already_bool)`, `Path(already_path)`.

**Why it matters:** Redundant conversions obscure intent and waste cycles. The annotation already guarantees the type.

**Note:** This rule is defined in the keyword sets but not currently wired as a separate visitor check. It is tracked for completeness.

---

### 7. private_in_all

**Detects:** An underscore-prefixed name exported in `__all__`.

**Why it matters:** `__all__` declares the public API surface. An underscore prefix signals "private". Exporting `_internal_helper` in `__all__` contradicts the naming convention.

**Violation:**

```python
__all__ = ["MyService", "_internal_helper"]
```

**Correct:**

```python
__all__ = ["MyService"]
# _internal_helper is still importable by explicit name
```

---

### 8. bare_exception_wrap

**Detects:** `except Exception` handler that catches typed errors and raises `RuntimeError`, destroying the original exception type.

**Why it matters:** Callers catching specific exceptions (ValueError, KeyError) will miss them when they are wrapped in RuntimeError. Original exception type information is lost.

**Violation:**

```python
try:
    config.validate()
except Exception as e:
    raise RuntimeError(f"Config failed: {e}")
```

**Correct:**

```python
try:
    config.validate()
except Exception:
    raise  # preserve original type
# Or catch specific types
except ValueError as e:
    raise ConfigValidationError(str(e)) from e
```

---

### 9. always_true_default

**Detects:** Parameter with `Optional`/`None` default that is always overridden by every caller.

**Why it matters:** If every call site provides the value, the default is a lie. Remove the default and make the parameter required, or remove the parameter if callers all pass the same value.

**Note:** This rule is defined in the docstring but relies on cross-file analysis. It is tracked for completeness and may be implemented as a separate pass.

---

### 10. god_object_dispatch

**Detects:** A single function with 7+ `if/elif` branches dispatching on a string action parameter (named `action`, `operation`, `command`, or `mode`).

**Why it matters:** A function with many dispatch branches is a god object in disguise. Each branch is an independent concern that should be a separate tool or handler.

**Threshold:** 7+ branches (CRUD tools with 3-5 branches are acceptable).

**Violation:**

```python
def execute(self, action: str, data: dict):
    if action == "scan":
        return self._scan(data)
    elif action == "report":
        return self._report(data)
    elif action == "notify":
        return self._notify(data)
    elif action == "archive":
        return self._archive(data)
    elif action == "export":
        return self._export(data)
    elif action == "validate":
        return self._validate(data)
    elif action == "transform":
        return self._transform(data)
```

**Correct:**

```python
# Split into separate single-concern tools
class ScanTool:
    def execute(self, data: dict): ...

class ReportTool:
    def execute(self, data: dict): ...
```

---

### 11. todo_in_code

**Detects:** `TODO`, `FIXME`, `HACK`, or `XXX` comment markers in production source.

**Why it matters:** A TODO is a promise embedded in code that nobody tracks. Either do the work or file an issue and delete the comment. (Golden Rule 9: "No TODO in committed code.")

**Violation:**

```python
def get_results():
    # TODO: add pagination support
    return db.query(Result).all()
```

**Correct:**

```python
def get_results():
    # Tracked in issue #42
    return db.query(Result).all()
```

Or simply implement the feature.

---

### 12. silent_exception

**Detects:** `except Exception` with `pass` or a bare default assignment (`x = {}`, `x = []`, `x = None`) and no logging or re-raise.

**Why it matters:** Silently swallowing exceptions hides bugs. Errors become invisible, making debugging impossible. (Golden Rule 5: "Error paths are first-class citizens.")

**Excluded:** `__del__` methods (silent cleanup is standard there). Handlers that reference logging identifiers or contain a `raise` statement.

**Violation:**

```python
try:
    data = parse_response(raw)
except Exception:
    data = {}
```

**Correct:**

```python
try:
    data = parse_response(raw)
except Exception:
    logger.exception("Failed to parse response")
    data = {}
```

---

### 13. production_assert

**Detects:** `assert` statements in production code (non-test files).

**Why it matters:** `assert` is stripped when Python runs with `-O`. Production invariants that use `assert` silently disappear, turning safety checks into no-ops. (Golden Rule 20: "assert is for tests, not production.")

**Violation:**

```python
def withdraw(account, amount):
    assert amount > 0  # stripped under python -O
    account.balance -= amount
```

**Correct:**

```python
def withdraw(account, amount):
    if amount <= 0:
        raise ValueError("Withdrawal amount must be positive")
    account.balance -= amount
```

---

### 14. do_nothing_wrapper

**Detects:** Function body is a single `return another_function(args)` with no added validation, transformation, or error handling.

**Why it matters:** A wrapper that only forwards a call adds indirection without value. Inline the call at call sites for clarity. (Golden Rule 1: "No abstraction without justification.")

**Excluded:** Dunder methods, framework contracts (`forward`, `handle`, `run`, `_execute`), private helpers (`_` prefix), named accessors (`get_*`, `create_*`, `build_*`, `to_*`, `from_*`, `is_*`, `has_*`), property-style collection accessors.

**Violation:**

```python
def fetch_records(db):
    return db.query(Record).all()
```

**Correct:**

```python
# Inline at call sites:
records = db.query(Record).all()
```

---

### 15. dead_config_field

**Detects:** Pydantic or config field declared but never read anywhere in the codebase.

**Why it matters:** Dead fields add noise to configuration and schemas. They mislead developers into thinking the field is used somewhere.

**Note:** This rule is defined in the docstring but relies on cross-file analysis. It is tracked for completeness.

---

### 16. sync_in_async

**Detects:** `session_scope()` called directly inside an `async def` body (not inside a nested sync def that could be passed to `asyncio.to_thread()`).

**Why it matters:** `session_scope()` is synchronous. Calling it directly in an async function blocks the event loop, preventing other coroutines from running. The correct pattern wraps the sync call in `asyncio.to_thread()`.

**Implementation detail:** The checker builds line ranges for nested sync defs inside the async function. `session_scope()` calls inside those ranges are allowed (they run via `asyncio.to_thread`). Only calls at the async function body level are flagged.

**Violation:**

```python
async def get_findings(system_id: int):
    with session_scope() as session:  # blocks the event loop
        return session.exec(select(Finding).where(...)).all()
```

**Correct:**

```python
async def get_findings(system_id: int):
    def _query():
        with session_scope() as session:
            return session.exec(select(Finding).where(...)).all()

    return await asyncio.to_thread(_query)
```

---

### 17. api_imports_module_internals

**Detects:** Files under `aila/api/` importing from `aila.modules.*` directly.

**Why it matters:** The API layer must access module functionality through the `ModuleProtocol` interface, not by importing module internals. Direct imports create tight coupling between the API layer and specific module implementations.

**Scoping:** Only files whose path contains `aila/api/` are checked.

**Violation:**

```python
# In aila/api/routers/findings.py
from aila.modules.vulnerability.db_models import LatestFindingRecord
```

**Correct:**

```python
# Access module data through the platform protocol
from aila.platform.modules import ModuleProtocol
# Module data is accessed via module.system_summary(), module.report_count(), etc.
```

---

---

### 18. asyncio_thread_on_async

**Detects:** `asyncio.to_thread(fn, ...)` where `fn` is itself an `async def` (coroutine function).

**Why it matters:** `asyncio.to_thread` runs a **sync** callable in a thread-pool executor. Passing an `async def` to it creates a coroutine object that is never awaited — the function body never executes. This is a silent no-op bug.

**Common trigger:** Confusing `submit()` (async, returns awaitable handle) with a sync queue-put call.

**Violation:**

```python
# TaskQueue.submit is async def — this wraps a coroutine, never runs it
result = await asyncio.to_thread(task_queue.submit, track="forensics", fn=..., kwargs={...})
```

**Correct:**

```python
# submit is async — await it directly
handle = await task_queue.submit(track="forensics", fn=..., kwargs={...})
```

---

### 19. sse_missing_no_redis_guard

**Detects:** An SSE streaming endpoint (`StreamingResponse` + `text/event-stream`) that does NOT check `pool_available()` before opening the Redis stream.

**Why it matters:** If Redis is down and the endpoint proceeds, the client hangs indefinitely on the first `XREAD` call. Every SSE endpoint MUST short-circuit with a single informational event when Redis is unavailable.

**Required pattern:**

```python
if not pool_available():
    async def _no_redis():
        yield f"data: {json.dumps({'message': 'Redis not configured'})}\n\n"
    return StreamingResponse(_no_redis(), media_type="text/event-stream", ...)
```

---

### 20. sse_missing_done_sentinel

**Detects:** An SSE streaming endpoint that never emits `event: done` when the backing resource reaches a terminal state.

**Why it matters:** Without a `done` event the frontend never knows the stream has ended. It keeps the connection open and the user sees "connecting" forever after the task completes.

**Required pattern:** On every `ping` (keepalive), check DB status. On terminal, emit and return:

```python
if status in _TERMINAL_STATUSES:
    yield f"event: done\ndata: {json.dumps({'status': status})}\n\n"
    return
```

---

### 21. sse_eventfeed_hook_missing_abort

**Detects (frontend):** A React hook that opens a streaming fetch (SSE) without an `AbortController` cleanup in the `useEffect` return.

**Why it matters:** Without abort cleanup, the stream continues after the component unmounts. This leaks network connections and causes React state-update-after-unmount warnings.

**Required pattern:**

```typescript
useEffect(() => {
  const controller = new AbortController();
  // ... open stream with controller.signal
  return () => { controller.abort(); };
}, [resourceId]);
```

---

## Running the Audit

```bash
# Audit the entire source tree
python -m aila.tools.honesty_audit src/

# Audit with whitelist
python -m aila.tools.honesty_audit src/ --whitelist honesty_whitelist.py

# Audit a single file
python -m aila.tools.honesty_audit src/aila/modules/vulnerability/module.py
```

## Adding a Whitelist Entry

When a finding is a known acceptable violation (framework requirement, deliberate pattern), add it to `honesty_whitelist.py`:

```python
HONESTY_WHITELIST = [
    # (filename_suffix, function_name, detail_substring)
    ("module.py", "register_tools", "unused parameter 'registry'"),
    ("orchestrator.py", "run", "do_nothing_wrapper"),
]
```

All three fields must match for suppression. This prevents accidentally suppressing findings in other files with the same function name.
