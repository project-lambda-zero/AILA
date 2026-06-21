# Module Authoring Tutorial

Build a new AILA module from scratch. Every code sample in this tutorial is copied from the working `hello_world` module -- if it compiles there, it compiles here.

For the full contract specification, see [MODULE_STANDARD.md](MODULE_STANDARD.md).
For the working reference implementation, see `src/aila/modules/hello_world/`.

---

## Step 1: Scaffold from the template

```bash
cp -r src/aila/modules/_template src/aila/modules/my_module
```

This gives you:

```
my_module/
  __init__.py
  module.py          # ModuleProtocol implementation
  runtime.py         # Request handler
  capabilities.py    # Description, tools, examples for LLM routing
  tool_keys.py       # Tool key constants
  workflow.py        # State machine
  contracts/
    __init__.py
  tools/
    __init__.py
  services/
    __init__.py
  reporting/
    __init__.py
```

The `_template/README.md` lists every placeholder to rename.

---

## Step 2: Define your module identity

Edit `module.py`. The module ID is a class attribute (not a property), and must match the directory name:

```python
from __future__ import annotations

from pathlib import Path
from typing import Any

from aila.platform.modules import (
    ModuleCapabilityProfile,
    ModuleContext,
    ModuleProtocol,
    ModuleRouteSpec,
    ModuleRuntime,
    action_id_for,
)
from aila.platform.runtime import ToolRegistry

from .capabilities import MODULE_DESCRIPTION, MODULE_EXAMPLES, MODULE_TOOLS
from .runtime import MyModuleRuntime
from .tool_keys import MY_MODULE_SCAN_TOOL
from .tools import MyModuleScanTool

MODULE_ID = Path(__file__).parent.name          # "my_module"
MODULE_ACTION_ID = action_id_for(MODULE_ID, "run")
SEED_VERSION = "1"


class MyModule(ModuleProtocol):
    """My module implementing ModuleProtocol."""

    module_id = MODULE_ID
    action_id = MODULE_ACTION_ID

    def capability_profiles(self) -> list[ModuleCapabilityProfile]:
        return [
            ModuleCapabilityProfile(
                module_id=self.module_id,
                action_id=self.action_id,
                description=MODULE_DESCRIPTION,
                tools=list(MODULE_TOOLS),
                examples=list(MODULE_EXAMPLES),
            )
        ]

    def required_tools(self) -> list[str]:
        return [MY_MODULE_SCAN_TOOL]

    async def register_tools(
        self, tool_registry: ToolRegistry, settings, registry=None, schema_registry=None
    ) -> None:
        tool_registry.register(MY_MODULE_SCAN_TOOL, MyModuleScanTool(settings))

    def build_runtime(self, context: ModuleContext) -> ModuleRuntime:
        return MyModuleRuntime(
            module_id=self.module_id,
            action_id=self.action_id,
            capability_profiles=self.capability_profiles(),
        )


def create_module() -> ModuleProtocol:
    return MyModule()
```

Key points:
- `module_id` is a **class attribute**, not a `@property`.
- `MODULE_ID = Path(__file__).parent.name` derives it from the directory name automatically.
- `create_module()` is a zero-argument factory function at module level. The platform calls it during discovery.
- `register_tools` is **`async def`** (not `def`).

---

## Step 3: Define capabilities

Edit `capabilities.py`. These three constants are embedded in the LLM routing prompt -- the router reads them to decide whether your module handles a user's query:

```python
from __future__ import annotations

MODULE_DESCRIPTION = "Scan registered systems for security misconfigurations."
MODULE_TOOLS: list[str] = ["my_module.scan"]
MODULE_EXAMPLES: list[str] = [
    "check my servers for misconfigurations",
    "scan the fleet for hardening issues",
]

__all__ = ["MODULE_DESCRIPTION", "MODULE_EXAMPLES", "MODULE_TOOLS"]
```

Write `MODULE_DESCRIPTION` for LLM consumption, not developer docs. The router sees this text and decides routing based on it.

---

## Step 4: Define tool keys

Edit `tool_keys.py`. Tool keys are prefixed with the module ID to prevent collisions:

```python
from __future__ import annotations

MY_MODULE_SCAN_TOOL = "my_module.scan"

__all__ = ["MY_MODULE_SCAN_TOOL"]
```

These constants are referenced in three places: `capabilities.py` (MODULE_TOOLS), `module.py` (required_tools, register_tools), and `tools/` (the implementation).

---

## Step 5: Implement a tool

Edit `tools/__init__.py`:

```python
from __future__ import annotations

from aila.config import Settings, get_settings
from aila.platform.tools._common import Tool

__all__ = ["MyModuleScanTool"]


class MyModuleScanTool(Tool):
    """Scan tool for my_module."""

    name = "my_module_scan"
    description = "Scan a target system for security misconfigurations."
    inputs = {
        "action": {"type": "string", "description": "Must be 'scan'."},
        "target": {"type": "string", "description": "Target system name."},
    }
    output_type = "object"
    skip_forward_signature_validation = True

    _action = "scan"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def forward(self, action: str | None = None, **kwargs) -> dict:
        effective = str(action or self._action).strip().lower()
        if effective != self._action:
            raise ValueError(f"Unsupported action: {action!r}")
        return self._execute(**kwargs)

    def _execute(self, target: str | None = None, **kwargs) -> dict:
        return {"target": target, "status": "scanned", "findings": []}
```

Do not call `init_db()` in `__init__`. The platform startup path handles database initialization.

---

## Step 6: Add HTTP routes (optional)

If your module exposes API endpoints, create `api_router.py`:

```python
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import Field

from aila.api.schemas.common import APIModel
from aila.platform.contracts.auth import AuthContext, require_auth

__all__ = ["MyModuleStatusResponse", "create_my_module_router"]


class MyModuleStatusResponse(APIModel):
    """Response for GET /my_module/status."""
    module: str = Field(description="Module identifier")
    status: str = Field(description="Module status")


def create_my_module_router() -> APIRouter:
    router = APIRouter(tags=["my_module"])

    @router.get("/status", response_model=MyModuleStatusResponse)
    async def module_status(
        _auth: AuthContext = Depends(require_auth),
    ) -> MyModuleStatusResponse:
        return MyModuleStatusResponse(module="my_module", status="ok")

    return router
```

Then wire it in `module.py` with a **deferred import** inside `route_specs()`:

```python
def route_specs(self) -> list[ModuleRouteSpec]:
    from .api_router import create_my_module_router   # deferred -- not at top of file

    return [
        ModuleRouteSpec(
            prefix="/my_module",
            router_factory=create_my_module_router,
            tool_keys=(MY_MODULE_SCAN_TOOL,),
            config_namespace=None,
        ),
    ]
```

`ModuleRouteSpec` fields:
- `prefix` -- URL prefix. The platform mounts your router here.
- `router_factory` -- zero-argument callable returning a FastAPI `APIRouter`.
- `tool_keys` -- tool keys your module exposes (surfaced via `GET /tools`).
- `config_namespace` -- your module's config namespace (or None).

The import **must** be deferred (inside the method, not at the top of `module.py`). Top-level imports create circular dependencies during module discovery. The honesty audit catches this violation.

---

## Step 7: Add `__all__` to every file

Every `__init__.py` and public module must define `__all__`:

```python
# Empty package init
__all__: list[str] = []

# Package that re-exports
from .models import ScanResult, ScanOptions
__all__ = ["ScanResult", "ScanOptions"]
```

Underscore-prefixed private modules (`_helpers.py`) do not define `__all__`.

---

## Step 8: Seed data (optional)

If your module needs initial data (lookup tables, default policies), implement `seed_data()`:

```python
async def seed_data(self, session: Any) -> None:
    from sqlmodel import select
    from aila.storage.db_models import SeedVersionRecord

    existing = (await session.exec(
        select(SeedVersionRecord).where(SeedVersionRecord.module_id == self.module_id)
    )).first()
    if existing is not None and existing.seed_version == SEED_VERSION:
        return

    # Insert your seed data here
    # ...

    if existing is None:
        session.add(SeedVersionRecord(module_id=self.module_id, seed_version=SEED_VERSION))
    else:
        existing.seed_version = SEED_VERSION
    await session.commit()
```

Key points:
- `seed_data` is **`async def`**. The session is an `AsyncSession`.
- All DB calls use `await` (`await session.exec(...)`, `await session.commit()`).
- Idempotent: check `SeedVersionRecord` first. Bump `SEED_VERSION` when adding new seed rows.

---

## Step 9: Add database tables (optional)

If your module needs its own tables:

1. Create `db_models/` in your module with SQLModel classes.
2. Prefix table names with your module ID: `my_module_records`, `my_module_findings`.
3. Add your models to `src/aila/alembic/env.py`:
   ```python
   from aila.modules.my_module import db_models as _my_module_models  # noqa: F401
   ```
4. Write an Alembic migration (see [DATABASE_MIGRATIONS.md](DATABASE_MIGRATIONS.md)).

Do not use `metadata.create_all()`. All schema changes go through Alembic.

---

## Step 10: Verify

```bash
# Compiles?
python -m compileall -q src/aila/modules/my_module

# Honesty audit?
python -m aila.tools.honesty_audit src/aila/modules/my_module --whitelist honesty_whitelist.py

# Platform discovers it?
uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload
# Check http://localhost:8000/docs -- your routes should appear
# Check http://localhost:8000/health -- your module should appear
```

---

## Step 11: Add a frontend page (optional)

Each module that contributes UI is its own pnpm workspace package living at
`src/aila/modules/<module_id>/frontend/`. The shell imports it by package
name, so it must declare a `package.json` and `tsconfig.json` before any
`.ts`/`.tsx` files compile.

Use `src/aila/modules/hello_world/frontend/` as the canonical reference.

**`frontend/package.json`** — workspace package metadata. Name follows the
`@aila/<module>-frontend` (kebab-case) convention:

```json
{
  "name": "@aila/my-module-frontend",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "main": "./spec.ts",
  "types": "./spec.ts",
  "exports": { ".": "./spec.ts" },
  "scripts": {
    "type-check": "tsc --noEmit",
    "clean": "rm -rf node_modules"
  },
  "peerDependencies": {
    "react": "catalog:react19",
    "@tanstack/react-query": "catalog:query"
  },
  "devDependencies": {
    "@aila/typescript-config": "workspace:*",
    "@types/react": "catalog:react19",
    "typescript": "catalog:"
  }
}
```

Add any module-specific deps under `dependencies` (with `catalog:<group>`
references where a catalog entry exists). Add shell-owned framework / data
/ design-system packages under `peerDependencies`. See
`docs/FRONTEND_MODULE_STANDARD.md` for the full dep-ownership matrix.

**`frontend/tsconfig.json`** — extends the shared module config and points
`@/`, `@app/`, `@platform/` aliases back at the shell:

```json
{
  "extends": "@aila/typescript-config/react-module",
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/*": ["../../../../../frontend/src/*"],
      "@app/*": ["../../../../../frontend/src/app/*"],
      "@platform/*": ["../../../../../frontend/src/platform/*"]
    }
  },
  "include": ["**/*.ts", "**/*.tsx"]
}
```

**`frontend/spec.ts`** — module UI contribution. The shell imports this
file via the package's `main` field:

```typescript
import { lazy } from "react";
import type { ModuleFrontendSpec } from "@platform/extension-registry/types";

const MyModulePage = lazy(() => import("./MyModulePage"));

export const frontendSpec = {
  moduleId: "my_module",
  nav: [{
    id: "my_module.home",
    slot: "sidebar.main" as const,
    label: "My Module",
    to: "/my_module",
    order: 100,
  }],
  routes: [{
    id: "my_module.home",
    path: "/my_module",
    title: "My Module",
    nav: true,
    slot: "page.full" as const,
    page: MyModulePage,
    breadcrumb: "My Module",
  }],
} satisfies ModuleFrontendSpec;
```

**`frontend/MyModulePage.tsx`** — page component using platform design
tokens:

```tsx
import { PageFrame } from "@app/layout/PageFrame";
import { AilaCard } from "@platform/ui/AilaCard";

export default function MyModulePage() {
  return (
    <PageFrame title="My Module">
      <AilaCard>
        <p className="text-text">My module is working.</p>
      </AilaCard>
    </PageFrame>
  );
}
```

Use platform tokens: `bg-base`, `bg-surface`, `text-text`, `text-text-muted`,
`border-border`. No custom CSS files. No hardcoded hex colors.

**Register the package with the shell** — add the new workspace dependency
to `frontend/package.json` so the shell can import it by name:

```json
{
  "dependencies": {
    "@aila/my-module-frontend": "workspace:*"
  }
}
```

…and add the corresponding entry to
`frontend/src/platform/extension-registry/loadModuleSpecs.ts`:

```ts
import { frontendSpec as myModuleSpec } from "@aila/my-module-frontend";
```

**Wire Tailwind v4 scanning** — Tailwind's content scan starts from the
directory containing `frontend/src/styles/globals.css` and ignores
`node_modules/`, so classes used only inside a module file get no CSS
generated unless you add an explicit `@source` directive. Add one line per
module right after the `@import "tailwindcss";` block:

```css
@source "../../../src/aila/modules/my_module/frontend/**/*.{ts,tsx}";
```

Already wired for `vr`, `vulnerability`, `forensics`, `sbd_nfr`, and
`hello_world`.

**Run `pnpm install`** — relinks the workspace so the shell can resolve the
new package and pnpm strict mode validates every bare import:

```bash
pnpm install
pnpm --filter @aila/my-module-frontend run type-check
```

---

## Common Mistakes

1. **Top-level `api_router` import in `module.py`** -- must be deferred inside `route_specs()`. The honesty audit catches this.

2. **`def register_tools` instead of `async def register_tools`** -- the protocol expects an awaitable. Sync `def` fails at startup.

3. **`def seed_data` instead of `async def seed_data`** -- same issue. The session is async; all DB calls must be awaited.

4. **Using `session.exec()` without `await`** -- returns a coroutine, not results. Every session call needs `await`.

5. **Missing `__all__`** -- every `__init__.py` and public module needs it. The honesty audit flags this.

6. **Importing from another module** -- `from aila.modules.vulnerability import ...` is forbidden. The honesty audit flags cross-module imports via the `import_boundary` rule.

7. **Calling `init_db()` in tool `__init__`** -- `init_db` is async and runs during platform startup. Tools must not call it.

8. **Using `os.getenv()` for module config** -- use `ConfigRegistry.get()` which resolves env var → DB → schema default.

9. **`metadata.create_all()` for new tables** -- write an Alembic migration instead. Latest revision lives in `src/aila/alembic/versions/`.

10. **Non-serializable task kwargs** -- every kwarg to a `@platform_task` function (or to `DurableStateMachine.execute()`) must be JSON-serializable. Pydantic models need `.model_dump(mode="json")` before crossing the boundary.

11. **`session.add()` on a row that may already exist** -- the second call raises an `IntegrityError`. Use `session.merge()` for INSERT-or-UPDATE on the primary key.

12. **Adding a bare import in a module frontend without declaring it in the module `package.json`** -- pnpm strict mode rejects the install. Add the import to `dependencies`, `peerDependencies`, or `devDependencies` as appropriate.

13. **Importing `react-router-dom`** -- React Router v7 collapsed both packages into `react-router`. Every import in this codebase uses `react-router`.

14. **Literal versions in a module `package.json`** -- shared deps must reference catalog entries (`"react": "catalog:react19"`); literals only for genuinely module-private deps.

15. **Forgetting the Tailwind `@source` directive for a new module** -- Tailwind v4 generates no CSS for classes it cannot see. Add the `@source` line to `frontend/src/styles/globals.css` when you ship the module.

16. **Editing `pnpm-lock.yaml` by hand** -- the file regenerates on every `pnpm install`. Edit `pnpm-workspace.yaml` or a `package.json` instead and re-run install.
---

## File Checklist

| File | Required | Purpose |
|---|---|---|
| `module.py` | Yes | ModuleProtocol + `create_module()` |
| `runtime.py` | Yes | `ModuleRuntime.handle()` |
| `capabilities.py` | Yes | `MODULE_DESCRIPTION`, `MODULE_TOOLS`, `MODULE_EXAMPLES` |
| `tool_keys.py` | Yes | Tool key constants (`my_module.tool_name`) |
| `workflow.py` | Yes | State machine (or `workflow/` package) |
| `contracts/` | Yes | Pydantic models (stub OK) |
| `tools/` | Yes | Tool implementations (stub OK) |
| `services/` | Yes | Domain services (stub OK) |
| `reporting/` | Yes | Report generation (stub OK) |
| `api_router.py` | Optional | FastAPI router factory |
| `db_models/` | Optional | SQLModel tables + Alembic migration |
| `frontend/` | Optional | React page + ModuleFrontendSpec |

---

*See also: [MODULE_STANDARD.md](MODULE_STANDARD.md) for the full contract, [WORKFLOW_GUIDE.md](WORKFLOW_GUIDE.md) for state machine patterns, [DATABASE_MIGRATIONS.md](DATABASE_MIGRATIONS.md) for Alembic guide.*
