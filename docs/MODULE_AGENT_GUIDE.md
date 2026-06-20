# AILA Module Development — AI Context Document

**Purpose:** This document gives an AI agent everything it needs to build a complete, production-grade AILA module — backend and frontend — without exploring the codebase first. Read this once. Then build.

**Codebase root:** `src/aila/` (Python) and `frontend/src/` (TypeScript/React)

---

## 1. Mental Model

A module is a self-contained feature unit. The platform discovers it, validates it, and routes requests to it. The platform never imports from inside a module except through `create_module()`.

```
Platform
  └── discovers  modules/<id>/module.py
  └── calls      create_module()
  └── calls      module.register_tools(...)       # startup
  └── calls      module.build_runtime(context)    # per request
  └── calls      runtime.handle(request)          # execution
  └── mounts     module.route_specs()             # HTTP routes
  └── loads      frontend/spec.ts                 # UI registration
```

The module folder name **is** the module ID. It must match `^[a-z][a-z0-9_]*$`.

---

## 2. Required File Layout

```
src/aila/modules/<module_id>/
├── __init__.py                  # empty or __all__ = []
├── module.py                    # ONLY file the platform imports directly
├── runtime.py                   # ModuleRuntime subclass
├── workflow.py                  # State machine (or workflow/ package for complex modules)
├── capabilities.py              # Three constants: DESCRIPTION, TOOLS, EXAMPLES
├── tool_keys.py                 # String constants for tool identifiers
├── contracts/
│   └── __init__.py              # Pydantic request/response models
├── tools/
│   └── __init__.py              # Tool implementations
├── services/
│   └── __init__.py              # Module-specific service classes
├── reporting/
│   └── __init__.py              # Report filtering, row serialization
└── frontend/
    ├── spec.ts                  # Module registration contract
    ├── routes.tsx               # React route definitions
    ├── nav.ts                   # Sidebar nav entries
    ├── types.ts                 # TypeScript interfaces
    ├── queries.ts               # TanStack Query hooks
    ├── mutations.ts             # TanStack Query mutations
    └── screens/
        └── MainPage.tsx         # Screen components
```

DB models (if needed): `db_models.py` or `db_models/` package.
Alembic migration (if needed): `src/aila/alembic/versions/0NN_<module_id>_tables.py`.

---

## 3. Backend: ModuleProtocol

`module.py` must export `create_module()` — a zero-argument callable returning a `ModuleProtocol` instance.

```python
# src/aila/modules/mymod/module.py
from __future__ import annotations
from aila.platform.modules.protocol import (
    ModuleProtocol, ModuleCapabilityProfile, ModuleContext,
    ModuleRouteSpec, ModuleRuntime,
)
from aila.platform.tools.registry import ToolRegistry
from aila.platform.modules.schema_registry import SchemaRegistry
from aila.platform.modules.config_registry import ConfigRegistry
from sqlalchemy.ext.asyncio import AsyncSession

from .capabilities import CAPABILITY_DESCRIPTION, MODULE_TOOLS, CAPABILITY_EXAMPLES
from .tool_keys import TOOL_DO_THING
from .tools import DoThingTool
from .runtime import MyModRuntime

MODULE_ID = "mymod"


class MyModModule:
    module_id = MODULE_ID

    # ── Required ────────────────────────────────────────────────────────────

    def capability_profiles(self) -> list[ModuleCapabilityProfile]:
        # Write description FOR THE LLM ROUTER — it goes into routing prompts.
        return [ModuleCapabilityProfile(
            module_id=MODULE_ID,
            action_id=f"{MODULE_ID}.do_thing",
            description=CAPABILITY_DESCRIPTION,
            tools=list(MODULE_TOOLS),
            examples=list(CAPABILITY_EXAMPLES),
        )]

    def required_tools(self) -> list[str]:
        # Must not be empty. Registry rejects empty list.
        return [TOOL_DO_THING]

    async def register_tools(
        self,
        tool_registry: ToolRegistry,
        settings,
        registry,
        schema_registry: SchemaRegistry,
    ) -> None:
        # If you have DB models, push them into schema_registry here:
        # from .db_models import MyRecord
        # schema_registry.register(MyRecord)
        tool_registry.register(TOOL_DO_THING, DoThingTool(settings=settings))

    def build_runtime(self, context: ModuleContext) -> ModuleRuntime:
        # context.tool_registry is ALREADY SCOPED to required_tools() only.
        # context.settings, context.llm_model, context.resolved_config available.
        do_thing_tool = context.tool_registry[TOOL_DO_THING]
        return MyModRuntime(do_thing_tool=do_thing_tool)

    # ── Optional ────────────────────────────────────────────────────────────

    def route_specs(self) -> list[ModuleRouteSpec]:
        from .api_router import create_mymod_router
        return [ModuleRouteSpec(
            prefix="/mymod",
            router_factory=create_mymod_router,
            auth_required=True,
        )]

    async def seed_data(self, session: AsyncSession) -> None:
        # Idempotent. Check SeedVersionRecord before writing.
        from aila.storage.db_models import SeedVersionRecord
        from sqlmodel import select
        SEED_VERSION = 1
        existing = (await session.exec(
            select(SeedVersionRecord).where(
                SeedVersionRecord.module_id == MODULE_ID,
                SeedVersionRecord.version >= SEED_VERSION,
            )
        )).first()
        if existing:
            return
        # ... write seed data ...
        session.add(SeedVersionRecord(module_id=MODULE_ID, version=SEED_VERSION))
        await session.commit()

    def filter_report_rows(self, rows: list, filters: dict) -> list:
        # Module owns its own report filtering logic.
        return rows

    def health_checks(self) -> dict:
        return {}


def create_module() -> MyModModule:
    return MyModModule()
```

**Validation rules enforced at startup:**
- `module.module_id` must match folder name
- `required_tools()` must not be empty
- Every `action_id` must start with `f"{module_id}."`
- No duplicate action IDs
- Non-empty capability description
- Module fails registration → warning logged, module disabled, platform continues

---

## 4. Backend: Capabilities

```python
# src/aila/modules/mymod/capabilities.py
MODULE_ID = "mymod"

# Feeds directly into LLM routing prompt. Write for a language model, not a human.
CAPABILITY_DESCRIPTION = (
    "Does X when the user asks about Y. Operates on Z. "
    "Use when the user wants to ... or needs to ..."
)

MODULE_TOOLS: tuple[str, ...] = ("mymod.do_thing",)

CAPABILITY_EXAMPLES: tuple[str, ...] = (
    "do the thing on server-01",
    "check thing status for all systems",
    "what is the thing result for ubuntu-vm",
)
```

---

## 5. Backend: Tool Keys

```python
# src/aila/modules/mymod/tool_keys.py
TOOL_DO_THING = "mymod.do_thing"
# Add one constant per tool. These are stable API — never rename after release.
```

---

## 6. Backend: Tools

Every tool extends `aila.platform.tools._common.Tool`. Single-action pattern:

```python
# src/aila/modules/mymod/tools/__init__.py
from __future__ import annotations
from aila.platform.tools._common import Tool


class DoThingTool(Tool):
    name = "mymod.do_thing"
    description = "Does the thing. Input: target_name (str). Output: result dict."
    inputs = {
        "target_name": {"type": "string", "description": "System to act on"},
    }
    output_type = "object"
    skip_forward_signature_validation = False

    def __init__(self, settings=None) -> None:
        self._settings = settings

    def forward(self, action: str | None = None, **kwargs) -> dict:
        if action == "do_thing" or action is None:
            return self._do_thing(**kwargs)
        raise ValueError(f"Unknown action: {action!r}")

    def _do_thing(self, target_name: str) -> dict:
        # Call external system here. Return a dict.
        return {"target": target_name, "result": "done"}
```

**Multi-action pattern** (when one tool covers several related operations):

```python
def forward(self, action: str | None = None, **kwargs) -> dict:
    dispatch = {
        "query": self._query,
        "cache_get": self._cache_get,
        "cache_set": self._cache_set,
    }
    if action not in dispatch:
        raise ValueError(f"Unknown action {action!r}. Valid: {list(dispatch)}")
    return dispatch[action](**kwargs)
```

---

## 7. Backend: Workflow State Machine

```python
# src/aila/modules/mymod/workflow.py
from __future__ import annotations
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from aila.platform.contracts._common import JsonObject
from aila.platform.contracts.runtime import PlatformResponse


class MyModStage(str, Enum):
    PREPARE = "prepare"
    EXECUTE = "execute"
    RESPONSE_EMIT = "response_emit"


@dataclass(slots=True)
class MyModContext:
    run_id: str
    action_id: str
    module_id: str
    target_names: list[str]
    force_refresh: bool
    message: str = ""
    module_payload: JsonObject = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)
    # Add your own fields here


# ── Pure handlers ────────────────────────────────────────────────────────────
# Each handler: reads context, writes to context, returns None (advance) or
# a specific next stage. DO NOT call tools or DB inside handlers — do that in
# services that the handler calls.

def state_prepare(ctx: MyModContext) -> MyModStage | None:
    ctx.module_payload["request"] = {
        "module_id": ctx.module_id,
        "target_names": list(ctx.target_names),
    }
    return None  # advance to next stage in STAGE_ORDER


def state_execute(ctx: MyModContext) -> MyModStage | None:
    # Do domain work here (call services, tools, etc.)
    ctx.module_payload["result"] = {"status": "ok"}
    ctx.message = f"Processed {len(ctx.target_names)} target(s)."
    return None


def state_response_emit(ctx: MyModContext) -> MyModStage | None:
    return None  # final stage — orchestrator detects and builds PlatformResponse


# ── Concurrency annotations (required) ──────────────────────────────────────
state_prepare.parallel_safe = False
state_prepare.writes_fields = ["module_payload"]

state_execute.parallel_safe = False
state_execute.writes_fields = ["module_payload", "message"]

state_response_emit.parallel_safe = True
state_response_emit.writes_fields = []

# ── Registry ─────────────────────────────────────────────────────────────────
STAGE_ORDER: tuple[MyModStage, ...] = (
    MyModStage.PREPARE,
    MyModStage.EXECUTE,
    MyModStage.RESPONSE_EMIT,
)

HANDLER_REGISTRY: dict[MyModStage, Callable] = {
    MyModStage.PREPARE: state_prepare,
    MyModStage.EXECUTE: state_execute,
    MyModStage.RESPONSE_EMIT: state_response_emit,
}

# Import-time validation — NEVER remove this
_missing = set(MyModStage) - set(HANDLER_REGISTRY)
if _missing:
    raise RuntimeError(f"Workflow missing handlers: {_missing}")
```

**For complex modules with multiple routable workflows** (like vulnerability):
- Create a `workflow/` package
- Define a dispatcher stage that routes to sub-workflows
- Each sub-workflow is a separate `WorkflowDefinition` with its own `STAGE_ORDER`
- Each state declaration includes retry tuples: `retries=2, timeout=600, on=[TimeoutError, OSError]`

---

## 8. Backend: Runtime

```python
# src/aila/modules/mymod/runtime.py
from __future__ import annotations
from aila.platform.modules.protocol import ModuleRuntime, ModuleRequest
from aila.platform.contracts.runtime import PlatformResponse
from .workflow import MyModWorkflow, MyModContext, STAGE_ORDER
from .contracts import MyModPayload, MyModOptions
from .tools import DoThingTool


class MyModRuntime(ModuleRuntime):
    def __init__(self, do_thing_tool: DoThingTool) -> None:
        self._tool = do_thing_tool

    def handle(self, request: ModuleRequest) -> PlatformResponse:
        # 1. Validate payload and options against Pydantic models
        payload = MyModPayload.model_validate(request.payload)
        options = MyModOptions.model_validate(request.options)

        # 2. Build workflow context
        ctx = MyModContext(
            run_id=request.run_id,
            action_id=request.action_id,
            module_id="mymod",
            target_names=payload.target_names,
            force_refresh=options.force_refresh,
        )

        # 3. Run state machine
        return MyModWorkflow(tool=self._tool).run(ctx)
```

---

## 9. Backend: Contracts (Pydantic)

```python
# src/aila/modules/mymod/contracts/__init__.py
from __future__ import annotations
from pydantic import BaseModel


class MyModPayload(BaseModel):
    target_names: list[str] = []


class MyModOptions(BaseModel):
    force_refresh: bool = False


# API response models — defined here, used in api_router.py
class ThingResult(BaseModel):
    target: str
    result: str
    score: float | None = None


class ThingResponse(BaseModel):
    items: list[ThingResult]
    total: int
```

**Rule:** All Pydantic models live in `contracts/`. Never define them inline in router files.

---

## 10. Backend: API Router

```python
# src/aila/modules/mymod/api_router.py
from __future__ import annotations
from fastapi import APIRouter, Depends, Request
from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from .contracts import ThingResponse, ThingResult


def create_mymod_router() -> APIRouter:
    router = APIRouter(prefix="/mymod", tags=["mymod"])

    @router.get(
        "/things",
        response_model=DataEnvelope[ThingResponse],  # ALWAYS explicit response_model
        summary="List things",
    )
    @limiter.limit("60/minute")
    async def list_things(
        request: Request,
        auth: AuthContext = Depends(require_user_or_api_key),
    ) -> DataEnvelope[ThingResponse]:
        # request param is required by slowapi rate limiter — do not remove
        del request
        # Do real DB work here
        items = []  # replace with real query
        return DataEnvelope(data=ThingResponse(items=items, total=len(items)))

    return router
```

**Rules for every endpoint:**
- Always `response_model=DataEnvelope[YourModel]` — never `-> dict`
- `request: Request` first param (slowapi requires it by name)
- `auth: AuthContext = Depends(require_user_or_api_key)` for auth
- `del request` if not used (suppresses ARG001)
- `@limiter.limit("60/minute")` on every endpoint
- GET endpoints have zero side effects — no rescans, no mutations
- Server-side pagination: `limit: int = Query(default=25, le=250)`, `offset: int = Query(default=0, ge=0)`
- DB field names translate to API field names at this boundary (never leak raw column names)
- Paginated responses include `total`, `page`, `page_size`, `pages`, `items`

---

## 11. Backend: DB Models and Migration

```python
# src/aila/modules/mymod/db_models.py
from __future__ import annotations
from uuid import uuid4
from datetime import datetime
from sqlmodel import SQLModel, Field
from sqlalchemy import Column, Text, DateTime
from aila.platform.contracts._common import utc_now


class MyModRecord(SQLModel, table=True):
    """One-line description. Written by: X. Consumed by: Y."""

    __tablename__ = "mymod_records"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    # Add team_id for multi-tenant tables:
    team_id: str | None = Field(default=None, index=True)
    name: str = Field(index=True)
    data_json: str = Field(default="{}", sa_column=Column(Text, server_default="{}"))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
```

Push table into registry in `register_tools()`:
```python
schema_registry.register(MyModRecord)
```

**Migration file** (`src/aila/alembic/versions/027_mymod_tables.py`):

```python
"""027 — mymod tables.

Revision ID: 027_mymod_tables
Revises: 026_drop_legacy_task_columns
Create Date: YYYY-MM-DD
"""
from __future__ import annotations
import sqlalchemy as sa
from alembic import op

revision: str = "027_mymod_tables"
down_revision: str | None = "026_drop_legacy_task_columns"  # set to actual latest
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mymod_records",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("team_id", sa.Text(), nullable=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("data_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_mymod_records_team_id", "mymod_records", ["team_id"])
    op.create_index("ix_mymod_records_name", "mymod_records", ["name"])


def downgrade() -> None:
    op.drop_index("ix_mymod_records_name", "mymod_records")
    op.drop_index("ix_mymod_records_team_id", "mymod_records")
    op.drop_table("mymod_records")
```

After creating the migration file, run: `alembic upgrade head`

---

## 12. Backend: DB Operations (ServiceFactory)

Use `ServiceFactory` for all DB operations. Never create raw sessions in module code.

```python
from aila.platform.services.factory import ServiceFactory
from .db_models import MyModRecord

# In a service or tool:
async def get_records(team_id: str) -> list[MyModRecord]:
    svc = ServiceFactory()
    records = await svc.storage.fetch_all(
        MyModRecord,
        MyModRecord.team_id == team_id,
    )
    return list(records)

async def save_record(record: MyModRecord) -> None:
    svc = ServiceFactory()
    await svc.storage.save(record)
```

For complex queries requiring joins or aggregation, use `async_session_scope` directly:

```python
from aila.storage.database import async_session_scope
from sqlmodel import select

async with async_session_scope() as session:
    results = (await session.exec(
        select(MyModRecord).where(MyModRecord.team_id == team_id)
    )).all()
```

---

## 13. Frontend: Module Registration

```typescript
// src/aila/modules/mymod/frontend/spec.ts
import { nav } from "./nav";
import { routes } from "./routes";

export const frontendSpec = {
  moduleId: "mymod",
  nav,
  routes,
};
```

```typescript
// src/aila/modules/mymod/frontend/nav.ts
export const nav = [
  {
    id: "mymod.main",
    label: "My Module",
    to: "/mymod",
    order: 60,  // sidebar position
  },
];
```

```tsx
// src/aila/modules/mymod/frontend/routes.tsx
import { lazy } from "react";
const MainPage = lazy(() => import("./screens/MainPage"));

export const routes = [
  {
    path: "/mymod",
    element: <MainPage />,
  },
  {
    path: "/mymod/:itemId",
    element: <DetailPage />,
  },
];
```

---

## 14. Frontend: TypeScript Types

```typescript
// src/aila/modules/mymod/frontend/types.ts

// Mirror the backend Pydantic contract EXACTLY.
// Field names must match what the API returns after translation.
// Backend: db column "criticality" → API field "severity" → TS "severity"

export interface ThingResult {
  id: number | null;
  target: string;
  result: string;
  score: number | null;
  created_at: string | null;
}

export interface PaginatedThingsResponse {
  items: ThingResult[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface ThingsQueryParams {
  page: number;
  pageSize: number;
  target?: string;
  sortBy: "score" | "created_at" | "target";
  order: "asc" | "desc";
}
```

---

## 15. Frontend: TanStack Query Hooks

```typescript
// src/aila/modules/mymod/frontend/queries.ts
import { useQuery } from "@tanstack/react-query";
import { authorizedRequestJson } from "@/platform/api/client";
import type { PaginatedThingsResponse, ThingsQueryParams } from "./types";

// Envelope wrapper — all backend responses are DataEnvelope<T>
interface Envelope<T> { data: T; }

export function useThings(params: ThingsQueryParams) {
  return useQuery({
    queryKey: ["mymod", "things", params],
    queryFn: async () => {
      const search = new URLSearchParams({
        page: String(params.page),
        page_size: String(params.pageSize),
        sort_by: params.sortBy,
        order: params.order,
        ...(params.target ? { target: params.target } : {}),
      });
      const res = await authorizedRequestJson<Envelope<PaginatedThingsResponse>>(
        `/mymod/things?${search}`
      );
      return res.data;
    },
  });
}
```

**Mutation:**

```typescript
// src/aila/modules/mymod/frontend/mutations.ts
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { authorizedRequestJson } from "@/platform/api/client";

export function useUpdateThing() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, status }: { id: number; status: string }) => {
      const res = await authorizedRequestJson<Envelope<ThingResult>>(
        `/mymod/things/${id}`,
        { method: "PATCH", body: JSON.stringify({ status }) }
      );
      return res.data;
    },
    onSuccess: () => {
      // Invalidate so list refetches
      qc.invalidateQueries({ queryKey: ["mymod", "things"] });
    },
  });
}
```

**TanStack Query v5 rules:**
- `onError` DOES NOT work in `defaultOptions` in v5 — it silently does nothing. Error state comes from `isError` + `error` on each hook.
- `onSuccess` on `useQuery` is deprecated — use `select` or handle in component.
- For mutations: `onSuccess`, `onError` in `useMutation` options work fine.
- Query key is an array. `["mymod", "things", params]` → invalidating `["mymod", "things"]` clears all paginated variants.

---

## 16. Frontend: Screen Component Pattern

```tsx
// src/aila/modules/mymod/frontend/screens/MainPage.tsx
import { useState } from "react";
import { AilaCard } from "@/components/aila/AilaCard";
import { AilaBadge } from "@/components/aila/AilaBadge";
import { AilaTable } from "@/components/aila/AilaTable";
import { LoadingSkeleton } from "@/components/aila/LoadingSkeleton";
import { useThings } from "../queries";
import type { ThingsQueryParams } from "../types";

export default function MainPage() {
  // URL-driven filter state
  const [params, setParams] = useState<ThingsQueryParams>({
    page: 1,
    pageSize: 25,
    sortBy: "created_at",
    order: "desc",
  });

  const { data, isLoading, isError, error } = useThings(params);

  // ── Loading ──────────────────────────────────────────────────────────────
  if (isLoading) {
    return (
      <div className="flex flex-col gap-2 p-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <LoadingSkeleton key={i} />
        ))}
      </div>
    );
  }

  // ── Error ────────────────────────────────────────────────────────────────
  if (isError) {
    return (
      <AilaCard className="border-critical/40 bg-critical/5 m-4">
        <p className="text-sm text-critical">{error.message}</p>
      </AilaCard>
    );
  }

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  // ── Empty state ──────────────────────────────────────────────────────────
  // NEVER show mock data. NEVER hide the empty state.
  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-muted text-sm">
        No results yet.
      </div>
    );
  }

  // ── Content ──────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="flex items-center justify-between">
        <h1 className="text-display text-lg font-semibold">My Module</h1>
        <span className="text-muted text-sm">{total} total</span>
      </div>

      <AilaTable
        data={items}
        columns={[
          {
            accessorKey: "target",
            header: "Target",
            cell: ({ row }) => (
              <span className="font-mono text-sm">{row.original.target}</span>
            ),
          },
          {
            accessorKey: "score",
            header: "Score",
            cell: ({ row }) => (
              <span className="tabular-nums text-sm">
                {row.original.score?.toFixed(2) ?? "—"}
              </span>
            ),
          },
        ]}
      />

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm text-muted">
        <span>
          Page {params.page} of {data?.pages ?? 1}
        </span>
        <div className="flex gap-2">
          <button
            onClick={() => setParams(p => ({ ...p, page: p.page - 1 }))}
            disabled={params.page <= 1}
            className="px-3 py-1 border border-border rounded-sm disabled:opacity-40"
          >
            Prev
          </button>
          <button
            onClick={() => setParams(p => ({ ...p, page: p.page + 1 }))}
            disabled={params.page >= (data?.pages ?? 1)}
            className="px-3 py-1 border border-border rounded-sm disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
```

---

## 17. Frontend: Design System Rules

**Components to use (not raw HTML):**

| Need | Component |
|------|-----------|
| Card container | `AilaCard` |
| Severity badge | `AilaBadge severity="critical|high|medium|low"` |
| Data table | `AilaTable` (TanStack Table v8 wrapper) |
| Loading placeholder | `LoadingSkeleton` |
| Charts | `AilaChart` |

**CSS variables (always use these — never hardcode hex):**

| Variable | Use |
|----------|-----|
| `--color-accent` | Primary action color (neon magenta in synthwave) |
| `--color-critical` | Critical severity |
| `--color-high` | High severity |
| `--color-medium` | Medium severity |
| `--color-low` | Low severity |
| `--color-surface` | Card background |
| `--color-elevated` | Elevated surface (hover state backgrounds) |
| `--color-border` | Default border |
| `--color-muted` | De-emphasized text |

**Typography:**
- `font-display` → Syne — headlines only
- `font-sans` → Space Grotesk — body text (default)
- `font-mono` → Fira Code — CVE IDs, hostnames, package names, scores, code

**Spacing and radius:**
- Corners: `rounded-sm` (2px) for badges, `rounded` (4px) for cards — NEVER `rounded-lg` or `rounded-full`
- Elevation: border-based (`border border-border`, `border-elevated`) — NO `shadow-*` classes (D-06)
- Hover: `hover:bg-elevated/50` for row hover, `hover:border-border-hover` for card hover

**Severity sort order** (always apply when displaying severity):
```typescript
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
items.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
```

---

## 18. Absolute Rules (Never Violate)

### Backend

1. **No bare `except Exception:`** — name exact types. `except (ValueError, OSError):` not `except Exception:`. Broad catches that are genuinely necessary go in `honesty_whitelist.py` with written justification.

2. **No `# noqa` comments** — fix the violation or add to `honesty_whitelist.py`.

3. **No cross-module imports** — never `from aila.modules.vulnerability.x import ...` inside another module. This is a hard boundary.

4. **No bare dict returns from endpoints** — every endpoint returns `DataEnvelope[YourPydanticModel]`. Never `-> dict` or `return {"key": val}`.

5. **No inline Pydantic models in routers** — all models in `contracts/`.

6. **No SQLite** — PostgreSQL only, always. No fallbacks, no test shortcuts.

7. **No mock/placeholder data in seeds or tools** — if data isn't real, the honest response is an error or empty state.

8. **`request: Request` is mandatory first param on rate-limited endpoints** — slowapi requires it by name. Suppress with `del request` if unused.

9. **`alembic upgrade head` after every migration** — never commit broken migration state.

10. **Explicit state machines** — multi-step behavior is visible in `STAGE_ORDER` + `HANDLER_REGISTRY`, never hidden in nested conditions.

### Frontend

1. **No mock data** — ever. Empty state = honest empty state with real message, not a greyed-out fake table.

2. **URL is state for filters** — use search params, not component state or context, for anything that should survive navigation or sharing.

3. **TanStack Query v5 onError** — `defaultOptions.onError` is silently ignored. Error state comes from `isError` + `error` on each hook/mutation.

4. **All API calls through hooks** — no raw `fetch()` in screen components. All calls in `queries.ts` or `mutations.ts`.

5. **Invalidate by prefix after mutations** — `qc.invalidateQueries({ queryKey: ["mymod", "things"] })` clears all paginated variants.

6. **No `shadow-*` classes** — border-based elevation only (D-06).

7. **No `rounded-lg` or `rounded-full`** — 2px or 4px only (D-05 arcade aesthetic).

8. **`response_model=DataEnvelope[T]` must match `Envelope<T>` in TypeScript** — if you change one, change the other.

9. **Three required states on every data-fetching component** — loading (skeleton), error (message), empty (honest text). Never skip any of them.

10. **Monospace for technical identifiers** — hostnames, CVE IDs, package names, hashes → `font-mono`.

---

## 19. What Vulnerability Module Adds at Scale

Study `src/aila/modules/vulnerability/` to understand what production scale looks like:

| Pattern | Where | When to use |
|---------|-------|-------------|
| Multi-mode dispatcher | `workflow/definitions.py` | Module has 3+ distinct query patterns |
| Per-state retry tuples | `workflow/definitions.py` | States touch flaky external systems |
| Adapter registry | `adapters/` | Multiple backends with same interface |
| Materialized view table | `db_models/` (`LatestFindingRecord`) | Query surface separate from history |
| Tool auto-discovery | `tools/tool_catalog.py` | 10+ tools, avoid manual registration list |
| DECOUPLE-01 callback injection | `module.register_tools()` | Platform must not import module DB models |
| Knowledge stores per agent | `build_runtime()` | Multiple LLM agents with separate memory |
| Streaming export | `api_router.py` | Large data exports, bounded memory |
| Compliance tagging | `reporting/compliance.py` | Regulatory tags on findings |
| Faceted filter counts | API + frontend | Filter UI showing counts per option |

Do not add these patterns preemptively. Add them when the specific need arises.

---

## 20. Development Order

```
1. Define module_id and action_ids
2. Write contracts/ (Pydantic models for input + output)
3. Write tool_keys.py and capabilities.py
4. Write tools/ (one tool per external concern)
5. Write workflow.py (state machine)
6. Write runtime.py (validates request, builds context, runs workflow)
7. Write module.py (register_tools, build_runtime, route_specs, required_tools)
8. Write db_models.py + alembic migration (if needed) → alembic upgrade head
9. Write api_router.py (if HTTP routes needed)
10. Compile check: python -m compileall src/aila/modules/<module_id> -q
11. Write frontend/types.ts
12. Write frontend/queries.ts + mutations.ts
13. Write frontend/screens/*.tsx
14. Write frontend/spec.ts, routes.tsx, nav.ts
15. Start platform → watch startup log for registration errors
```

---

## 21. Verification Commands

```bash
# Syntax check the module
python -m compileall src/aila/modules/<module_id> -q

# Run honesty audit (must exit 0)
python src/aila/tools/honesty_audit.py src/aila/modules/<module_id>

# Run module tests
pytest tests/ -k "<module_id>" -x

# Apply migration
alembic upgrade head

# Type-check frontend
cd frontend && npx tsc --noEmit
```

---

*This document reflects AILA codebase state as of 2026-04-14 (v4.1 complete, Phase 184).*
*Reference modules: `src/aila/modules/hello_world/` (minimal), `src/aila/modules/vulnerability/` (production scale).*
