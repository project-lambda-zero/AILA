# hello_world Module

Minimal reference implementation of the AILA module contract. Copy this module (or `_template/`) as a starting point for new modules.

## What This Module Does

- Registers one tool: `hello_world.greet`
- Exposes one authenticated API endpoint: `GET /hello_world/status` (returns `{module: "hello_world", status: "ok"}`)
- Implements a three-stage workflow: `PREPARE -> EXECUTE -> RESPONSE_EMIT`
- Seeds no data (stamps `SeedVersionRecord` only)
- Contributes a sidebar entry + `/hello_world` route from `frontend/spec.ts`

## Files

| File | Purpose |
|---|---|
| `module.py` | `ModuleProtocol` implementation and `create_module()` factory |
| `runtime.py` | Request handler delegating to the workflow |
| `capabilities.py` | `MODULE_DESCRIPTION`, `MODULE_TOOLS`, `MODULE_EXAMPLES` |
| `tool_keys.py` | Tool key constants (`HELLO_WORLD_GREET_TOOL = "hello_world.greet"`) |
| `workflow.py` | Three-stage state machine driven by `HelloWorldWorkflow` |
| `contracts/` | `HelloPayload` / `HelloOptions` Pydantic models |
| `tools/` | `HelloGreetTool` implementation |
| `services/` | Service stub (empty `__init__.py`) |
| `reporting/` | Reporting stub (empty `__init__.py`) |
| `api_router.py` | FastAPI router factory (`create_hello_world_router`) |
| `frontend/` | `@aila/hello-world-frontend` workspace package -- sidebar nav + `HelloWorldPage` |

## API

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/hello_world/status` | Bearer JWT | Returns module id + health status |

## Frontend

The frontend is a pnpm workspace package (`@aila/hello-world-frontend`). The shell pulls in `frontendSpec` from `frontend/spec.ts` via `frontend/src/platform/extension-registry/loadModuleSpecs.ts`. Module-local React/Tailwind dependencies live in `frontend/package.json` (declared as `peerDependencies`; the shell resolves them).

## Extending

To add a new tool:
1. Add a key constant to `tool_keys.py` (prefix: `hello_world.<tool_name>`)
2. Create a `Tool` subclass under `tools/`
3. Register it inside `HelloWorldModule.register_tools()` in `module.py`
4. Append the key to `MODULE_TOOLS` in `capabilities.py`

To add database tables:
1. Create `db_models/` with `SQLModel` classes
2. Add an Alembic migration under `src/aila/alembic/versions/`
3. Seed initial rows (if any) in `HelloWorldModule.seed_data()`