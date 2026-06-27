# Module Template

Scaffold for new AILA modules. The `_template/` directory is skipped at boot (leading underscore) -- copy it, rename placeholders, then register the new module in `src/aila/platform/modules/builtin.py`.

## Quick Start

1. Copy this directory:
   ```bash
   cp -r src/aila/modules/_template src/aila/modules/my_module
   ```

2. Rename all `Template` / `TEMPLATE` references to your module name:
   - `TemplateModule` -> `MyModuleModule`
   - `TemplateRuntime` -> `MyModuleRuntime`
   - `TEMPLATE_SAMPLE_TOOL` -> `MY_MODULE_SAMPLE_TOOL`
   - `TemplateSampleTool` -> `MyModuleSampleTool`

3. Update `capabilities.py`:
   - Set `MODULE_DESCRIPTION` to a real description
   - Set `MODULE_TOOLS` to your tool keys
   - Set `MODULE_EXAMPLES` to example prompts

4. Update `tool_keys.py` -- tool key constants MUST be prefixed with the module id (`my_module.<tool_name>`).

5. Implement your tools in `tools/` (subclass `aila.platform.tools._common.Tool`).

6. Implement your workflow in `workflow.py`, or expand it into a `workflow/` package when the state machine grows beyond one file.

7. Optional surfaces:
   - HTTP routes -- create `api_router.py` and return a `ModuleRouteSpec` from `route_specs()`. Use a **deferred import** inside `route_specs()` so the module file itself does not import `api_router.py` at module top level (the honesty audit flags top-level FastAPI imports).
   - Database tables -- create `db_models/` and an Alembic migration under `src/aila/alembic/versions/`.
   - Frontend -- create `frontend/` as its own pnpm workspace package (`@aila/<module-id>-frontend`). Look at `hello_world/frontend/` for the smallest working example. Then add `"@aila/<module-id>-frontend": "workspace:*"` to the shell's `frontend/package.json` and import its `frontendSpec` from `frontend/src/platform/extension-registry/loadModuleSpecs.ts`.
   - Per-queue worker -- declare an ARQ queue track in `_task_queue.py` if the module submits long-running background work.

8. Register the module: append an import + `create_module()` entry to `src/aila/platform/modules/builtin.py`.

9. Run `make check` (lint + honesty audit + compile + typecheck). The honesty audit catches the common mistakes listed in `CLAUDE.md` (missing `__all__`, top-level `api_router` import, bare `except Exception`).

## File Reference

The files shipped in this scaffold:

| File | Purpose | Present in `_template/` |
|---|---|---|
| `module.py` | `ModuleProtocol` + `create_module()` | Yes |
| `runtime.py` | Request handler | Yes |
| `capabilities.py` | Description, tools, examples | Yes |
| `tool_keys.py` | Tool key constants | Yes |
| `workflow.py` | State machine | Yes |
| `contracts/` | Pydantic models | Yes |
| `tools/` | Tool implementations | Yes (sample tool only) |
| `services/` | Domain services | Yes (empty stub) |
| `reporting/` | Report generation | Yes (empty stub) |
| `api_router.py` | HTTP routes | Add when needed |
| `db_models/` | SQLModel tables | Add when needed |
| `frontend/` | React workspace package | Add when needed |

## Rules

- Module id = directory name (lowercase + underscores only).
- Tool keys MUST be prefixed with the module id: `my_module.<tool_name>`.
- Modules NEVER import from another module -- cross-module communication goes through platform contracts, the extension registry, or the LLM router.
- `api_router.py` MUST NOT be imported at module top level. Use a deferred import inside `route_specs()`.
- Every public Python module declares `__all__`.
- For frontends, every bare import MUST be declared in the module's own `package.json` (deps, peerDeps, or devDeps). Shared versions go through pnpm catalogs in `pnpm-workspace.yaml`.
- See `docs/MODULE_STANDARD.md` and `docs/FRONTEND_MODULE_STANDARD.md` for the full contract. `src/aila/modules/hello_world/` is the smallest working example.