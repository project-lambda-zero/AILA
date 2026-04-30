# Module Template

Scaffold for new AILA modules. Copy this directory and follow the steps below.

## Quick Start

1. Copy this directory:
   ```bash
   cp -r src/aila/modules/_template src/aila/modules/my_module
   ```

2. Rename all `Template`/`TEMPLATE` references to your module name:
   - `TemplateModule` -> `MyModuleModule`
   - `TemplateRuntime` -> `MyModuleRuntime`
   - `TEMPLATE_SAMPLE_TOOL` -> `MY_MODULE_SAMPLE_TOOL`
   - `TemplateSampleTool` -> `MyModuleSampleTool`

3. Update `capabilities.py`:
   - Set `MODULE_DESCRIPTION` to a real description
   - Set `MODULE_TOOLS` to your tool keys
   - Set `MODULE_EXAMPLES` to example prompts

4. Update `tool_keys.py` with your tool key constants (prefix with module_id)

5. Implement your tools in `tools/`

6. Implement your workflow in `workflow.py` (or create a `workflow/` package for complex state machines)

7. If your module needs HTTP routes, create `api_router.py` and update `route_specs()` in `module.py` with a deferred import

8. If your module needs database tables, create `db_models/` and an Alembic migration

9. Register your module: add it to `src/aila/platform/modules/builtin.py`

## File Reference

| File | Purpose | Required |
|---|---|---|
| module.py | ModuleProtocol + create_module() | Yes |
| runtime.py | Request handler | Yes |
| capabilities.py | Description, tools, examples | Yes |
| tool_keys.py | Tool key constants | Yes |
| workflow.py | State machine | Yes |
| contracts/ | Pydantic models | Yes |
| tools/ | Tool implementations | Yes |
| services/ | Domain services | Yes (stub OK) |
| reporting/ | Report generation | Yes (stub OK) |
| api_router.py | HTTP routes | Optional |
| db_models/ | SQLModel tables | Optional |
| frontend/ | React components | Optional |

## Rules

- Module ID = directory name (lowercase, underscores only)
- Tool keys must be prefixed with module_id: `my_module.tool_name`
- Never import from another module
- Never import from platform at the top of api_router.py (use deferred imports in route_specs)
- Define `__all__` on every public module
- See `docs/MODULE_STANDARD.md` for the complete specification
