# hello_world Module

Minimal reference implementation of the AILA module contract. Copy this module (or `_template/`) as a starting point for new modules.

## What This Module Does

- Registers one tool: `hello_world.greet`
- Exposes one API endpoint: `GET /hello_world/status`
- Implements a three-stage workflow: PREPARE -> EXECUTE -> RESPONSE_EMIT
- Seeds no data (stamps SeedVersionRecord only)

## Files

| File | Purpose |
|---|---|
| module.py | ModuleProtocol implementation and create_module() factory |
| runtime.py | Request handler delegating to workflow |
| capabilities.py | Module description, tool list, example prompts |
| tool_keys.py | Tool key constants |
| workflow.py | Three-stage state machine |
| contracts/ | HelloPayload and HelloOptions |
| tools/ | HelloGreetTool implementation |
| services/ | Service stub (empty) |
| reporting/ | Reporting stub (empty) |
| api_router.py | FastAPI router factory |
| frontend/ | React page stub |

## API

| Method | Path | Description |
|---|---|---|
| GET | /hello_world/status | Returns module status and greeting |

## Extending

To add a new tool:
1. Add a key constant to `tool_keys.py`
2. Create a Tool subclass in `tools/`
3. Register it in `module.py:register_tools()`
4. Add the key to `capabilities.py:MODULE_TOOLS`

To add database tables:
1. Create `db_models/` with SQLModel classes
2. Create an Alembic migration
3. Add seed data in `module.py:seed_data()`
