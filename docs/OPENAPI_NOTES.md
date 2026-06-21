# OpenAPI Enrichment Notes

Conventions and patterns used in the AILA OpenAPI schema (`/docs` or `/openapi.json`).

---

## Schema Conventions

### Response Models

Every endpoint declares an explicit `response_model` or uses `responses={}` for non-standard responses.

### SSE Endpoints

SSE endpoints use `response_class=StreamingResponse` with a `responses` dict that documents the event stream format:

```python
@router.get(
    "/{task_id}/events",
    response_class=StreamingResponse,
    responses={
        200: {
            "description": "SSE event stream with progress updates",
            "content": {
                "text/event-stream": {
                    "schema": {
                        "type": "string",
                        "description": "Each data: line is JSON with stage, message, percent, timestamp.",
                    },
                },
            },
        },
    },
)
```

This pattern eliminates bare `{}` in the OpenAPI schema (XCUT-12).

### Dual-Response Endpoints

Endpoints that return different content types based on `Accept` header use a `responses` dict with multiple content types:

```python
responses={
    200: {
        "content": {
            "application/json": {"schema": {"$ref": "#/components/schemas/Model"}},
            "text/event-stream": {"schema": {"type": "string", "description": "..."}},
        },
    },
}
```

Example: `POST /sessions/{id}/messages` returns JSON or SSE depending on `Accept: text/event-stream`.

### Report Explain Endpoint

`GET /reports/{run_id}/explain` uses dual status codes:

- 200: Cached explanation available (`ExplainCachedResponse`)
- 202: Explanation queued for generation (`ExplainQueuedResponse`)

Both response models are documented in the `responses` dict.

---

## Response Envelopes

### Success: `DataEnvelope[T]`

Most successful responses are wrapped in `DataEnvelope` (`src/aila/api/schemas/envelope.py`):

```json
{
  "data": <T>,
  "meta": { "total": 42, "offset": 0, "limit": 50 }
}
```

`meta` is optional and used for paginated lists. Endpoints that predate the
envelope (a small remainder under `/auth/token`, `/auth/refresh`, and the
scan/task submission surface) return their `response_model` directly.

### Errors: two coexisting shapes

Two error envelopes are wired into the app simultaneously. Which one a
response uses depends on the exception class:

| Shape | Where it comes from | When it fires |
|-------|--------------------|---------------|
| `ErrorResponse` — `{"detail": str, "code": str \| null, "errors": list \| null}` | The Phase 80 handlers in `create_app()` plus the `_catch_unhandled_exceptions` middleware | Any `fastapi.HTTPException` raised in a route, and the last-resort 500 fallback. |
| `ErrorEnvelope` — `{"code": str, "message": str, "hint": str \| null, "trace_id": str \| null}` | `register_error_handlers()` in `src/aila/api/errors/` | Every `AILAError` subclass (typed taxonomy), every `RequestValidationError` (422), and any otherwise-unhandled `Exception` (500). |

Both bodies are documented under `responses={}` keys on individual routes
when the route can return both, but most routes raise `HTTPException` and
therefore yield the `ErrorResponse` shape. See `docs/API_ERRORS.md` for the
full code list and the `safe_exc_message()` redaction policy on the
`ErrorEnvelope` `message` field.

The `_reject_oversized_requests` middleware short-circuits any request
exceeding 10 MB with the `ErrorResponse` shape and `code="PAYLOAD_TOO_LARGE"`.

---

## Naming Conventions

### Tags

Each router sets `tags=[<name>]` for OpenAPI grouping. The 29 platform-owned
routers mounted in `src/aila/api/app.py` (in `include_router` order) carry
these tags:

| Tag | Router file | One-liner |
|-----|-------------|-----------|
| `auth` | `auth.py` | `POST /auth/token`, `/auth/refresh`, `/auth/keys*` |
| `users` | `users.py` | `POST /auth/login`, `/auth/refresh/user`, `/auth/logout`, `/auth/sessions*`, `/users*` |
| `oidc` | `oidc.py` | `/auth/oidc/*` |
| `admin-teams`, `admin-dead-letter`, `admin-workflows` | `admin_teams.py`, `admin_dead_letter.py`, `admin_workflows.py` | Admin-only surfaces |
| `health` | `health.py` | `/health`, `/health/comprehensive`, `/status` |
| `audit` | `audit.py` | `/audit/events*`, `/audit/seals*` |
| `config` | `config.py` | ConfigRegistry read/write |
| `systems` | `systems.py` | System CRUD + module delegation |
| `tools` | `tools.py` | Tool discovery and invocation |
| `tasks` | `tasks.py` | Task queue lifecycle; also exports a separate `task_submit_router` for `POST /task` |
| `sessions` | `sessions.py` | Conversation session persistence |
| `scans` | `scans.py` | `POST /analyze`, `GET /scans/{run_id}` |
| `dashboard`, `search`, `tags`, `findings-workflow`, `saved-filters`, `widgets`, `scheduled-reports`, `notifications` | Plan 138-03 surfaces | UI-facing platform routers |
| `automation` | `automation.py` | Automation schedule CRUD + actions |
| `sse-events` | `sse_events.py` | Platform-wide SSE event stream |
| `topology` | `topology.py` | Network topology aggregation |
| `executive` | `executive.py` | Executive reporting |
| `cost` | `cost.py` | LLM cost intelligence |
| `llm-log` | `llm_log.py` | Admin LLM interaction log |

Feature modules contribute additional routers via `route_specs()`
(`_mount_module_routers()` in `app.py`). The current production set
(`forensics`, `sbd_nfr`, `vr`, `vulnerability`) each add at least one
routed prefix; `hello_world` adds the reference module surface.

### Summaries

Every endpoint sets a `summary` string (typically under 60 chars):

```python
@router.get("", summary="List tasks visible to the authenticated user")
```


### Descriptions

Complex endpoints add a `description` for the OpenAPI docs:

```python
@router.post(
    "/task",
    description="Submit a freeform query to AILAPlatform.handle() via task queue...",
)
```

---

## Accessing the Docs

- **Swagger UI:** `http://localhost:8000/docs`
- **ReDoc:** `http://localhost:8000/redoc`
- **Raw OpenAPI JSON:** `http://localhost:8000/openapi.json`

---

*Source: `src/aila/api/app.py` (router mounts + middleware chain),
`src/aila/api/errors/` (envelope handlers),
`src/aila/api/schemas/envelope.py` (success envelope).*
