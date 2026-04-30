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

## Error Response Shape

All error responses (4xx, 5xx) return `ErrorResponse`:

```json
{
  "detail": "Human-readable message",
  "code": "MACHINE_READABLE_CODE",
  "errors": [{"loc": [...], "msg": "...", "type": "..."}]
}
```

The custom exception handlers in `app.py` ensure this envelope is used consistently:
- `RequestValidationError` handler maps FastAPI 422 to ErrorResponse with `code="VALIDATION_ERROR"`
- `HTTPException` handler wraps standard HTTP errors in ErrorResponse
- `Exception` catch-all middleware returns ErrorResponse for unhandled exceptions

---

## Naming Conventions

### Tags

Each router sets `tags=["<router_name>"]` for OpenAPI grouping:

| Tag | Router |
|-----|--------|
| auth | Authentication and API key management |
| audit | Audit event queries |
| config | ConfigRegistry read/write |
| health | Platform health checks |
| scans | Scan submission and progress |
| sessions | Conversation sessions |
| systems | System CRUD and module delegation |
| tasks | Task queue lifecycle |
| tools | Tool discovery and invocation |

### Summaries

Every endpoint has a `summary` parameter (short, < 60 chars):

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

*Last updated: 2026-04-05 (v1.7)*
