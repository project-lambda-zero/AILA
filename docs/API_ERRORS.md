# API Error Catalog

Every error response from the AILA REST API. All errors follow the `ErrorResponse` envelope:

```json
{
  "detail": "Human-readable error message",
  "code": "MACHINE_READABLE_CODE",
  "errors": []
}
```

---

## Authentication Errors (401)

### Invalid or missing token

- **When:** No `Authorization: Bearer <token>` header, or token is malformed
- **Response:** `{"detail": "Not authenticated"}`
- **Fix:** Include a valid JWT token from `POST /auth/token`

### Expired token

- **When:** JWT `exp` claim has passed
- **Response:** `{"detail": "Token expired"}`
- **Fix:** Refresh via `POST /auth/refresh` or re-authenticate with `POST /auth/token`

### Revoked key

- **When:** The API key that issued the JWT has been revoked (`revoked_at` is set)
- **Response:** `{"detail": "API key has been revoked"}`
- **Fix:** Create a new API key via `POST /auth/keys` (admin) or `aila create-api-key` (CLI)

### Invalid API key

- **When:** `POST /auth/token` with an API key that does not match any stored hash
- **Response:** `{"detail": "Invalid API key"}`
- **Fix:** Verify the key value; create a new key if lost

### Blacklisted token

- **When:** JWT's `key_id` claim matches a revoked ApiKeyRecord
- **Response:** `{"detail": "API key has been revoked"}`
- **Fix:** Re-authenticate with a non-revoked key

---

## Authorization Errors (403)

### Insufficient role

- **When:** Endpoint requires a higher role than the caller has (e.g., reader calling admin-only endpoint)
- **Response:** `{"detail": "Insufficient permissions: requires <role> role"}`
- **Fix:** Use a token from a key with the required role

### Role hierarchy

| Endpoint Category | Required Role |
|-------------------|---------------|
| `POST /auth/keys`, `DELETE /auth/keys/{id}` | admin |
| `PUT /config/{ns}/{key}` | admin |
| `POST /analyze`, `POST /task` | operator |
| All GET endpoints, `POST /sessions` | reader |

---

## Validation Errors (422)

### Request body validation

- **When:** Request body fails Pydantic schema validation (missing fields, wrong types, constraint violations)
- **Code:** `VALIDATION_ERROR`
- **Response:**

```json
{
  "detail": "1 validation error: field 'query_text' is required",
  "code": "VALIDATION_ERROR",
  "errors": [
    {
      "loc": ["body", "query_text"],
      "msg": "Field required",
      "type": "missing"
    }
  ]
}
```

- **Fix:** Check the request body against the schema (see OpenAPI docs at `/docs`)

### Config value validation

- **When:** `PUT /config/{namespace}/{key}` with a value that fails ConfigRegistry validation
- **Response:** `{"detail": "Invalid value for {namespace}.{key}: {reason}"}`
- **Fix:** Check the expected type and constraints for the config field

---

## Not Found Errors (404)

### Resource not found

- **When:** Requested resource does not exist or is not accessible to the caller
- **Affected endpoints:** `GET /scans/{run_id}`, `GET /tasks/{task_id}`, `GET /sessions/{id}/messages`, `GET /systems/{id}`
- **Response:** `{"detail": "Resource '{id}' not found or not accessible"}`
- **Fix:** Verify the resource ID; check that the caller has access (same group_id, or admin role)

### Session not found

- **When:** Session ID does not exist or belongs to another user (D-25: user isolation)
- **Response:** `{"detail": "Session '{id}' not found or belongs to another user"}`
- **Fix:** Verify the session_id via `POST /sessions`

---

## Conflict Errors (409)

### Task already terminal

- **When:** `POST /tasks/{id}/cancel` on a task in done/failed/cancelled state
- **Response:** `{"detail": "Task '{id}' is already in a terminal state"}`
- **Fix:** Only cancel non-terminal tasks (queued, waiting, running, paused)

### Task not paused

- **When:** `POST /tasks/{id}/resume` on a task not in paused state
- **Response:** `{"detail": "Task '{id}' is not in PAUSED state"}`
- **Fix:** Only resume paused tasks

### Duplicate key revocation

- **When:** `DELETE /auth/keys/{id}` on an already-revoked key
- **Response:** `{"detail": "Key already revoked"}`

### DAG cycle detected

- **When:** Task submission creates a dependency cycle
- **Response:** `{"detail": "Dependency cycle detected"}`
- **Fix:** Remove the circular dependency from `depends_on`

---

## Payload Too Large (413)

### Oversized request

- **When:** Request body exceeds 10MB (Content-Length header check in middleware)
- **Response:** `{"detail": "Request body too large"}`
- **Fix:** Reduce payload size; for bulk operations, use smaller batches

---

## Service Unavailable (503)

### Platform not initialized

- **When:** `POST /analyze`, `POST /task`, or session message endpoints called before platform startup completes
- **Response:** `{"detail": "Platform not initialized -- check server logs for startup errors and restart the API server"}`
- **Fix:** Wait for startup to complete; check server logs for initialization errors

---

## Internal Server Errors (500)

### Unhandled exception

- **When:** An unexpected error occurs in request processing
- **Response:** `{"detail": "Internal server error", "code": null}`
- **Fix:** Check server logs for the full stack trace; report as a bug if reproducible

The `@app.middleware('http')` catch-all ensures that non-HTTPException errors always return an `ErrorResponse` envelope, never a bare HTML error page.

---

## SSE-Specific Responses

### Redis not configured

- **When:** SSE endpoint called but `AILA_PLATFORM_REDIS_URL` is not set
- **Response:** Single SSE event then close:

```
data: {"message": "Redis not configured \u2014 no progress stream available"}
```

- **Fix:** Configure Redis URL via `AILA_PLATFORM_REDIS_URL` env var or `PUT /config/platform/redis_url`

---

## HTTP Status Code Summary

| Status | Meaning | Common Causes |
|--------|---------|---------------|
| 200 | Success | GET, PUT, POST (sync responses) |
| 201 | Created | POST /sessions, POST /auth/keys |
| 202 | Accepted | POST /analyze, POST /task (async) |
| 401 | Unauthorized | Missing/invalid/expired/revoked token |
| 403 | Forbidden | Insufficient role for endpoint |
| 404 | Not Found | Resource missing or not accessible |
| 409 | Conflict | Terminal state, already revoked, cycle |
| 413 | Payload Too Large | Request body > 10MB |
| 422 | Validation Error | Schema validation failure |
| 500 | Internal Error | Unhandled exception |
| 503 | Service Unavailable | Platform not initialized |

---

*Last updated: 2026-04-05 (v1.7)*
