# API Error Catalog

The AILA REST API ships two coexisting non-2xx envelopes. Which one a
response uses depends on the exception class raised by the route, not the
status code. Both are documented here.

## Envelope shapes

### `ErrorResponse` -- raised by `HTTPException` and the catch-all

Returned by the Phase 80 handlers in `src/aila/api/app.py` and the
`_catch_unhandled_exceptions` middleware:

```json
{
  "detail": "Human-readable error message",
  "code": "MACHINE_READABLE_CODE_OR_NULL",
  "errors": null
}
```

`code` may be `null` for status codes where the API has no machine code
(401, 403, 404, 409 -- see the catalog below). `errors` is `null` except for
validation errors that flow through the Phase 80 handler.

### `ErrorEnvelope` -- raised by typed `AILAError` and validation errors

Returned by `register_error_handlers()`
(`src/aila/api/errors/handlers.py`) for every `AILAError` subclass, every
`fastapi.RequestValidationError`, and any otherwise-unhandled `Exception`:

```json
{
  "code": "MISSING_API_KEY",
  "message": "LLM API key is not configured.",
  "hint": "Go to Admin -> API Keys and add the provider key for this operation.",
  "trace_id": "5e7c1c4f3f8d4a4c8b9c0d1e2f3a4b5c"
}
```

- `code` comes from the exception's `ClassVar code` for typed subclasses,
  or a derived `_DERIVED_NAME_ERROR` token for pre-Phase-176a subclasses
  that fall back to HTTP 500.
- `message` is **always a safe static string** sourced from the exception's
  `ClassVar user_message` (typed taxonomy) or `"An internal error occurred."`
  for any 500-class path. `str(exc)` is **never** placed in `message` -- it
  could leak file paths, provider identifiers, or other caller-supplied
  context (Phase 178 S1).
- `hint` resolves through `ERROR_HINTS` in
  `src/aila/api/errors/hints.py`; falls back to the `DEFAULT` entry when no
  code-specific hint is registered.
- `trace_id` is the current `correlation_id` contextvar set by
  `CorrelationIdMiddleware`; `None` when the exception fires before that
  middleware binds the context.

The Phase 178 redactor `safe_exc_message()` in
`src/aila/platform/workflows/log.py` enforces the matching redaction for
the audit log: exception text persisted to `workflow_state_transitions` is
replaced with `type(exc).__name__` unless the exception inherits from
`WorkflowSafeMessage`. Full stack traces always land in structlog
server-side via `logger.exception(...)`.

### Typed codes and HTTP status mapping

| `code` | HTTP | Exception | When |
|--------|------|-----------|------|
| `MISSING_API_KEY` | 503 | `MissingApiKeyError` | LLM/provider API key is not configured. |
| `SSH_CONNECTION_FAILED` | 502 | `SSHConnectionFailedError` | SSH to a target system fails. |
| `ROUTER_ERROR` | 500 | `RouterError` | Internal LLM/OmniRoute routing failure. |
| `MODULE_PLATFORM_NOT_READY` | 503 | `ModulePlatformNotReadyError` | A module runtime is still initializing. |
| `CONFIG_VALUE_MISSING` | 500 | `ConfigValueMissingError` | A required `ConfigRegistry` entry is absent. |
| `WORKER_UNREACHABLE` | 503 | `WorkerUnreachableError` | The background task worker is unreachable. |
| `VALIDATION_ERROR` | 422 | `RequestValidationError` | Request body or query/path params fail Pydantic validation. |
| `INTERNAL_ERROR` | 500 | any otherwise-unhandled `Exception` | The generic last-resort handler. |
| *(derived)* | 500 | any legacy `AILAError` (`AuthenticationError`, `NotFoundError`, …) | Subclass lacks the `ClassVar code` / `http_status` pair; the handler derives a code from the class name and returns 500. |

The legacy catalog below documents the `ErrorResponse` shape used by every
route that raises `HTTPException` directly.


## Authentication Errors (401)

### Invalid or missing token

- **When:** No `Authorization: Bearer <token>` header, or the token is malformed.
- **Response:** `{"detail": "Not authenticated"}`
- **Fix:** Present a valid Bearer JWT from `POST /auth/login` (user) or `POST /auth/token` (API key).

### Invalid credentials (user login)

- **When:** `POST /auth/login` with an unknown username, an inactive account, an OIDC-only account, or a wrong password.
- **Response:** `{"detail": "Invalid credentials"}`
- **Fix:** Verify username + password. The same string is returned for every failure mode to avoid username enumeration; check the server audit log for `login_failed` with the specific reason.

### Invalid or expired refresh token

- **When:** `POST /auth/refresh/user` with a missing, expired, revoked, or wrong-type refresh token, or whose user account is no longer active.
- **Response:** `{"detail": "Invalid or expired refresh token"}`
- **Fix:** Re-authenticate via `POST /auth/login`.

### Expired token

- **When:** JWT `exp` claim has passed.
- **Response:** `{"detail": "JWT access token has expired -- obtain a new token via POST /auth/token or POST /auth/refresh"}`
- **Fix:** Refresh via `POST /auth/refresh` (API key) or `POST /auth/refresh/user` (user), or re-authenticate.

### Revoked API key

- **When:** The `ApiKeyRecord` matched by the JWT's `key_id` claim has `revoked_at` set (zero-cache-window blacklist).
- **Response:** `{"detail": "API key has been revoked"}`
- **Fix:** Create a new API key via `POST /auth/keys` (admin) or `aila create-api-key` (CLI).

### Invalid API key

- **When:** `POST /auth/token` with a raw key that does not match any active `ApiKeyRecord` hash.
- **Response:** `{"detail": "Invalid API key -- verify the key is correct and not revoked, then retry POST /auth/token"}`
- **Fix:** Verify the key value or create a new key.

### Rate limit exceeded (429)

- **When:** slowapi rate limit triggered for the bucket derived from the JWT `user_id`/`key_id` claim or remote IP (e.g. >10 logins/min, >5 token exchanges/min).
- **Response:** slowapi handler body (JSON with `error` + `Retry-After` header).
- **Fix:** Back off and retry after the duration in `Retry-After`. For per-user limits, the bucket is identity-based, so a noisy peer cannot starve other callers.


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
  "code": "VALIDATION_ERROR",
  "message": "Request validation failed",
  "hint": "Fix the highlighted input fields and retry.",
  "trace_id": "5e7c1c4f3f8d4a4c8b9c0d1e2f3a4b5c"
}
```

Phase 176a routes validation errors through `validation_error_handler`,
which emits the `ErrorEnvelope` shape above. Pre-Phase-176a code paths
that raise a custom 422 via `HTTPException` still return the older
`ErrorResponse` shape with `detail` + `errors` populated. Refer to the
route's OpenAPI documentation for the exact shape it returns.

- **Fix:** Match the request body against the schema published at `/docs`.


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

- **When:** Request body exceeds 10 MB (Content-Length header check in `_reject_oversized_requests`).
- **Response:** `{"detail": "Request body too large (max 10MB)", "code": "PAYLOAD_TOO_LARGE", "errors": null}`
- **Fix:** Reduce payload size; for bulk operations, use smaller batches.


---

## Service Unavailable (503)

### Platform not initialized

- **When:** `POST /analyze`, `POST /task`, or session message endpoints called before platform startup completes
- **Response:** `{"detail": "Platform not initialized -- check server logs for startup errors and restart the API server"}`
- **Fix:** Wait for startup to complete; check server logs for initialization errors

---

## Internal Server Errors (500)

### Unhandled exception

- **When:** The exception bubbles past every typed handler.
- **Response (`ErrorEnvelope` path):** `{"code": "INTERNAL_ERROR", "message": "An internal error occurred.", "hint": "...contact support with the trace ID shown below.", "trace_id": "..."}`
- **Response (legacy `_catch_unhandled_exceptions` path):** `{"detail": "Internal server error", "code": null, "errors": null}`
- **Fix:** Capture the `trace_id` and correlate against server-side structlog. `safe_exc_message()` redacts persisted audit text to the exception class name; full traceback only ever reaches structlog.

`register_error_handlers()` covers `AILAError`, `RequestValidationError`,
and bare `Exception`. The middleware-level `_catch_unhandled_exceptions`
exists as a belt-and-suspenders 500 wrapper for any path that escapes the
handler chain (e.g. errors raised in middleware itself).


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
| 413 | Payload Too Large | Request body > 10 MB |
| 422 | Validation Error | Schema validation failure (`ErrorEnvelope`, `code=VALIDATION_ERROR`) |
| 429 | Too Many Requests | slowapi rate limit triggered |
| 500 | Internal Error | Unhandled exception (`ErrorEnvelope`, `code=INTERNAL_ERROR`) |
| 503 | Service Unavailable | Platform not initialized |

---

*Source: `src/aila/api/errors/` (envelope handlers + hint registry),
`src/aila/platform/exceptions.py` (typed taxonomy),
`src/aila/api/app.py` (Phase 80 handlers + middleware),
`src/aila/platform/workflows/log.py` (`safe_exc_message`).*
